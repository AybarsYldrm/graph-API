'use strict';
const path = require('path');
const { AuthService } = require('./src/services/AuthService');
const { SMTPService } = require('./src/services/SMTPService');
const { NoSQL } = require('./src/db/NoSQL');
const { parse, execute } = require('./src/graphql');
const { PKISystem } = require('./src/pki');
const HttpService = require('./src/services/HttpService');
const { URL } = require('url');

const isProduction = process.env.NODE_ENV === 'production';

(async () => {
  const db = new NoSQL();
  await db.init();

  const smtp = new SMTPService({
    username: 'aybarsyildirim.network@gmail.com',
    password: 'lvft tmdk zmye njwt'
  });

  const pki = new PKISystem();

  const authService = new AuthService({ db, pki, smtp, persistTokens: false });

  const http = new HttpService(authService, {
    publicPath: path.join(__dirname, 'public'),
    pagesPath: path.join(__dirname, 'public', 'pages'),
    maxRequestsPerMinute: 200,
    uploadDefaultLimit: 8 * 1024 * 1024,
    uploadDefaultMaxKBps: 1024,
    allowedOrigins: ['https://fitfak.net']
  });

  const cookieDefaults = {
    name: 'auth_token',
    ttlMs: authService.tokenTTL,
    sameSite: isProduction ? 'None' : 'Lax',
    secure: isProduction,
    httpOnly: true,
    path: '/'
  };

  const graphSchema = {
    Query: {
      me: {
        auth: true,
        resolve: async (_p, _args, { req, db }) => {
          const user = await db.findOne('users', { id: req.user.id });
          if (!user) return { success: false, message: 'User not found' };
          const { name, surname, schoolNumber, role, email } = user;
          return { success: true, data: { id: req.user.id, name, surname, schoolNumber, role, email } };
        }
      },
      event: {
        auth: true,
        resolve: async (_p, { id }, { db }) => {
          const doc = await db.findOne('events', { id });
          return doc ? { __type: 'Event', ...doc } : null;
        }
      },
      events: {
        auth: true,
        resolve: async (_p, { ownerId, tag }, { db }) => {
          const filter = {};
          if (ownerId) filter.ownerId = ownerId;
          if (tag) filter.tags = { $in: [tag] };
          const list = await db.find('events', filter, { limit: 200, sort: (a, b) => a.startsAt.localeCompare(b.startsAt) });
          return list.map(e => ({ __type: 'Event', ...e }));
        }
      },
      microsoftAuthorizationUrl: {
        auth: false,
        resolve: (_p, args = {}, { authService }) => {
          if (!authService.microsoftConfigValid()) {
            return { success: false, message: 'Microsoft OAuth yapılandırması eksik.' };
          }

          const payload = (args.statePayload && typeof args.statePayload === 'object') ? args.statePayload : {};
          if (args.origin) payload.origin = args.origin;

          const { url, state } = authService.buildMicrosoftAuthorizationUrl({
            state: args.state,
            statePayload: Object.keys(payload).length ? payload : undefined,
            prompt: args.prompt,
            loginHint: args.loginHint,
            domainHint: args.domainHint,
            codeChallenge: args.codeChallenge,
            codeChallengeMethod: args.codeChallengeMethod
          });

          return { success: true, data: { url, state } };
        }
      }
    },
    Mutation: {
      register: {
        auth: false,
        resolve: async (_p, args, { authService }) => {
          try {
            const { success, userId, tokenSent } = await authService.register(args);
            return {
              success,
              data: tokenSent ? 'Doğrulama bağlantısı e-posta ile gönderildi.' : 'Kayıt oluşturuldu (test token üretildi).',
              userId
            };
          } catch (e) {
            return { success: false, message: e.message };
          }
        }
      },
      login: {
        auth: false,
        resolve: async (_p, { email, password }, { authService, res }) => {
          try {
            const result = await authService.login(email, password);
            if (!result.success) return result;
            const token = result.data?.token;
            if (token) authService.setAuthCookieOnResponse(res, token, cookieDefaults);
            return result;
          } catch (e) {
            return { success: false, message: e.message };
          }
        }
      },
      session: {
        auth: false,
        resolve: async (_p, { token }, { authService, res }) => {
          try {
            const payload = await authService.verifyJWT(token);
            if (!payload) return { success: false, message: 'Invalid or expired token' };
            authService.setAuthCookieOnResponse(res, token, cookieDefaults);
            return { success: true, message: 'Cookie set' };
          } catch (e) {
            return { success: false, message: e.message };
          }
        }
      },
      requestPasswordReset: {
        auth: false,
        resolve: async (_p, { email, originUrl }, { req, authService }) => {
          try {
            const ip = req.ip || req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
            const result = await authService.requestPasswordReset(email, ip, originUrl);
            if (!result.success) return { success: false, message: result.message };
            return { success: true, message: result.tokenSent ? 'Şifre sıfırlama bağlantısı e-posta ile gönderildi.' : 'Şifre sıfırlama tokenı oluşturuldu.' };
          } catch (e) {
            return { success: false, message: e.message };
          }
        }
      },
      resetPassword: {
        auth: false,
        resolve: async (_p, { token, newPassword }, { authService }) => {
          try {
            const result = await authService.resetPassword(token, newPassword);
            if (!result.success) return { success: false, message: result.message };
            return { success: true, message: 'Şifre başarıyla değiştirildi ✅' };
          } catch (e) {
            return { success: false, message: e.message };
          }
        }
      },
      verifyEmail: {
        auth: false,
        resolve: async (_p, { token }, { authService }) => {
          try {
            const result = await authService.verifyEmailToken(token);
            if (!result.success) return { success: false, message: result.message };
            return { success: true, message: 'Email başarıyla doğrulandı ✅' };
          } catch (e) {
            return { success: false, message: e.message };
          }
        }
      },
      completeMicrosoftLogin: {
        auth: false,
        resolve: async (_p, { code, state, codeVerifier }, { authService, res }) => {
          try {
            const result = await authService.handleMicrosoftCallback({ code, state, codeVerifier });
            if (result.success && result.data?.token) {
              authService.setAuthCookieOnResponse(res, result.data.token, cookieDefaults);
            }
            return result;
          } catch (e) {
            return { success: false, message: e.message };
          }
        }
      },
      logout: {
        auth: true,
        resolve: async (_p, _args, { authService, req, res }) => {
          if (typeof authService.revokeToken === 'function') {
            try { await authService.revokeToken(req.user?.id); } catch (e) { /* ignore */ }
          }
          authService.clearAuthCookieOnResponse(res, cookieDefaults.name, cookieDefaults);
          return { success: true, message: 'Logged out' };
        }
      },
      createEvent: {
        type: 'Event',
        auth: true,
        roles: ['admin'],
        resolve: async (_p, { title, startsAt, endsAt, location, tags }, { db, req }) => {
          const ownerId = req.user.id;
          const created = await db.insert('events', { title, startsAt, endsAt, ownerId, location, tags: tags || [] });
          return { __type: 'Event', ...created };
        }
      },
      updateEvent: {
        type: 'Event',
        auth: true,
        roles: ['admin'],
        resolve: async (_p, { id, ...patch }, { db }) => {
          const existing = await db.findOne('events', { id });
          if (!existing) throw new Error('Event bulunamadı.');
          const updated = await db.update('events', id, patch);
          return updated ? { __type: 'Event', ...updated } : null;
        }
      },
      deleteEvent: {
        type: 'Boolean',
        auth: true,
        roles: ['admin'],
        resolve: async (_p, { id }, { db }) => db.remove('events', id)
      }
    },
    types: { Event: {} }
  };

  const registerGraphEndpoint = (pathPattern) => {
    http.registerGraphQL(pathPattern, {
      schema: graphSchema,
      parse,
      execute,
      contextFactory: () => ({ db, authService })
    });
  };

  registerGraphEndpoint('/graphql');
  registerGraphEndpoint('/graph');

  http.addRoute('GET', '/auth/microsoft', (req, res) => {
    if (!authService.microsoftConfigValid()) {
      return http.sendJson(res, 503, { success: false, message: 'Microsoft OAuth yapılandırması yapılmadı.' });
    }

    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const origin = parsedUrl.searchParams.get('origin');
    const prompt = parsedUrl.searchParams.get('prompt');
    const loginHint = parsedUrl.searchParams.get('login_hint');
    const domainHint = parsedUrl.searchParams.get('domain_hint');

    const statePayload = {};
    if (origin) statePayload.origin = origin;

    const { url: redirectUrl } = authService.buildMicrosoftAuthorizationUrl({
      statePayload: Object.keys(statePayload).length ? statePayload : undefined,
      prompt,
      loginHint,
      domainHint
    });

    return http.redirectHtml(res, redirectUrl, 302);
  });

  http.addRoute('GET', '/auth/microsoft/callback', async (req, res) => {
    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const error = parsedUrl.searchParams.get('error');
    const errorDescription = parsedUrl.searchParams.get('error_description');
    if (error) {
      return http.sendHtml(res, 400, `<h1>Microsoft OAuth hatası</h1><p>${error}: ${errorDescription || ''}</p>`);
    }

    const code = parsedUrl.searchParams.get('code');
    const state = parsedUrl.searchParams.get('state');
    if (!code) {
      return http.sendHtml(res, 400, '<h1>Eksik Microsoft kodu</h1>');
    }

    try {
      const result = await authService.handleMicrosoftCallback({ code, state });
      if (result.success && result.data?.token) {
        authService.setAuthCookieOnResponse(res, result.data.token, cookieDefaults);
      }

      const stateInfo = result.data?.state;
      const redirectTarget = (stateInfo && stateInfo.origin) ? stateInfo.origin : '/';
      return http.redirectHtml(res, redirectTarget, 302);
    } catch (e) {
      return http.sendHtml(res, 500, `<h1>Microsoft OAuth işlemi başarısız</h1><p>${e.message}</p>`);
    }
  });

  http.addRoute('POST', '/sign', async (req, res) => {
    const { payload } = req.body || {};
    if (!payload) return http.sendJson(res, 400, { success: false, message: 'Missing payload' });
    try {
      const envelope = await pki.sign(req.user.id, payload);
      return http.sendJson(res, 200, { success: true, envelope });
    } catch (e) {
      return http.sendJson(res, 500, { success: false, message: e.message });
    }
  }, { auth: true, roles: ['admin'] });

  http.addRoute('POST', '/verify', async (req, res) => {
    const { envelope } = req.body || {};
    if (!envelope) return http.sendJson(res, 400, { success: false, message: 'Missing envelope' });
    try {
      const result = pki.verify(envelope);
      return http.sendJson(res, 200, { success: true, result });
    } catch (e) {
      return http.sendJson(res, 400, { success: false, message: e.message });
    }
  }, { auth: true, roles: ['admin', 'user'] });

  http.addRoute('POST', '/html', async (req, res) => {
    if (!req.body || !req.body.files) return http.sendJson(res, 400, { success: false, files: [] });
    const files = req.body.files.map(f => ({ field: f.fieldname, filename: f.filename }));
    return http.sendJson(res, 200, { success: true, files });
  }, {
    multipart: true,
    auth: true,
    roles: ['admin'],
    rateLimit: { windowMs: 10 * 1000, max: 1 },
    upload: {
      folder: 'html',
      maxBytes: 1 * 1024 * 1024,
      accept: ['text/html'],
      naming: (orig) => `html_${Date.now()}${path.extname(orig)}`
    }
  });

  const port = process.env.PORT || 80;
  http.listen(port, () => console.log(`Server listening on ${port}`));
})();
