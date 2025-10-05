'use strict';
const path = require('path');
const { AuthService } = require('./src/services/AuthService');
const { SMTPService } = require('./src/services/SMTPService');
const { NoSQL } = require('./src/db/NoSQL');
const { parse, execute } = require('./src/graphql');
const { PKISystem } = require('./src/pki');
const HttpService = require('./src/services/HttpService');

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
          const userId = req.user?.id;
          if (!userId) throw new Error('Authentication required');
          const user = await db.findOne('users', { id: userId });
          if (!user) return { success: false, message: 'User not found' };
          const { name, surname, schoolNumber, role, email, microsoftUniqueName, lastMicrosoftLogin, pkiIssuedAt } = user;
          return {
            success: true,
            data: {
              id: userId,
              name,
              surname,
              schoolNumber,
              role,
              email,
              microsoftUniqueName: microsoftUniqueName || null,
              lastMicrosoftLogin: lastMicrosoftLogin || null,
              pkiIssuedAt: pkiIssuedAt || null
            }
          };
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
      completeMicrosoftLogin: {
        auth: false,
        resolve: async (_p, { code, state, codeVerifier }, { authService, res }) => {
          try {
            const result = await authService.handleMicrosoftCallback({ code, state, codeVerifier });
            if (result.success && result.data?.cookie?.token) {
              const cfg = Object.assign({}, cookieDefaults);
              if (result.data.cookie.ttlMs != null) cfg.ttlMs = result.data.cookie.ttlMs;
              authService.setAuthCookieOnResponse(res, result.data.cookie.token, cfg);
            }
            return result;
          } catch (e) {
            return { success: false, message: e.message };
          }
        }
      },
      logout: {
        auth: true,
        resolve: async (_p, _args, { authService, res }) => {
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
      contextFactory: ({ req }) => ({ db, authService, pki, user: req?.user || null })
    });
  };

  registerGraphEndpoint('/graphql');
  registerGraphEndpoint('/graph');

  http.registerMicrosoftAuthRoutes({
    loginPath: '/auth/microsoft',
    callbackPath: '/auth/microsoft/callback',
    logoutPath: '/auth/logout',
    successRedirect: '/pages/dashboard.html',
    failureRedirect: '/pages/login.html',
    logoutRedirect: '/pages/login.html',
    cookie: cookieDefaults,
    allowedRedirectOrigins: ['https://fitfak.net', 'http://localhost:3000', 'https://localhost:3000']
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
