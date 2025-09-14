'use strict';
const path = require('path');
const { AuthService } = require('./src/services/AuthService');
const { SMTPService } = require('./src/services/SMTPService');
const { NoSQL } = require('./src/db/NoSQL');
const { parse, execute } = require('./src/graphql');
const { PKISystem } = require('./src/pki');
const HttpService = require('./src/services/HttpService');

(async () => {
  // --- init infra ---
  const db = new NoSQL();
  await db.init();

  const smtp = new SMTPService({
    username: 'aybarsyildirim.network@gmail.com',
    password: 'lvft tmdk zmye njwt'
  });

  const pki = new PKISystem();

  // AuthService: dev memory token store by default here
  const authService = new AuthService({ db, pki, smtp, persistTokens: false });

  // HttpService instance (uses your new compact API)
  const http = new HttpService(authService, {
    publicPath: path.join(__dirname, 'public'),
    pagesPath: path.join(__dirname, 'public', 'pages'),
    maxRequestsPerMinute: 200,
    uploadDefaultLimit: 8 * 1024 * 1024,
    uploadDefaultMaxKBps: 1024,
    allowedOrigins: ['https://fitfak.net']
  });

  // ---------------- Auth GraphQL schema ----------------
  // note: resolvers receive context: { db, req, res, authService, http, user }
  const authSchema = {
    Mutation: {
      register: {
        auth: false,
        resolve: async (_p, args, { authService }) => {
          try {
            const { success, userId, tokenSent } = await authService.register(args);
            return {
              success,
              data: tokenSent ? 'Doğrulama bağlantısı e-posta ile gönderildi.' : 'Kayıt oluşturuldu (test token üretildi).'
            };
          } catch (e) {
            return { success: false, message: e.message };
          }
        }
      },

      login: {
        auth: false,
        resolve: async (_p, { email, password }, { authService, req, res }) => {
          const result = await authService.login(email, password);
          if (!result.success) return { success: false, message: result.message };

          const token = result.data.token;
          // return minimal info (token optional)
          return { success: true, data: { token } };
        }
      },
      session: {
  auth: false,
  resolve: async (_p, { token }, { authService, res, req, db }) => {
    try {
      // 1) Doğrula
      const payload = await authService.verifyJWT(token);

      if (!payload) return { success: false, message: 'Invalid or expired token' };

      // 2) (Opsiyonel) DB'den kullanıcı bilgisi çekme — isterseniz kullanın
      let user = null;
      try {
        if (authService.db && payload.id) {
          user = await authService.db.findOne('users', { id: payload.id });
        }
      } catch (e) {
        console.warn('[SESSION] db lookup failed', e && e.message);
      }

      // 3) Cookie ayarları
      // DEV: cross-origin test yapıyorsanız SameSite: 'Lax', secure: false kullanın.
      // PROD (cross-site): SameSite: 'None' ve secure: true (HTTPS) olmalı.
      authService.setAuthCookieOnResponse(res, token, {
        name: 'auth_token',
        ttlMs: authService.tokenTTL,
        sameSite: (process.env.NODE_ENV === 'production') ? 'None' : 'Lax',
        secure: (process.env.NODE_ENV === 'production'),
        httpOnly: true,
        path: '/'
      });

      // 4) hemen Set-Cookie header'ını logla (debug)
      try {
        const sc = (res.getHeader && res.getHeader('Set-Cookie')) || null;
      } catch (e) {
        console.log('[SESSION] could not read res.getHeader("Set-Cookie")', e && e.message);
      }

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
            const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';
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
      }
    }
  };

  // ---------------- /graph/auth proxy ----------------
  http.addRoute('POST', '/graph/auth', async (req, res) => {
    try {
      const { query, variables } = req.body || {};
      if (!query) return http.sendJson(res, 400, { success: false, message: 'GraphQL query gerekli.' });

      const ast = parse(query);
      const result = await execute({
        schema: authSchema,
        document: ast,
        variableValues: variables,
        // pass res + http + authService so resolvers can set cookies / headers
        contextValue: { db, req, res, authService, http, user: req.user }
      });

      return http.sendGraph(res, 200, result);
    } catch (e) {
      return http.sendJson(res, 400, { success: false, message: e.message });
    }
  }, { auth: false, graph: true });


const sessionSchema = {
  Query: {
    me: {
      auth: true,
      resolve: async (_p, _args, { req, db }) => {
        const user = await db.findOne('users', { id: req.user.id });

        if (!user) return { success: false, message: 'User not found' };

        // Sadece gerekli alanları döndür
        const { name, surname, schoolNumber, role } = user;

        return {
          success: true,
          data: { id: req.user.id, name, surname, schoolNumber, role }
        };
      }
    }
  },
  Mutation: {
      logout: {
        auth: true,
        resolve: async (_p, _args, { authService, req, res }) => {
          // optional: revoke tokens server-side if implemented
          if (typeof authService.revokeToken === 'function') {
            try { await authService.revokeToken(req.user?.id); } catch (e) { /* ignore */ }
          }

          // clear cookie
          authService.clearAuthCookieOnResponse(res, 'auth_token', {
            sameSite: 'Strict',
            secure: process.env.NODE_ENV === 'production',
            httpOnly: true,
            path: '/'
          });

          return { success: true, message: 'Logged out' };
        }
      }
  }
};


http.addRoute('POST', '/graph/auth/session', async (req, res) => {
    try {
      const { query, variables } = req.body || {};
      if (!query) return http.sendJson(res, 400, { success: false, message: 'GraphQL query gerekli.' });

      const ast = parse(query);
      const result = await execute({
        schema: sessionSchema,
        document: ast,
        variableValues: variables,
        // pass res + http + authService so resolvers can set cookies / headers
        contextValue: { db, req, res, authService, http, user: req.user }
      });

      return http.sendGraph(res, 200, result);
    } catch (e) {
      return http.sendJson(res, 400, { success: false, message: e.message });
    }
  }, { auth: true, graph: true });
  // ---------------- General /graphql endpoint ----------------
  const schema = {
    Query: {
      event: {
        type: 'Event',
        resolve: async (_p, { id }, { db }) => {
          const doc = await db.findOne('events', { id });
          return doc ? { __type: 'Event', ...doc } : null;
        }
      },
      events: {
        type: '[Event!]',
        resolve: async (_p, { ownerId, tag }, { db }) => {
          const filter = {};
          if (ownerId) filter.ownerId = ownerId;
          if (tag) filter.tags = { $in: [tag] };
          const list = await db.find('events', filter, { limit: 200, sort: (a, b) => a.startsAt.localeCompare(b.startsAt) });
          return list.map(e => ({ __type: 'Event', ...e }));
        }
      }
    },
    Mutation: {
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

  http.addRoute('POST', '/graph', async (req, res) => {
    const { query, variables } = req.body || {};
    if (!query) return http.sendJson(res, 400, { error: 'query required' });
    try {
      const ast = parse(query);
      const result = await execute({
        schema,
        document: ast,
        variableValues: variables,
        contextValue: { db, req, res, authService, http, user: req.user }
      });
      return http.sendGraph(res, 200, result);
    } catch (e) {
      return http.sendJson(res, 400, { error: e.message });
    }
  }, { auth: true, graph: true });

  // ---------------- PKI sign/verify ----------------
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
  }, { auth: true, roles: ['admin','user'] });

  // ---------------- HTML upload route ----------------
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

  // ---------------- start server ----------------
  const port = process.env.PORT || 80;
  http.listen(port, () => console.log(`Server listening on ${port}`));
})();
