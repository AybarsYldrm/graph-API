'use strict';
const fs = require('fs');
const path = require('path');

const { AuthService } = require('./src/services/AuthService');
const { SMTPService } = require('./src/services/SMTPService');
const { NoSQL } = require('./src/db/NoSQL');
const { parse, execute } = require('./src/graphql');
const { PKISystem } = require('./src/pki');
const HttpService = require('./src/services/HttpService');
const { SnowflakeAuth } = require('./src/services/SnowflakeAuth');
const { WebPushService } = require('./src/services/WebPushService');

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

  const snowflake = new SnowflakeAuth({
    secret: process.env.SNOWFLAKE_SECRET || 'graph-demo-snowflake-secret',
    permissionsPath: path.join(__dirname, 'data', 'permissions.json'),
    allowExpiredBypass: true
  });

  const webPush = new WebPushService({
    dataDir: path.join(__dirname, 'data', 'webpush'),
    subject: 'mailto:network@fitfak.net'
  });
  await webPush.ensureVapid();

  const permissionMap = snowflake.permissions.list.reduce((acc, entry) => {
    acc[entry.name] = 1 << entry.bit;
    return acc;
  }, {});

  const adminMask = permissionMap.ADMIN || (1 << 13);
  const manageUsersMask = permissionMap.MANAGE_USERS || 0;
  const manageRolesMask = permissionMap.MANAGE_ROLES || 0;
  const manageSettingsMask = permissionMap.MANAGE_SETTINGS || 0;
  const readMask = permissionMap.READ || (1 << 1);

  const hasRole = (user, roles) => {
    if (!user) return false;
    const list = Array.isArray(user.roles) ? user.roles.slice() : [];
    if (user.role) list.push(user.role);
    return list.some((role) => roles.includes(role));
  };

  const hasPermission = (user, mask) => {
    if (!user) return false;
    if (mask === 0) return true;
    if (hasRole(user, ['admin'])) return true;
    const value = Number(user.permissionId || 0);
    return (value & mask) === mask;
  };

  const http = new HttpService(authService, {
    publicPath: path.join(__dirname, 'public'),
    pagesPath: path.join(__dirname, 'public', 'pages'),
    maxRequestsPerMinute: 200,
    uploadDefaultLimit: 8 * 1024 * 1024,
    uploadDefaultMaxKBps: 1024,
    allowedOrigins: [
      'https://fitfak.net',
      'http://localhost',
      'http://localhost:3000',
      'https://localhost',
      'https://localhost:3000'
    ]
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
        resolve: async (_parent, _args, { req, db }) => {
          const userId = req.user?.id;
          if (!userId) throw new Error('Authentication required');
          const user = await db.findOne('users', { id: userId });
          if (!user) return { success: false, message: 'User not found' };
          const permissions = snowflake.decodePermissions(user.permissionId || 0);
          return {
            success: true,
            data: {
              id: userId,
              name: user.name,
              surname: user.surname,
              schoolNumber: user.schoolNumber,
              role: user.role,
              email: user.email,
              permissionId: user.permissionId || 0,
              permissions,
              microsoftUniqueName: user.microsoftUniqueName || null,
              lastMicrosoftLogin: user.lastMicrosoftLogin || null,
              pkiIssuedAt: user.pkiIssuedAt || null
            }
          };
        }
      },
      myPermissions: {
        auth: true,
        resolve: (_parent, _args, { req }) => {
          const user = req.user;
          if (!user) throw new Error('Authentication required');
          return {
            success: true,
            data: snowflake.decodePermissions(user.permissionId || 0)
          };
        }
      },
      event: {
        auth: true,
        resolve: async (_parent, { id }, { db, req }) => {
          const doc = await db.findOne('events', { id });
          if (!doc) return null;
          const actor = req.user;
          const isOwner = actor && doc.ownerId === actor.id;
          if (!isOwner && !hasPermission(actor, adminMask) && !hasPermission(actor, manageSettingsMask)) {
            throw new Error('Forbidden: insufficient permission');
          }
          return { __type: 'Event', ...doc };
        }
      },
      events: {
        auth: true,
        resolve: async (_parent, { ownerId, tag }, { db, req }) => {
          const actor = req.user;
          const filter = {};
          if (tag) filter.tags = { $in: [tag] };

          if (ownerId) {
            filter.ownerId = ownerId;
          } else if (!hasPermission(actor, adminMask) && !hasPermission(actor, manageSettingsMask)) {
            filter.ownerId = actor.id;
          }

          const list = await db.find('events', filter, {
            limit: 200,
            sort: (a, b) => a.startsAt.localeCompare(b.startsAt)
          });
          return list.map((event) => ({ __type: 'Event', ...event }));
        }
      },
      microsoftAuthorizationUrl: {
        auth: false,
        resolve: (_parent, args = {}, { authService }) => {
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
      },
      pushPublicKey: {
        auth: false,
        resolve: async () => {
          const key = await webPush.getOrCreatePublicKey();
          return { success: true, data: { publicKey: key } };
        }
      },
      myPushSubscriptions: {
        auth: true,
        resolve: async (_parent, _args, { req }) => {
          const subs = await webPush.listSubscriptions(req.user.id);
          return { success: true, data: subs };
        }
      },
      permissionsCatalog: {
        auth: true,
        resolve: (_parent, _args, { req }) => {
          const actor = req.user;
          if (!hasPermission(actor, adminMask) && !hasPermission(actor, manageRolesMask)) {
            throw new Error('Forbidden: insufficient permission');
          }
          return { success: true, data: snowflake.permissions.list };
        }
      }
    },
    Mutation: {
      completeMicrosoftLogin: {
        auth: false,
        resolve: async (_parent, { code, state, codeVerifier }, { authService, res }) => {
          try {
            const result = await authService.handleMicrosoftCallback({ code, state, codeVerifier });
            if (result.success && result.data?.cookie?.token) {
              const cfg = Object.assign({}, cookieDefaults);
              if (result.data.cookie.ttlMs != null) cfg.ttlMs = result.data.cookie.ttlMs;
              authService.setAuthCookieOnResponse(res, result.data.cookie.token, cfg);
            }
            return result;
          } catch (err) {
            return { success: false, message: err.message };
          }
        }
      },
      logout: {
        auth: true,
        resolve: async (_parent, _args, { authService, res }) => {
          authService.clearAuthCookieOnResponse(res, cookieDefaults.name, cookieDefaults);
          return { success: true, message: 'Logged out' };
        }
      },
      createEvent: {
        auth: true,
        resolve: async (_parent, { title, startsAt, endsAt, location, tags }, { db, req }) => {
          const actor = req.user;
          if (!hasPermission(actor, adminMask) && !hasPermission(actor, manageSettingsMask)) {
            throw new Error('Forbidden: insufficient permission');
          }
          const created = await db.insert('events', {
            title,
            startsAt,
            endsAt,
            ownerId: actor.id,
            location,
            tags: tags || []
          });
          return { __type: 'Event', ...created };
        }
      },
      updateEvent: {
        auth: true,
        resolve: async (_parent, { id, ...patch }, { db, req }) => {
          const actor = req.user;
          if (!hasPermission(actor, adminMask) && !hasPermission(actor, manageSettingsMask)) {
            throw new Error('Forbidden: insufficient permission');
          }
          const existing = await db.findOne('events', { id });
          if (!existing) throw new Error('Event bulunamadı.');
          const updated = await db.update('events', id, patch);
          return updated ? { __type: 'Event', ...updated } : null;
        }
      },
      deleteEvent: {
        auth: true,
        resolve: async (_parent, { id }, { db, req }) => {
          const actor = req.user;
          if (!hasPermission(actor, adminMask) && !hasPermission(actor, manageSettingsMask)) {
            throw new Error('Forbidden: insufficient permission');
          }
          return db.remove('events', id);
        }
      },
      registerPushSubscription: {
        auth: true,
        resolve: async (_parent, { subscription, metadata }, { req }) => {
          const ip = req.socket?.remoteAddress;
          if (!webPush.checkRateLimit(ip)) {
            throw new Error('Too many push subscription attempts');
          }
          const record = await webPush.subscribe(req.user.id, subscription, {
            userAgent: metadata?.userAgent || req.headers['user-agent'] || null,
            platform: metadata?.platform || null
          });
          return { success: true, data: { endpoint: record.endpoint, browser: record.browser } };
        }
      },
      removePushSubscription: {
        auth: true,
        resolve: async (_parent, { endpoint }, { req }) => {
          if (!endpoint) throw new Error('Endpoint gerekli');
          const removed = await webPush.unsubscribe(req.user.id, endpoint);
          return { success: removed, endpoint };
        }
      },
      sendPushNotification: {
        auth: true,
        resolve: async (_parent, { userId, title, body, icon, url: targetUrl, ttl }, { req }) => {
          const actor = req.user;
          if (!hasPermission(actor, adminMask) && !hasPermission(actor, manageUsersMask)) {
            throw new Error('Forbidden: insufficient permission');
          }
          if (!title) throw new Error('Başlık gerekli');

          const message = {
            title: String(title),
            body: body ? String(body) : '',
            icon: icon ? String(icon) : undefined,
            data: {}
          };
          if (targetUrl) message.data.url = String(targetUrl);

          const options = {};
          if (Number.isInteger(ttl) && ttl > 0) options.ttl = ttl;

          const results = userId
            ? await webPush.sendToUser(userId, message, options)
            : await webPush.broadcast(message, options);

          return { success: true, target: userId || 'broadcast', results };
        }
      },
      generateSnowflakeToken: {
        auth: true,
        resolve: (_parent, { permissionId, actionId, mode = 'secure', ttlMs }, { req }) => {
          const actor = req.user;
          if (!hasPermission(actor, adminMask) && !hasPermission(actor, manageRolesMask)) {
            throw new Error('Forbidden: insufficient permission');
          }

          const pid = Number(permissionId || 0);
          const aid = Number(actionId || 0);

          if (mode === 'plain') {
            const token = snowflake.createPlain(pid, aid);
            return {
              success: true,
              mode: 'plain',
              token,
              permission: snowflake.decodePermissions(pid)
            };
          }

          const { token, expiresAt, ttl } = snowflake.createSecure(pid, aid, ttlMs);
          return {
            success: true,
            mode: 'secure',
            token,
            ttlMs: ttl,
            expiresAt: new Date(expiresAt).toISOString(),
            permission: snowflake.decodePermissions(pid)
          };
        }
      },
      verifySnowflakeToken: {
        auth: true,
        resolve: (_parent, { token }, { req }) => {
          const actor = req.user;
          if (!token) throw new Error('Token gerekli');
          if (!hasPermission(actor, adminMask) && !hasPermission(actor, manageUsersMask) && !hasPermission(actor, readMask)) {
            throw new Error('Forbidden: insufficient permission');
          }

          const normalized = String(token).replace(/[^0-9]/g, '');
          if (!normalized) throw new Error('Token formatı geçersiz');

          const decode = normalized.length > 30
            ? snowflake.verifySecure(normalized)
            : snowflake.verifyPlain(normalized);

          if (!decode.ok) {
            return { success: false, decode };
          }

          return {
            success: true,
            decode,
            permission: snowflake.decodePermissions(decode.permissionId)
          };
        }
      }
    },
    types: { Event: {} }
  };

  const registerGraphEndpoint = (pathPattern) => {
    http.registerGraphQL(pathPattern, {
      schema: graphSchema,
      parse,
      execute,
      contextFactory: ({ req, res }) => ({
        db,
        authService,
        pki,
        webPush,
        snowflake,
        permissions: permissionMap,
        user: req?.user || null,
        req,
        res
      })
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
    allowedRedirectOrigins: [
      'https://fitfak.net',
      'http://localhost:3000',
      'https://localhost:3000',
      'http://localhost',
      'https://localhost'
    ]
  });

  http.addRoute('POST', '/sign', async (req, res) => {
    const { payload } = req.body || {};
    if (!payload) return http.sendJson(res, 400, { success: false, message: 'Missing payload' });
    try {
      const envelope = await pki.sign(req.user.id, payload);
      return http.sendJson(res, 200, { success: true, envelope });
    } catch (err) {
      return http.sendJson(res, 500, { success: false, message: err.message });
    }
  }, { auth: true, roles: ['admin'] });

  http.addRoute('POST', '/verify', async (req, res) => {
    const { envelope } = req.body || {};
    if (!envelope) return http.sendJson(res, 400, { success: false, message: 'Missing envelope' });
    try {
      const result = pki.verify(envelope);
      return http.sendJson(res, 200, { success: true, result });
    } catch (err) {
      return http.sendJson(res, 400, { success: false, message: err.message });
    }
  }, { auth: true });

  http.addRoute('GET', '/sw.js', (_req, res) => {
    try {
      const file = fs.readFileSync(path.join(__dirname, 'public', 'sw.js'), 'utf8');
      res.writeHead(200, Object.assign({
        'Content-Type': 'application/javascript; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate'
      }, http.securityHeaders));
      res.end(file);
    } catch (err) {
      http.sendJson(res, 404, { success: false, message: 'Service worker bulunamadı' });
    }
  });

  http.addRoute('GET', '/api/push/vapid', async (_req, res) => {
    const key = await webPush.getOrCreatePublicKey();
    return http.sendJson(res, 200, { success: true, data: { publicKey: key } });
  });

  http.addRoute('POST', '/api/push/subscribe', async (req, res) => {
    const ip = req.socket?.remoteAddress;
    if (!webPush.checkRateLimit(ip)) {
      return http.sendJson(res, 429, { success: false, message: 'Rate limit exceeded' });
    }
    const subscription = req.body?.subscription;
    const metadata = req.body?.metadata || {};
    if (!subscription || !subscription.endpoint) {
      return http.sendJson(res, 400, { success: false, message: 'Subscription endpoint gerekli' });
    }
    try {
      const record = await webPush.subscribe(req.user.id, subscription, {
        userAgent: metadata.userAgent || req.headers['user-agent'] || null,
        platform: metadata.platform || null
      });
      return http.sendJson(res, 201, { success: true, data: { endpoint: record.endpoint, browser: record.browser } });
    } catch (err) {
      return http.sendJson(res, 400, { success: false, message: err.message });
    }
  }, { auth: true });

  http.addRoute('POST', '/api/push/unsubscribe', async (req, res) => {
    const endpoint = req.body?.endpoint;
    if (!endpoint) {
      return http.sendJson(res, 400, { success: false, message: 'Endpoint gerekli' });
    }
    const removed = await webPush.unsubscribe(req.user.id, endpoint);
    return http.sendJson(res, 200, { success: removed, endpoint });
  }, { auth: true });

  http.addRoute('POST', '/api/push/send', async (req, res) => {
    const actor = req.user;
    if (!hasPermission(actor, adminMask) && !hasPermission(actor, manageUsersMask)) {
      return http.sendJson(res, 403, { success: false, message: 'Forbidden' });
    }

    const ip = req.socket?.remoteAddress;
    if (!webPush.checkRateLimit(ip)) {
      return http.sendJson(res, 429, { success: false, message: 'Rate limit exceeded' });
    }

    const { userId, title, body, icon, url: targetUrl, ttl } = req.body || {};
    if (!title) {
      return http.sendJson(res, 400, { success: false, message: 'Başlık gerekli' });
    }

    const message = {
      title: String(title),
      body: body ? String(body) : '',
      icon: icon ? String(icon) : undefined,
      data: {}
    };
    if (targetUrl) message.data.url = String(targetUrl);

    const options = {};
    if (Number.isInteger(ttl) && ttl > 0) options.ttl = ttl;

    try {
      const results = userId
        ? await webPush.sendToUser(userId, message, options)
        : await webPush.broadcast(message, options);
      return http.sendJson(res, 200, { success: true, target: userId || 'broadcast', results });
    } catch (err) {
      return http.sendJson(res, 500, { success: false, message: err.message });
    }
  }, { auth: true });

  http.addRoute('GET', '/api/snowflake/permissions', (_req, res) => {
    return http.sendJson(res, 200, { success: true, data: snowflake.permissions.list });
  }, { auth: true });

  http.addRoute('POST', '/api/snowflake/generate', (req, res) => {
    const actor = req.user;
    if (!hasPermission(actor, adminMask) && !hasPermission(actor, manageRolesMask)) {
      return http.sendJson(res, 403, { success: false, message: 'Forbidden' });
    }

    const { permissionId, actionId, mode = 'secure', ttlMs } = req.body || {};
    const pid = Number(permissionId || 0);
    const aid = Number(actionId || 0);

    if (mode === 'plain') {
      const token = snowflake.createPlain(pid, aid);
      return http.sendJson(res, 200, {
        success: true,
        mode: 'plain',
        token,
        permission: snowflake.decodePermissions(pid)
      });
    }

    try {
      const { token, expiresAt, ttl } = snowflake.createSecure(pid, aid, ttlMs);
      return http.sendJson(res, 200, {
        success: true,
        mode: 'secure',
        token,
        ttlMs: ttl,
        expiresAt: new Date(expiresAt).toISOString(),
        permission: snowflake.decodePermissions(pid)
      });
    } catch (err) {
      return http.sendJson(res, 400, { success: false, message: err.message });
    }
  }, { auth: true });

  http.addRoute('POST', '/api/snowflake/verify', (req, res) => {
    const actor = req.user;
    if (!hasPermission(actor, adminMask) && !hasPermission(actor, manageUsersMask) && !hasPermission(actor, readMask)) {
      return http.sendJson(res, 403, { success: false, message: 'Forbidden' });
    }

    const token = String(req.body?.token || '').replace(/[^0-9]/g, '');
    if (!token) {
      return http.sendJson(res, 400, { success: false, message: 'Token gerekli' });
    }

    const decode = token.length > 30 ? snowflake.verifySecure(token) : snowflake.verifyPlain(token);
    if (!decode.ok) {
      return http.sendJson(res, 400, { success: false, decode });
    }

    return http.sendJson(res, 200, {
      success: true,
      decode,
      permission: snowflake.decodePermissions(decode.permissionId)
    });
  }, { auth: true });

  http.addRoute('POST', '/html', async (req, res) => {
    if (!req.body || !req.body.files) return http.sendJson(res, 400, { success: false, files: [] });
    const files = req.body.files.map((f) => ({ field: f.fieldname, filename: f.filename }));
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
