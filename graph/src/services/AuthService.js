'use strict';

const crypto = require('crypto');
const https = require('https');
const fs = require('fs').promises;
const path = require('path');
const { URL } = require('url');

const DEFAULT_USER_PERMISSIONS = (1 << 0) | (1 << 1);
const ADMIN_PERMISSIONS = 0x3FFF;

class AuthService {
  constructor(opts = {}) {
    this.db = opts.db;
    this.pki = opts.pki;
    this.smtp = opts.smtp;
    this.baseDir = opts.baseDir || path.join(process.cwd(), 'pki');

    this.iterations = 310_000;
    this.keylen = 64;
    this.digest = 'sha512';

    this.tokenTTL = opts.tokenTTLMs || 1000 * 60 * 60; // 1 saat
    this.resetRateLimit = opts.resetRateLimit || 3;
    this.resetRateLimitWindow = opts.resetRateLimitWindow || 1000 * 60 * 10; // 10 dk

    this.tokens = new Map();
    this.tokens.remove = (t) => this.tokens.delete(t);

    this.resetRequestCounts = new Map();

    this.emailSendWindow = opts.emailSendWindow || 1000 * 60 * 10; // 10 dk
    this.lastEmailSends = new Map(); // userId -> { type, token, sentAt }

    const microsoftOpts = Object.assign({}, opts.microsoft || {});
    this.microsoft = {
      tenantId: microsoftOpts.tenantId || opts.microsoftTenantId || 'common',
      clientId: microsoftOpts.clientId || opts.microsoftClientId || null,
      clientSecret: microsoftOpts.clientSecret || opts.microsoftClientSecret || null,
      redirectUri: microsoftOpts.redirectUri || opts.microsoftRedirectUri || null,
      scope: Array.isArray(microsoftOpts.scope)
        ? microsoftOpts.scope
        : String(microsoftOpts.scope || opts.microsoftScope || 'openid profile email offline_access User.Read')
            .split(/\s+/)
            .filter(Boolean),
      authorityHost: microsoftOpts.authorityHost || 'https://login.microsoftonline.com',
      graphHost: microsoftOpts.graphHost || 'https://graph.microsoft.com',
      timeoutMs: microsoftOpts.timeoutMs || 10_000,
      openIdConfigUrl: microsoftOpts.openIdConfigUrl
        || `${(microsoftOpts.authorityHost || 'https://login.microsoftonline.com').replace(/\/$/, '')}/${microsoftOpts.tenantId || opts.microsoftTenantId || 'common'}/v2.0/.well-known/openid-configuration`
    };

    this.microsoftOpenIdConfig = null;
    this.microsoftOpenIdFetchedAt = 0;
    this.microsoftJwks = null;
    this.microsoftJwksFetchedAt = 0;
    this.microsoftJwksTtlMs = microsoftOpts.jwksTtlMs || 60 * 60 * 1000;

    const cleanupMs = opts.tokenCleanupIntervalMs || 1000 * 60 * 60;
    this._cleanupHandle = setInterval(() => this._cleanupExpiredTokens(), cleanupMs);
    this._cleanupHandle.unref && this._cleanupHandle.unref();
  }

  _permissionForRole(role, existingPermissionId = null) {
    if (role === 'admin') return ADMIN_PERMISSIONS;
    if (typeof existingPermissionId === 'number' && existingPermissionId > 0) {
      return existingPermissionId;
    }
    return DEFAULT_USER_PERMISSIONS;
  }

  // -------------------------
  // Path helpers
  // -------------------------
  _userDir(type, userId) {
    const safeId = String(userId || '').trim();
    if (!safeId) throw new Error('User id gerekli.');
    return path.join(this.baseDir, type, safeId);
  }

  keyPathFor(userId) { return path.join(this._userDir('keys', userId), 'private.key.pem'); }
  publicKeyPathFor(userId) { return path.join(this._userDir('keys', userId), 'public.key.pem'); }
  certPathFor(userId) { return path.join(this._userDir('certs', userId), 'certificate.crt.pem'); }

  // -------------------------
  // Token helpers
  // -------------------------
  generateToken(numBytes = 32) { return crypto.randomBytes(numBytes).toString('base64url'); }

  async _storeToken(type, token, record) {
    const rec = Object.assign({}, record, { type, createdAt: Date.now() });
    this.tokens.set(token, rec);
  }

  async _getToken(token) {
    const rec = this.tokens.get(token);
    return rec ? Object.assign({ token }, rec) : null;
  }

  async _deleteToken(token) {
    if (typeof this.tokens.remove === 'function') this.tokens.remove(token);
    else this.tokens.delete(token);
  }

  async _cleanupExpiredTokens() {
    const now = Date.now();
    for (const [t, rec] of this.tokens.entries()) {
      if (!rec || (rec.expiresAt && rec.expiresAt <= now)) this.tokens.delete(t);
    }
  }

  // -------------------------
  // Microsoft OAuth helpers
  // -------------------------
  microsoftConfigValid() {
    return Boolean(this.microsoft && this.microsoft.clientId && this.microsoft.redirectUri);
  }

  _assertMicrosoftConfig() {
    if (!this.microsoftConfigValid()) {
      throw new Error('Microsoft OAuth yapılandırması eksik (clientId veya redirectUri tanımlı değil).');
    }
  }

  buildMicrosoftState(payload = {}) {
    try {
      const base = Object.assign({ ts: Date.now() }, payload || {});
      return Buffer.from(JSON.stringify(base), 'utf8').toString('base64url');
    } catch (err) {
      throw new Error('Microsoft state oluşturulamadı.');
    }
  }

  parseMicrosoftState(state) {
    if (!state) return null;
    try {
      const json = Buffer.from(String(state), 'base64url').toString('utf8');
      return JSON.parse(json);
    } catch (err) {
      return null;
    }
  }

  buildMicrosoftAuthorizationUrl(options = {}) {
    this._assertMicrosoftConfig();

    const state = options.state || (options.statePayload ? this.buildMicrosoftState(options.statePayload) : undefined);
    const authorizeUrl = new URL(`${this.microsoft.authorityHost.replace(/\/$/, '')}/${this.microsoft.tenantId}/oauth2/v2.0/authorize`);
    const params = new URLSearchParams({
      client_id: this.microsoft.clientId,
      response_type: 'code',
      response_mode: 'query',
      redirect_uri: this.microsoft.redirectUri,
      scope: this.microsoft.scope.join(' ')
    });

    if (state) params.set('state', state);
    if (options.prompt) params.set('prompt', options.prompt);
    if (options.loginHint) params.set('login_hint', options.loginHint);
    if (options.domainHint) params.set('domain_hint', options.domainHint);
    if (options.codeChallenge) {
      params.set('code_challenge', options.codeChallenge);
      params.set('code_challenge_method', options.codeChallengeMethod || 'S256');
    }

    authorizeUrl.search = params.toString();
    return { url: authorizeUrl.toString(), state: state || null };
  }

  _httpsRequest(options, body = null, timeoutMs = null) {
    return new Promise((resolve, reject) => {
      const req = https.request({
        method: options.method || 'GET',
        hostname: options.hostname,
        path: options.path,
        headers: options.headers || {},
        port: options.port || 443,
        protocol: options.protocol || 'https:'
      }, (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          resolve({ statusCode: res.statusCode || 0, headers: res.headers || {}, body: raw });
        });
      });

      req.on('error', reject);
      const to = timeoutMs || this.microsoft.timeoutMs;
      if (to) {
        req.setTimeout(to, () => {
          req.destroy(new Error('HTTPS isteği zaman aşımına uğradı.'));
        });
      }

      if (body) req.write(body);
      req.end();
    });
  }

  async _fetchJsonFromUrl(urlStr, options = {}) {
    const parsed = new URL(urlStr);
    const response = await this._httpsRequest({
      method: options.method || 'GET',
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      headers: options.headers || {}
    });

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw new Error(`HTTP ${response.statusCode}`);
    }

    try {
      return JSON.parse(response.body || '{}');
    } catch (err) {
      throw new Error('JSON yanıtı çözümlenemedi');
    }
  }

  async _getMicrosoftOpenIdConfig(force = false) {
    const now = Date.now();
    if (!force && this.microsoftOpenIdConfig && (now - this.microsoftOpenIdFetchedAt < this.microsoftJwksTtlMs)) {
      return this.microsoftOpenIdConfig;
    }

    this._assertMicrosoftConfig();
    const cfg = await this._fetchJsonFromUrl(this.microsoft.openIdConfigUrl);
    this.microsoftOpenIdConfig = cfg;
    this.microsoftOpenIdFetchedAt = now;
    return cfg;
  }

  async _loadMicrosoftJwks(force = false) {
    const now = Date.now();
    if (!force && this.microsoftJwks && (now - this.microsoftJwksFetchedAt < this.microsoftJwksTtlMs)) {
      return this.microsoftJwks;
    }

    const cfg = await this._getMicrosoftOpenIdConfig();
    if (!cfg || !cfg.jwks_uri) throw new Error('Microsoft JWKS adresi bulunamadı.');

    const jwks = await this._fetchJsonFromUrl(cfg.jwks_uri);
    if (!jwks || !Array.isArray(jwks.keys)) throw new Error('Microsoft JWKS yanıtı geçersiz.');

    this.microsoftJwks = jwks;
    this.microsoftJwksFetchedAt = now;
    return jwks;
  }

  async _getMicrosoftJwk(kid) {
    if (!kid) throw new Error('Microsoft token kid alanı eksik.');
    const jwks = await this._loadMicrosoftJwks();
    const found = jwks.keys.find(k => k.kid === kid);
    if (!found) {
      // force refresh once if key not found
      const refreshed = await this._loadMicrosoftJwks(true);
      const retry = refreshed.keys.find(k => k.kid === kid);
      if (!retry) throw new Error('Microsoft JWKS içinde anahtar bulunamadı.');
      return retry;
    }
    return found;
  }

  async verifyMicrosoftIdToken(token) {
    if (!token) return null;
    const parts = String(token).split('.');
    if (parts.length !== 3) return null;

    let header;
    let payload;
    try {
      header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    } catch (err) {
      return null;
    }

    if (!header || !payload || !header.kid) return null;

    let key;
    try {
      key = await this._getMicrosoftJwk(header.kid);
    } catch (err) {
      return null;
    }

    let publicKey;
    try {
      publicKey = crypto.createPublicKey({ key, format: 'jwk' });
    } catch (err) {
      return null;
    }

    const verifierInput = Buffer.from(`${parts[0]}.${parts[1]}`);
    const signature = Buffer.from(parts[2], 'base64url');

    const algorithm = header.alg || 'RS256';
    const algo = algorithm === 'RS256' ? 'RSA-SHA256' : (algorithm === 'RS512' ? 'RSA-SHA512' : null);
    if (!algo) return null;

    const ok = crypto.verify(algo, verifierInput, publicKey, signature);
    if (!ok) return null;

    if (payload.exp && payload.exp * 1000 <= Date.now()) return null;
    if (this.microsoft.clientId) {
      const aud = payload.aud;
      if (Array.isArray(aud)) {
        if (!aud.includes(this.microsoft.clientId)) return null;
      } else if (aud && aud !== this.microsoft.clientId) {
        return null;
      }
    }

    const cfg = await this._getMicrosoftOpenIdConfig().catch(() => null);
    if (cfg && cfg.issuer && payload.iss && payload.iss !== cfg.issuer) return null;

    return payload;
  }

  async _exchangeMicrosoftCodeForToken(code, codeVerifier) {
    this._assertMicrosoftConfig();
    if (!code) throw new Error('Microsoft authorization code gerekli.');

    const tokenUrl = new URL(`${this.microsoft.authorityHost.replace(/\/$/, '')}/${this.microsoft.tenantId}/oauth2/v2.0/token`);
    const form = new URLSearchParams({
      client_id: this.microsoft.clientId,
      scope: this.microsoft.scope.join(' '),
      redirect_uri: this.microsoft.redirectUri,
      grant_type: 'authorization_code',
      code
    });

    if (this.microsoft.clientSecret) form.set('client_secret', this.microsoft.clientSecret);
    if (codeVerifier) form.set('code_verifier', codeVerifier);

    const body = form.toString();
    const response = await this._httpsRequest({
      method: 'POST',
      hostname: tokenUrl.hostname,
      path: tokenUrl.pathname + tokenUrl.search,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body, 'utf8').toString()
      }
    }, body);

    let parsed = null;
    try { parsed = JSON.parse(response.body || '{}'); } catch (err) {
      throw new Error('Microsoft token yanıtı çözümlenemedi.');
    }

    if (response.statusCode < 200 || response.statusCode >= 300 || parsed.error) {
      const message = parsed && (parsed.error_description || parsed.error) ? `${parsed.error}: ${parsed.error_description || ''}`.trim() : `HTTP ${response.statusCode}`;
      throw new Error(`Microsoft token isteği başarısız: ${message}`);
    }

    if (!parsed.access_token) throw new Error('Microsoft token yanıtı access_token içermiyor.');
    return parsed;
  }

  async _fetchMicrosoftProfile(accessToken) {
    if (!accessToken) throw new Error('Microsoft access token eksik.');
    const meUrl = new URL('/v1.0/me', this.microsoft.graphHost);

    const response = await this._httpsRequest({
      method: 'GET',
      hostname: meUrl.hostname,
      path: meUrl.pathname + meUrl.search,
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    });

    let parsed = null;
    try { parsed = JSON.parse(response.body || '{}'); } catch (err) {
      throw new Error('Microsoft Graph yanıtı çözümlenemedi.');
    }

    if (response.statusCode < 200 || response.statusCode >= 300 || parsed.error) {
      const message = parsed && (parsed.error && parsed.error.message) ? parsed.error.message : `HTTP ${response.statusCode}`;
      throw new Error(`Microsoft Graph isteği başarısız: ${message}`);
    }
    return parsed;
  }

  async loginWithMicrosoft(code, options = {}) {
    if (!this.db) throw new Error('Veritabanı servisi yapılandırılmamış.');

    const tokenSet = await this._exchangeMicrosoftCodeForToken(code, options.codeVerifier);
    if (!tokenSet.id_token) throw new Error('Microsoft yanıtı id_token içermiyor.');

    const idTokenPayload = await this.verifyMicrosoftIdToken(tokenSet.id_token);
    if (!idTokenPayload) throw new Error('Microsoft id_token doğrulanamadı.');

    const profile = await this._fetchMicrosoftProfile(tokenSet.access_token);
    const statePayload = options.state ? this.parseMicrosoftState(options.state) : null;

    const email = profile.mail || profile.userPrincipalName || profile.preferredUsername || idTokenPayload.preferred_username || idTokenPayload.email;
    if (!email) throw new Error('Microsoft hesabı e-posta bilgisi içermiyor.');

    const uniqueMicrosoftId = idTokenPayload.oid || idTokenPayload.sub || profile.id;
    if (!uniqueMicrosoftId) throw new Error('Microsoft kullanıcısı için benzersiz kimlik alınamadı.');

    let user = await this.db.findOne('users', { microsoftId: uniqueMicrosoftId });
    if (!user) user = await this.db.findOne('users', { email });

    const timestamp = new Date().toISOString();
    const basePatch = {
      microsoftId: uniqueMicrosoftId,
      microsoftObjectId: idTokenPayload.oid || null,
      microsoftTenantId: idTokenPayload.tid || this.microsoft.tenantId,
      microsoftUniqueName: idTokenPayload.preferred_username || null,
      lastMicrosoftLogin: timestamp
    };
    if (tokenSet.refresh_token) basePatch.microsoftRefreshToken = tokenSet.refresh_token;

    const firstLogin = !user || !user.lastMicrosoftLogin;

    if (!user) {
      const display = typeof profile.displayName === 'string' ? profile.displayName.trim() : '';
      const displayParts = display ? display.split(/\s+/) : [];
      const given = profile.givenName || displayParts[0] || email;
      const family = profile.surname || (displayParts.length > 1 ? displayParts.slice(1).join(' ') : '');
      const permissionId = this._permissionForRole('user');
      user = await this.db.insert('users', {
        email,
        name: given,
        surname: family,
        role: 'user',
        permissionId,
        passwordHash: 'microsoft-oauth',
        verified: true,
        authProvider: 'microsoft',
        ...basePatch
      });
    } else {
      const provider = user.authProvider && user.authProvider !== 'local' ? user.authProvider : 'microsoft';
      const patch = Object.assign({}, basePatch, {
        verified: true,
        authProvider: provider
      });
      patch.permissionId = this._permissionForRole(user.role || 'user', user.permissionId);
      if (!user.name) {
        const display = typeof profile.displayName === 'string' ? profile.displayName.trim() : '';
        if (profile.givenName) patch.name = profile.givenName;
        else if (display) patch.name = display.split(/\s+/)[0];
      }
      if (!user.surname) {
        if (profile.surname) patch.surname = profile.surname;
        else if (typeof profile.displayName === 'string') {
          const parts = profile.displayName.trim().split(/\s+/);
          if (parts.length > 1) patch.surname = parts.slice(1).join(' ');
        }
      }
      if (!user.email && email) patch.email = email;
      const updated = await this.db.update('users', user.id, patch);
      if (updated) user = updated;
    }

    const certInfo = await this.ensureCertificateForUser(user);

    if (firstLogin && this.smtp) {
      try {
        this.smtp.send({
          from: 'network@fitfak.net',
          to: email,
          subject: 'Microsoft ile oturum açma tamamlandı',
          message: `Merhaba ${user.name || ''},<br/>Microsoft hesabınızla ilk oturum açma işleminiz tamamlandı.<br/>PKI sertifikanız ${certInfo.created ? 'oluşturuldu.' : 'mevcut sertifikanız kullanılacaktır.'}`
        });
      } catch (e) {
        // ignore mail failures
      }
    }

    const cookieTtlMs = idTokenPayload.exp ? Math.max(0, (idTokenPayload.exp * 1000) - Date.now()) : this.tokenTTL;

    return {
      success: true,
      data: {
        token: tokenSet.id_token,
        cookie: { token: tokenSet.id_token, ttlMs: cookieTtlMs },
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          surname: user.surname,
          role: user.role
        },
        state: statePayload,
        expiresIn: tokenSet.expires_in || null,
        scope: tokenSet.scope || null
      }
    };
  }

  async handleMicrosoftCallback(params = {}) {
    const result = await this.loginWithMicrosoft(params.code, { state: params.state, codeVerifier: params.codeVerifier });
    return result;
  }

  // -------------------------
  // Email send rate-limiting
  // -------------------------
  async _shouldSendEmail(userId, type) {
    const prev = this.lastEmailSends.get(userId);
    if (prev && prev.type === type && (Date.now() - prev.sentAt < this.emailSendWindow)) {
      return { send: false, token: prev.token };
    }
    return { send: true };
  }

  async _markEmailSent(userId, type, token) {
    this.lastEmailSends.set(userId, { type, token, sentAt: Date.now() });
  }

  // -------------------------
  // Password helpers
  // -------------------------
  hashPassword(password) {
    const salt = crypto.randomBytes(16);
    const hash = crypto.pbkdf2Sync(password, salt, this.iterations, this.keylen, this.digest);
    return `pbkdf2-${this.iterations}-${salt.toString('hex')}-${hash.toString('hex')}`;
  }

  async verifyPassword(password, storedHash) {
    if (!storedHash || typeof storedHash !== 'string') return false;
    const parts = storedHash.split('-');
    if (parts.length < 4 || parts[0] !== 'pbkdf2') throw new Error('Unsupported hash type');
    const iter = parseInt(parts[1], 10);
    const salt = Buffer.from(parts[2], 'hex');
    const original = Buffer.from(parts[3], 'hex');
    const test = crypto.pbkdf2Sync(password, salt, iter, original.length, this.digest);
    return crypto.timingSafeEqual(original, test);
  }

  // -------------------------
  // Validation helpers
  // -------------------------
  validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !re.test(email)) return { ok: false, message: 'Geçerli bir email adresi giriniz.' };
    return { ok: true };
  }

  validatePasswordRules(password) {
    const pw = password === undefined || password === null ? '' : String(password);
    if (pw.length === 0) return { ok: false, message: 'Şifre boş olamaz.' };
    if (pw.length < 8) return { ok: false, message: 'Şifre en az 8 karakter olmalıdır.' };
    if (!/[a-z]/.test(pw)) return { ok: false, message: 'Şifre en az bir küçük harf içermelidir.' };
    if (!/[A-Z]/.test(pw)) return { ok: false, message: 'Şifre en az bir büyük harf içermelidir.' };
    if (!/[0-9]/.test(pw)) return { ok: false, message: 'Şifre en az bir rakam içermelidir.' };
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(pw)) return { ok: false, message: 'Şifre en az bir özel karakter içermelidir.' };
    return { ok: true };
  }

  // -------------------------
  // Register & Email verification
  // -------------------------
  async register() {
    throw new Error('Parola ile kayıt ve giriş devre dışı bırakıldı. Lütfen Microsoft ile oturum açın.');
  }

  async verifyEmailToken() {
    return { success: false, message: 'Parola tabanlı doğrulama devre dışıdır.' };
  }

  async verifyEmail() { return { success: false, message: 'Parola tabanlı doğrulama devre dışıdır.' }; }

  // -------------------------
  // Password reset
  // -------------------------
  async requestPasswordReset() {
    return { success: false, message: 'Parola sıfırlama Microsoft dışı hesaplar için devre dışıdır.' };
  }

  async validatePasswordResetToken() {
    return { valid: false, message: 'Parola sıfırlama devre dışı bırakıldı.' };
  }

  async resetPasswordToken() {
    return { success: false, message: 'Parola sıfırlama devre dışı bırakıldı.' };
  }

  async resetPassword() { return { success: false, message: 'Parola sıfırlama devre dışı bırakıldı.' }; }

  // -------------------------
  // PKI JWT
  // -------------------------
  async ensureCertificateForUser(user) {
    if (!user || !user.id) return { created: false };
    if (!this.pki || typeof this.pki.createCertForUser !== 'function') return { created: false };

    try {
      if (typeof this.pki.migrateLegacyMaterial === 'function') {
        try { this.pki.migrateLegacyMaterial(user.id); } catch (_) {}
      }
      await fs.access(this.keyPathFor(user.id));
      await fs.access(this.certPathFor(user.id));
      return { created: false, skipped: true };
    } catch (err) {
      try {
        await fs.mkdir(path.dirname(this.keyPathFor(user.id)), { recursive: true });
        await fs.mkdir(path.dirname(this.certPathFor(user.id)), { recursive: true });
      } catch (_) {}

      const created = await this.pki.createCertForUser(user);
      if (created && !created.skipped && this.db) {
        try {
          await this.db.update('users', user.id, { pkiIssuedAt: new Date().toISOString() });
        } catch (e) {
          // update best-effort
        }
      }
      return { created: !created?.skipped, details: created };
    }
  }

  async verifyJWT(token) {
    const payload = await this.verifyMicrosoftIdToken(token);
    if (!payload) return null;

    if (!this.db) return { payload };

    let user = null;
    const identifiers = [];
    if (payload.oid) identifiers.push({ microsoftId: payload.oid });
    if (payload.sub) identifiers.push({ microsoftId: payload.sub });
    if (payload.preferred_username) identifiers.push({ email: payload.preferred_username });
    if (payload.email) identifiers.push({ email: payload.email });

    for (const filter of identifiers) {
      user = await this.db.findOne('users', filter);
      if (user) break;
    }

    if (!user) return null;

    if (user && (user.permissionId == null || user.permissionId < 0)) {
      const normalized = this._permissionForRole(user.role || 'user', user.permissionId);
      if (this.db && normalized !== user.permissionId) {
        try {
          const updated = await this.db.update('users', user.id, { permissionId: normalized });
          if (updated) user = updated;
        } catch (_) {}
      } else {
        user.permissionId = normalized;
      }
    }

    return { user, payload };
  }

  async login(email, password) {
    return { success: false, message: 'Parola tabanlı giriş devre dışı bırakıldı.' };
  }

  async authorize(token, allowedRoles = []) {
    const result = await this.verifyJWT(token);
    if (!result || !result.user) return null;
    if (!Array.isArray(allowedRoles) || allowedRoles.length === 0) return result;

    const userRoles = [];
    if (result.user.role) userRoles.push(result.user.role);
    if (Array.isArray(result.user.roles)) userRoles.push(...result.user.roles);

    const hasRole = userRoles.some(r => allowedRoles.includes(r));
    if (!hasRole) return null;
    return result;
  }

    _serializeCookie(name, value, opts = {}) {
    const parts = [`${name}=${encodeURIComponent(String(value || ''))}`];

    if (opts.maxAge !== undefined && opts.maxAge !== null) {
      parts.push(`Max-Age=${Math.floor(Number(opts.maxAge))}`);
    }
    if (opts.expires) {
      const d = (opts.expires instanceof Date) ? opts.expires : new Date(opts.expires);
      parts.push(`Expires=${d.toUTCString()}`);
    }
    parts.push(`Path=${opts.path || '/'}`);

    if (opts.domain) parts.push(`Domain=${opts.domain}`);
    if (opts.httpOnly) parts.push('HttpOnly');
    if (opts.secure) parts.push('Secure');

    if (opts.sameSite) {
      // normalize to Lax/Strict/None
      const s = String(opts.sameSite).toLowerCase();
      if (['lax','strict','none'].includes(s)) {
        parts.push(`SameSite=${s.charAt(0).toUpperCase() + s.slice(1)}`);
      }
    }

    return parts.join('; ');
  }

  /**
   * Returns a serialized Set-Cookie header string for an auth token.
   * token: raw token string
   * opts: { name, ttlMs, maxAge (seconds) override, sameSite, secure, path, domain, httpOnly }
   *
   * By default: httpOnly true, secure => NODE_ENV==='production', sameSite 'Lax'
   */
  buildAuthCookieHeader(token, opts = {}) {
    const name = opts.name || 'auth_token';
    const ttlMs = (opts.ttlMs != null) ? Number(opts.ttlMs) : Number(this.tokenTTL || 3600 * 1000);
    const defaults = {
      path: opts.path || '/',
      httpOnly: (opts.httpOnly !== undefined) ? opts.httpOnly : true,
      secure: (opts.secure !== undefined) ? opts.secure : (process.env.NODE_ENV === 'production'),
      sameSite: opts.sameSite || 'Lax'
    };

    // prefer explicit maxAge in seconds, otherwise compute from ttlMs
    const maxAge = (opts.maxAge !== undefined && opts.maxAge !== null)
      ? Number(opts.maxAge)
      : Math.floor(ttlMs / 1000);

    const cookieOpts = Object.assign({}, defaults, { maxAge });

    return this._serializeCookie(name, token, cookieOpts);
  }

  buildClearCookieHeader(name = 'auth_token', opts = {}) {
    const defaults = {
      path: opts.path || '/',
      httpOnly: (opts.httpOnly !== undefined) ? opts.httpOnly : true,
      secure: (opts.secure !== undefined) ? opts.secure : (process.env.NODE_ENV === 'production'),
      sameSite: opts.sameSite || 'Lax'
    };
    // Max-Age=0 ensures deletion; Also include Expires in the past for compatibility
    const cookieOpts = Object.assign({}, defaults, { maxAge: 0, expires: new Date(0) });
    return this._serializeCookie(name, '', cookieOpts);
  }

  attachSetCookieHeader(res, headerStr) {
    try {
      const existing = res.getHeader && res.getHeader('Set-Cookie');
      if (!existing) {
        res.setHeader('Set-Cookie', headerStr);
        return;
      }
      if (Array.isArray(existing)) {
        const arr = existing.slice();
        arr.push(headerStr);
        res.setHeader('Set-Cookie', arr);
        return;
      }
      // single string -> convert to array
      res.setHeader('Set-Cookie', [String(existing), headerStr]);
    } catch (e) {
      // best-effort fallback
      try { res.setHeader('Set-Cookie', headerStr); } catch(e2) {}
    }
  }

  setAuthCookieOnResponse(res, token, opts = {}) {
    const headerStr = this.buildAuthCookieHeader(token, opts);
    this.attachSetCookieHeader(res, headerStr);
  }

  clearAuthCookieOnResponse(res, name = 'auth_token', opts = {}) {
    const headerStr = this.buildClearCookieHeader(name, opts);
    this.attachSetCookieHeader(res, headerStr);
  }

  shutdown() {
    clearInterval(this._cleanupHandle);
  }
}

module.exports = { AuthService };
