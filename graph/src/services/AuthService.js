'use strict';

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

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

    const cleanupMs = opts.tokenCleanupIntervalMs || 1000 * 60 * 60;
    this._cleanupHandle = setInterval(() => this._cleanupExpiredTokens(), cleanupMs);
    this._cleanupHandle.unref && this._cleanupHandle.unref();
  }

  // -------------------------
  // Path helpers
  // -------------------------
  keyPathFor(userId) { return path.join(this.baseDir, 'keys', `${userId}.key.pem`); }
  certPathFor(userId) { return path.join(this.baseDir, 'certs', `${userId}.crt.pem`); }

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
  async register({ email, name, surname, schoolNumber, password, role, originUrl }) {
    const emailCheck = this.validateEmail(email);
    if (!emailCheck.ok) throw new Error(emailCheck.message);

    const exists = await this.db.findOne('users', { email });
    if (exists) throw new Error('Bu email zaten kayıtlı.');

    const pwCheck = this.validatePasswordRules(password);
    if (!pwCheck.ok) throw new Error(pwCheck.message);

    const passwordHash = this.hashPassword(password);
    const user = await this.db.insert('users', {
      email, name, surname, schoolNumber,
      role: role || 'user',
      passwordHash,
      verified: false
    });

    if (this.pki && typeof this.pki.createCertForUser === 'function') {
      await this.pki.createCertForUser(user);
    }

    const check = await this._shouldSendEmail(user.id, 'emailVerification');
    let token;
    if (!check.send) {
      token = check.token;
    } else {
      token = this.generateToken(32);
      await this._storeToken('emailVerification', token, { userId: user.id, expiresAt: Date.now() + this.tokenTTL });

      if (this.smtp) {
        const origin = originUrl || 'https://fitfak.net';
        const verifyUrl = `${origin.replace(/\/$/, '')}/graph/auth/${token}/verify`;
        await this.smtp.send({
          from: 'network@fitfak.net',
          to: email,
          subject: 'Email Doğrulama',
          message: `Merhaba ${name},<br>Email doğrulamak için <a href="${verifyUrl}">buraya tıklayın</a>. Bu bağlantı 1 saat geçerlidir.`
        });
      }

      await this._markEmailSent(user.id, 'emailVerification', token);
    }

    return { success: true, userId: user.id, tokenSent: !!this.smtp, token };
  }

  async verifyEmailToken(token) {
    const rec = await this._getToken(token);
    if (!rec || rec.type !== 'emailVerification') return { success: false, message: 'Geçersiz veya süresi dolmuş bağlantı.' };
    if (Date.now() > rec.expiresAt) {
      await this._deleteToken(token);
      return { success: false, message: 'Bağlantı süresi dolmuş.' };
    }
    await this.db.update('users', rec.userId, { verified: true });
    await this._deleteToken(token);
    return { success: true };
  }

  async verifyEmail(token) { return this.verifyEmailToken(token); }

  // -------------------------
  // Password reset
  // -------------------------
  async requestPasswordReset(email, ip, originUrl) {
    const emailCheck = this.validateEmail(email);
    if (!emailCheck.ok) return { success: false, message: emailCheck.message };

    const user = await this.db.findOne('users', { email });
    if (!user) return { success: false, message: 'Email bulunamadı.' };

    const now = Date.now();
    const reqInfo = this.resetRequestCounts.get(ip) || { count: 0, firstRequestAt: now };
    if (now - reqInfo.firstRequestAt > this.resetRateLimitWindow) {
      reqInfo.count = 0;
      reqInfo.firstRequestAt = now;
    }
    if (reqInfo.count >= this.resetRateLimit) {
      return { success: false, message: 'Çok fazla istek. Lütfen biraz bekleyin.' };
    }
    reqInfo.count++;
    this.resetRequestCounts.set(ip, reqInfo);

    const check = await this._shouldSendEmail(user.id, 'passwordReset');
    let token;
    if (!check.send) {
      token = check.token;
    } else {
      token = this.generateToken(32);
      await this._storeToken('passwordReset', token, { userId: user.id, expiresAt: now + this.tokenTTL, ip });

      if (this.smtp) {
        const origin = originUrl || 'https://fitfak.net';
        const resetUrl = `${origin.replace(/\/$/, '')}/graph/auth/${token}/reset`;
        await this.smtp.send({
          from: 'network@fitfak.net',
          to: email,
          subject: 'Parola Sıfırlama',
          message: `Parolanızı sıfırlamak için <a href="${resetUrl}">buraya tıklayın</a>. Bu bağlantı 1 saat içinde geçerlidir.`
        });
      }

      await this._markEmailSent(user.id, 'passwordReset', token);
    }

    return { success: true, tokenSent: !!this.smtp, token };
  }

  async validatePasswordResetToken(token) {
    const rec = await this._getToken(token);
    if (!rec || rec.type !== 'passwordReset') return { valid: false, message: 'Geçersiz veya süresi dolmuş bağlantı.' };
    if (Date.now() > rec.expiresAt) {
      await this._deleteToken(token);
      return { valid: false, message: 'Bağlantı süresi dolmuş.' };
    }
    return { valid: true, userId: rec.userId };
  }

  async resetPasswordToken(token, newPassword) {
    const rec = await this._getToken(token);
    if (!rec || rec.type !== 'passwordReset') return { success: false, message: 'Geçersiz veya süresi dolmuş bağlantı.' };
    if (Date.now() > rec.expiresAt) {
      await this._deleteToken(token);
      return { success: false, message: 'Bağlantı süresi dolmuş.' };
    }

    const pwCheck = this.validatePasswordRules(newPassword);
    if (!pwCheck.ok) return { success: false, message: pwCheck.message };

    const passwordHash = this.hashPassword(String(newPassword));
    await this.db.update('users', rec.userId, { passwordHash });
    await this._deleteToken(token);
    return { success: true, message: 'Parola başarıyla güncellendi.' };
  }

  async resetPassword(token, newPassword) { return this.resetPasswordToken(token, newPassword); }

  // -------------------------
  // PKI JWT
  // -------------------------
  async createJWT(user, ttlSec = 3600) {
  const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'JWT' })).toString('base64url');
  const exp = Math.floor(Date.now() / 1000) + ttlSec;
  const payloadObj = { id: user.id, role: user.role, exp };
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');

  const dataToSign = `${header}.${payload}`;
  const privKey = await fs.readFile(this.keyPathFor(user.id), 'utf8');

  // crypto.sign ile ieee-p1363 raw r||s formatı
  const sigBuf = crypto.sign(null, Buffer.from(dataToSign), { key: privKey, dsaEncoding: 'ieee-p1363' });
  const sig = sigBuf.toString('base64url');
  return `${dataToSign}.${sig}`;
}

  async verifyJWT(token) {
  try {
    const [headerB64, payloadB64, sigB64] = token.split('.');
    if (!headerB64 || !payloadB64 || !sigB64) return null;
    const payloadObj = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
    const certPem = await fs.readFile(this.certPathFor(payloadObj.id), 'utf8');

    const verifierInput = Buffer.from(`${headerB64}.${payloadB64}`);
    const sigBuf = Buffer.from(sigB64, 'base64url');

    const ok = crypto.verify(null, verifierInput, { key: certPem, dsaEncoding: 'ieee-p1363' }, sigBuf);
    if (!ok) return null;
    if (payloadObj.exp < Math.floor(Date.now() / 1000)) return null;
    return payloadObj;
  } catch (err) {
    return null;
  }
}

  async login(email, password) {
    const emailCheck = this.validateEmail(email);
    if (!emailCheck.ok) return { success: false, message: emailCheck.message };

    const user = await this.db.findOne('users', { email });
    if (!user) return { success: false, message: 'Email bulunamadı.' };
    if (!user.verified) return { success: false, message: 'Email doğrulanmamış.' };

    const valid = await this.verifyPassword(password, user.passwordHash);
    if (!valid) return { success: false, message: 'Geçersiz şifre.' };

    const token = await this.createJWT(user);
    return { success: true, data: { token } };
  }

  async authorize(token, allowedRoles = []) {
    const payload = await this.verifyJWT(token);
    if (!payload || !allowedRoles.includes(payload.role)) return null;
    return payload;
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
