'use strict';

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const url = require('url');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

class WebPushService {
  constructor(options = {}) {
    this.dataDir = path.resolve(options.dataDir || path.join(process.cwd(), 'graph', 'data', 'webpush'));
    this.subject = options.subject || 'mailto:network@fitfak.net';
    this.rateLimitWindowMs = options.rateLimitWindowMs || 60_000;
    this.rateLimitMax = options.rateLimitMax || 30;

    this._rateMap = new Map();

    this.vapidPrivPath = path.join(this.dataDir, 'vapid_priv.pem');
    this.vapidPubJwkPath = path.join(this.dataDir, 'vapid_pub.jwk.json');
    this.subscriptionsDir = path.join(this.dataDir, 'subscriptions');

    fs.mkdirSync(this.subscriptionsDir, { recursive: true });

    this.vapidCache = null;
  }

  // ------------- utility helpers -------------
  base64url(buf) {
    return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  base64urlToBuffer(str) {
    const replaced = str.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - (replaced.length % 4)) % 4;
    const padded = replaced + '='.repeat(padLen);
    return Buffer.from(padded, 'base64');
  }

  parseKeyFlex(str) {
    if (typeof str !== 'string') throw new Error('Subscription anahtarları geçerli değil');
    if (/-|_/g.test(str)) return this.base64urlToBuffer(str);
    return Buffer.from(str, 'base64');
  }

  ensureUncompressedPoint(buf) {
    const buffer = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
    if (buffer.length === 65 && buffer[0] === 0x04) return buffer;
    if (buffer.length === 64) return Buffer.concat([Buffer.from([0x04]), buffer]);
    throw new Error('P-256 anahtarı desteklenmiyor');
  }

  async ensureVapid() {
    if (this.vapidCache) return this.vapidCache;

    const existsPriv = fs.existsSync(this.vapidPrivPath);
    const existsPub = fs.existsSync(this.vapidPubJwkPath);

    if (existsPriv && existsPub) {
      const privPem = await fsp.readFile(this.vapidPrivPath, 'utf8');
      const publicKeyJwk = JSON.parse(await fsp.readFile(this.vapidPubJwkPath, 'utf8'));
      this.vapidCache = { privPem, publicKeyJwk };
      return this.vapidCache;
    }

    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const publicKeyJwk = publicKey.export({ format: 'jwk' });
    await fsp.writeFile(this.vapidPrivPath, privPem, 'utf8');
    await fsp.writeFile(this.vapidPubJwkPath, JSON.stringify(publicKeyJwk, null, 2), 'utf8');
    this.vapidCache = { privPem, publicKeyJwk };
    return this.vapidCache;
  }

  jwkToPublicKeyUint8(jwk) {
    const x = this.base64urlToBuffer(jwk.x);
    const y = this.base64urlToBuffer(jwk.y);
    return Buffer.concat([Buffer.from([0x04]), x, y]);
  }

  createVapidJwt(aud, subject = this.subject, ttlSeconds = 12 * 60 * 60) {
    const { privPem, publicKeyJwk } = this.vapidCache || {};
    if (!privPem || !publicKeyJwk) throw new Error('VAPID anahtarı hazır değil');

    const header = { alg: 'ES256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    const payload = { aud, exp: now + ttlSeconds, sub: subject };

    const encode = (obj) => this.base64url(Buffer.from(JSON.stringify(obj)));
    const signingInput = `${encode(header)}.${encode(payload)}`;
    const signer = crypto.createSign('SHA256');
    signer.update(signingInput);
    const signature = signer.sign({ key: privPem, dsaEncoding: 'ieee-p1363' });

    return {
      jwt: `${signingInput}.${this.base64url(signature)}`,
      publicKeyJwk
    };
  }

  _hmacSha256(key, data) {
    return crypto.createHmac('sha256', key).update(data).digest();
  }

  _hkdfExtract(salt, ikm) {
    return this._hmacSha256(salt, ikm);
  }

  _hkdfExpandOne(prk, info) {
    const infoPlus = Buffer.concat([info, Buffer.from([0x01])]);
    return this._hmacSha256(prk, infoPlus);
  }

  _rateLimitCheck(ip) {
    if (!ip) return true;
    const now = Date.now();
    const entry = this._rateMap.get(ip) || { t0: now, count: 0 };
    if (now - entry.t0 > this.rateLimitWindowMs) {
      entry.t0 = now;
      entry.count = 0;
    }
    entry.count++;
    this._rateMap.set(ip, entry);
    return entry.count <= this.rateLimitMax;
  }

  // ------------- subscription storage -------------
  _subscriptionFile(userId) {
    const safe = String(userId || '').trim();
    if (!safe) throw new Error('Kullanıcı kimliği gerekli');
    return path.join(this.subscriptionsDir, `${safe}.json`);
  }

  async _loadSubscriptions(userId) {
    const file = this._subscriptionFile(userId);
    try {
      const raw = await fsp.readFile(file, 'utf8');
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed;
      return [];
    } catch (err) {
      return [];
    }
  }

  async _saveSubscriptions(userId, subs) {
    const file = this._subscriptionFile(userId);
    await fsp.mkdir(path.dirname(file), { recursive: true });
    await fsp.writeFile(file, JSON.stringify(subs, null, 2), 'utf8');
  }

  _dedupeSubscription(subs, subscription) {
    const endpoint = subscription && subscription.endpoint;
    if (!endpoint) return subs;
    return subs.filter((entry) => entry.endpoint !== endpoint);
  }

  detectBrowser(userAgent = '') {
    const ua = String(userAgent).toLowerCase();
    if (ua.includes('edg/')) return 'edge';
    if (ua.includes('firefox/')) return 'firefox';
    if (ua.includes('safari/') && !ua.includes('chrome/')) return 'safari';
    if (ua.includes('chrome/')) return 'chrome';
    return 'unknown';
  }

  async subscribe(userId, subscription, meta = {}) {
    if (!subscription || !subscription.endpoint) {
      throw new Error('Subscription endpoint gerekli');
    }

    await this.ensureVapid();

    const existing = await this._loadSubscriptions(userId);
    const deduped = this._dedupeSubscription(existing, subscription);
    const record = Object.assign({}, subscription, {
      endpoint: subscription.endpoint,
      keys: subscription.keys,
      ua: meta.userAgent || null,
      browser: this.detectBrowser(meta.userAgent),
      platform: meta.platform || null,
      createdAt: new Date().toISOString(),
      lastResult: null
    });
    deduped.push(record);
    await this._saveSubscriptions(userId, deduped);
    return record;
  }

  async unsubscribe(userId, endpoint) {
    if (!endpoint) return false;
    const existing = await this._loadSubscriptions(userId);
    const filtered = existing.filter((entry) => entry.endpoint !== endpoint);
    if (filtered.length === existing.length) return false;
    await this._saveSubscriptions(userId, filtered);
    return true;
  }

  async listSubscriptions(userId) {
    const subs = await this._loadSubscriptions(userId);
    return subs.map((entry) => ({
      endpoint: entry.endpoint,
      browser: entry.browser,
      platform: entry.platform,
      createdAt: entry.createdAt,
      lastResult: entry.lastResult || null
    }));
  }

  async listAllUsers() {
    try {
      const files = await fsp.readdir(this.subscriptionsDir);
      return files.filter((f) => f.endsWith('.json')).map((f) => path.basename(f, '.json'));
    } catch (err) {
      return [];
    }
  }

  async _send(subscription, payloadBuf, options = {}) {
    const endpointUrl = url.parse(subscription.endpoint);
    const isHttps = endpointUrl.protocol === 'https:';
    const hostname = endpointUrl.hostname;
    const port = endpointUrl.port ? parseInt(endpointUrl.port, 10) : (isHttps ? 443 : 80);
    const pathName = endpointUrl.path;

    if (!subscription.keys || !subscription.keys.p256dh || !subscription.keys.auth) {
      throw new Error('Subscription anahtarları eksik');
    }

    const salt = crypto.randomBytes(16);
    const ecdh = crypto.createECDH('prime256v1');
    const asPublic = this.ensureUncompressedPoint(ecdh.generateKeys());

    const uaPublic = this.ensureUncompressedPoint(this.parseKeyFlex(subscription.keys.p256dh));
    const authSecret = this.parseKeyFlex(subscription.keys.auth);

    const sharedSecret = ecdh.computeSecret(uaPublic);
    const prkKey = this._hkdfExtract(authSecret, sharedSecret);

    const keyInfo = Buffer.concat([
      Buffer.from('WebPush: info', 'ascii'),
      Buffer.from([0x00]),
      uaPublic,
      asPublic
    ]);

    const ikm = this._hkdfExpandOne(prkKey, keyInfo);
    const prk = this._hkdfExtract(salt, ikm);

    const cekInfo = Buffer.concat([Buffer.from('Content-Encoding: aes128gcm', 'ascii'), Buffer.from([0x00])]);
    const nonceInfo = Buffer.concat([Buffer.from('Content-Encoding: nonce', 'ascii'), Buffer.from([0x00])]);

    const cek = this._hkdfExpandOne(prk, cekInfo).subarray(0, 16);
    const nonce = this._hkdfExpandOne(prk, nonceInfo).subarray(0, 12);

    const plaintext = Buffer.concat([payloadBuf, Buffer.from([0x02])]);
    const cipher = crypto.createCipheriv('aes-128-gcm', cek, nonce);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const bodyCipher = Buffer.concat([encrypted, authTag]);

    const rs = Buffer.alloc(4);
    rs.writeUInt32BE(4096, 0);
    const headerBlock = Buffer.concat([salt, rs, Buffer.from([asPublic.length]), asPublic]);
    const body = Buffer.concat([headerBlock, bodyCipher]);

    const audience = `${endpointUrl.protocol}//${endpointUrl.host}`;
    const { jwt, publicKeyJwk } = this.createVapidJwt(audience, options.subject || this.subject, options.ttl || 12 * 60 * 60);
    const vapidPub = this.ensureUncompressedPoint(this.jwkToPublicKeyUint8(publicKeyJwk));

    const headers = {
      'Content-Encoding': 'aes128gcm',
      'Content-Length': String(body.length),
      TTL: String(options.ttl || 2_419_200),
      Encryption: `salt=${this.base64url(salt)}`,
      'Crypto-Key': `dh=${this.base64url(asPublic)}; p256ecdsa=${this.base64url(vapidPub)}`,
      Authorization: `vapid t=${jwt}, k=${this.base64url(vapidPub)}`
    };

    const requestOptions = {
      method: 'POST',
      hostname,
      port,
      path: pathName,
      headers,
      protocol: endpointUrl.protocol
    };

    const transport = isHttps ? https : http;

    return await new Promise((resolve, reject) => {
      const req = transport.request(requestOptions, (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            body: Buffer.concat(chunks).toString('utf8')
          });
        });
      });
      req.on('error', reject);
      req.write(body);
      req.end();
    });
  }

  async sendToUser(userId, message, options = {}) {
    await this.ensureVapid();
    const subs = await this._loadSubscriptions(userId);
    if (!subs.length) return [];
    const payloadBuf = Buffer.from(JSON.stringify(message || {}), 'utf8');
    const results = [];

    for (let i = subs.length - 1; i >= 0; i--) {
      const sub = subs[i];
      try {
        const result = await this._send(sub, payloadBuf, options);
        results.push({ endpoint: sub.endpoint, statusCode: result.statusCode });
        sub.lastResult = { statusCode: result.statusCode, at: new Date().toISOString() };
        if (result.statusCode === 404 || result.statusCode === 410) {
          subs.splice(i, 1);
        }
      } catch (err) {
        results.push({ endpoint: sub.endpoint, error: err.message });
        sub.lastResult = { error: err.message, at: new Date().toISOString() };
        if (/gone|not found|410/.test(err.message || '')) subs.splice(i, 1);
      }
    }

    await this._saveSubscriptions(userId, subs);
    return results;
  }

  async broadcast(message, options = {}) {
    const userIds = await this.listAllUsers();
    const results = {};
    for (const userId of userIds) {
      results[userId] = await this.sendToUser(userId, message, options);
    }
    return results;
  }

  getPublicKeyBase64() {
    if (!this.vapidCache) return null;
    const pub = this.jwkToPublicKeyUint8(this.vapidCache.publicKeyJwk);
    return this.base64url(pub);
  }

  async getOrCreatePublicKey() {
    await this.ensureVapid();
    return this.getPublicKeyBase64();
  }

  checkRateLimit(ip) {
    return this._rateLimitCheck(ip);
  }
}

module.exports = { WebPushService };
