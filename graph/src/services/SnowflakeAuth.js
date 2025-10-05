'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class SnowflakeAuth {
  constructor(options = {}) {
    const secret = options.secret || process.env.SNOWFLAKE_SECRET;
    if (!secret) throw new Error('SnowflakeAuth secret is required');

    this.secret = secret;
    this.epoch = BigInt(options.epoch || 1700000000000n);
    this.defaultTtlMs = BigInt(options.defaultTtlMs || 60_000);
    this.allowExpiredBypass = options.allowExpiredBypass !== undefined
      ? Boolean(options.allowExpiredBypass)
      : true;

    this.permissionsPath = options.permissionsPath
      || path.join(process.cwd(), 'graph', 'data', 'permissions.json');

    this.permissions = { list: [], byBit: [] };
    this.reloadPermissions();
  }

  // ---------------- Permissions helpers ----------------
  reloadPermissions() {
    try {
      const raw = fs.readFileSync(this.permissionsPath, 'utf8');
      const arr = JSON.parse(raw);
      const byBit = [];
      for (const entry of arr) {
        if (typeof entry.bit !== 'number') continue;
        byBit[entry.bit] = entry;
      }
      this.permissions = { list: arr, byBit };
    } catch (err) {
      this.permissions = { list: [], byBit: [] };
    }
  }

  decodePermissions(permissionId) {
    const pid = Number(permissionId) || 0;
    const masked = pid & 0x3FFF; // 14 bit mask
    const active = [];

    for (let bit = 0; bit < 14; bit++) {
      if ((masked & (1 << bit)) === 0) continue;
      const meta = this.permissions.byBit[bit] || {};
      active.push({
        bit,
        mask: 1 << bit,
        name: meta.name || `BIT_${bit}`,
        label_tr: meta.label_tr || null,
        desc_tr: meta.desc_tr || null
      });
    }

    return {
      permissionId: masked,
      permissionHex: '0x' + masked.toString(16).toUpperCase(),
      permissionBin: masked.toString(2).padStart(14, '0'),
      allowedCount: active.length,
      active
    };
  }

  // ---------------- token helpers ----------------
  #hmac(data) {
    return crypto.createHmac('sha256', this.secret).update(data).digest();
  }

  createSecure(permissionId, actionId, ttlOverrideMs) {
    const ttl = ttlOverrideMs != null ? BigInt(ttlOverrideMs) : this.defaultTtlMs;
    if (ttl <= 0n) throw new Error('TTL must be positive');

    const expiry = BigInt(Date.now()) + ttl;
    const tsField = expiry - this.epoch;
    if (tsField < 0n) throw new Error('Expiry precedes epoch');

    const random = BigInt(crypto.randomInt(0, 8)) & 0x7n;
    const action = BigInt(actionId) & 0x3Fn;
    const permission = BigInt(permissionId) & 0x3FFFn;

    const snowflake = (tsField << 23n) | (random << 20n) | (action << 14n) | permission;
    const idBuf = Buffer.alloc(8);
    idBuf.writeBigUInt64BE(snowflake);

    const tagBuf = this.#hmac(idBuf).subarray(0, 8);
    const tag = BigInt('0x' + tagBuf.toString('hex'));
    const token = (snowflake << 64n) | tag;

    return {
      token: token.toString(10),
      expiresAt: Number(expiry),
      ttl: Number(ttl)
    };
  }

  verifySecure(tokenDec) {
    try {
      const token = BigInt(tokenDec);
      const snowflake = token >> 64n;
      const tag = token & ((1n << 64n) - 1n);

      const idBuf = Buffer.alloc(8);
      idBuf.writeBigUInt64BE(snowflake);
      const expectedTag = BigInt('0x' + this.#hmac(idBuf).subarray(0, 8).toString('hex'));
      if (expectedTag !== tag) {
        return { ok: false, error: 'HMAC mismatch' };
      }

      const tsField = snowflake >> 23n;
      const expiry = tsField + this.epoch;
      const now = BigInt(Date.now());
      const expired = now > expiry;

      const random = Number((snowflake >> 20n) & 0x7n);
      const actionId = Number((snowflake >> 14n) & 0x3Fn);
      const permissionId = Number(snowflake & 0x3FFFn);

      if (expired && !this.allowExpiredBypass) {
        return { ok: false, error: 'Expired', expiresAt: Number(expiry) };
      }

      return {
        ok: true,
        type: expired ? 'secure-expired' : 'secure',
        expired,
        bypass: expired && this.allowExpiredBypass,
        expiresAt: Number(expiry),
        permissionId,
        actionId,
        random
      };
    } catch (err) {
      return { ok: false, error: 'Invalid token format' };
    }
  }

  createPlain(permissionId, actionId) {
    const tsField = BigInt(Date.now()) - this.epoch;
    const random = BigInt(crypto.randomInt(0, 8)) & 0x7n;
    const action = BigInt(actionId) & 0x3Fn;
    const permission = BigInt(permissionId) & 0x3FFFn;

    const snowflake = (tsField << 23n) | (random << 20n) | (action << 14n) | permission;
    return snowflake.toString(10);
  }

  verifyPlain(tokenDec) {
    try {
      const snowflake = BigInt(tokenDec);
      const timestamp = (snowflake >> 23n) + this.epoch;
      const random = Number((snowflake >> 20n) & 0x7n);
      const actionId = Number((snowflake >> 14n) & 0x3Fn);
      const permissionId = Number(snowflake & 0x3FFFn);
      return {
        ok: true,
        type: 'plain',
        createdAt: Number(timestamp),
        permissionId,
        actionId,
        random
      };
    } catch (err) {
      return { ok: false, error: 'Invalid token format' };
    }
  }
}

module.exports = { SnowflakeAuth };
