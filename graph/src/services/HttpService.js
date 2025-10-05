'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');
const { StringDecoder } = require('string_decoder');

class HttpService {
  constructor(authService = null, options = {}) {
    this.authService = authService;

    // routes + rate limiting
    this.routes = [];
    this.globalRateStore = new Map();
    this.maxRequestsPerMinute = options.maxRequestsPerMinute || 120;
    this.globalRateWindowMs = options.globalRateWindowMs || 60_000;
    this.customRateStores = new Map();

    // public / defaults
    this.publicPath = options.publicPath || path.join(process.cwd(), 'public');
    this.uploadDefaultLimit = options.uploadDefaultLimit || 5 * 1024 * 1024;
    this.uploadDefaultMaxKBps = options.uploadDefaultMaxKBps || null;
    this.allowedOrigins = options.allowedOrigins || ['*'];

    // basic mime map
    this.mimeMap = Object.assign({
      '.js':'application/javascript', '.css':'text/css',
      '.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg', '.gif':'image/gif',
      '.ico':'image/x-icon', '.svg':'image/svg+xml', '.webp':'image/webp',
      '.json':'application/json', '.xml':'application/xml', '.html':'text/html'
    }, options.extraMime || {});

    // security headers default
    this.securityHeaders = Object.assign({
      'X-Content-Type-Options':'nosniff',
      'X-Frame-Options':'DENY',
      'Strict-Transport-Security':'max-age=31536000; includeSubDomains'
    }, options.securityHeaders || {});
  }

  // HttpService class içine ekle
_buildCorsHeaders(req, extra = {}) {
  const headers = Object.assign({}, this.securityHeaders, extra);

  const originHeader = req && req.headers && req.headers.origin;
  // allowedOrigins: ['*'] veya ['https://fitfak.net', ...]
  if (this.allowedOrigins.includes('*')) {
    headers['Access-Control-Allow-Origin'] = originHeader || '*';
    // If wildcard and credentials true, browsers will reject if credentials included.
    // So when credentials will be used, prefer echoing originHeader.
  } else if (originHeader && this.allowedOrigins.includes(originHeader)) {
    headers['Access-Control-Allow-Origin'] = originHeader;
  } else {
    // fallback: don't set Allow-Origin (or set to a safe default)
    headers['Access-Control-Allow-Origin'] = this.allowedOrigins[0] || '';
  }

  headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS';
  headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-Csrf-Token';
  headers['Access-Control-Allow-Credentials'] = 'true';
  return headers;
}


  // ---------- internals ----------
  _getIp(req) {
    const xf = req.headers['x-forwarded-for'];
    return xf ? xf.split(',')[0].trim() : req.socket.remoteAddress;
  }

  _safeJoin(root, target) {
    const resolved = path.resolve(root, './' + target);
    if (!resolved.startsWith(root)) return null;
    return resolved;
  }

  _randomFilename(orig) {
    const ext = path.extname(orig) || '';
    return `${crypto.randomBytes(16).toString('hex')}${ext}`;
  }

  _sanitizeString(str) {
    if (typeof str !== 'string') return str;
    // remove <script> blocks, remove inline event handlers, escape tags
    let s = str.replace(/<\s*script[\s\S]*?>[\s\S]*?<\s*\/\s*script\s*>/gi, '');
    s = s.replace(/ on\w+\s*=\s*(?:"[^"]*"|'[^']*')/gi, '');
    s = s.replace(/</g,'&lt;').replace(/>/g,'&gt;');
    return s;
  }

  _sanitizeObject(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    if (Array.isArray(obj)) return obj.map(v => typeof v === 'string' ? this._sanitizeString(v) : this._sanitizeObject(v));
    const out = {};
    for (const k of Object.keys(obj)) {
      const v = obj[k];
      out[k] = typeof v === 'string' ? this._sanitizeString(v) : this._sanitizeObject(v);
    }
    return out;
  }

  // ---------- send helpers ----------
  // sendJson
sendJson(res, statusCode, payload, extraHeaders = {}, req = null) {
  if (res.headersSent) return;
  const safe = (payload && typeof payload === 'object') ? this._sanitizeObject(payload) : payload;

  // build headers (CORS + security)
  const cors = this._buildCorsHeaders(req, extraHeaders);
  const headers = Object.assign({
    'Content-Type':'application/json; charset=utf-8'
  }, cors);

  // preserve existing Set-Cookie (so cookie set earlier won't be lost)
  try {
    const existing = (res.getHeader && res.getHeader('Set-Cookie')) || null;
    if (existing) headers['Set-Cookie'] = existing;
  } catch (e) { /* ignore */ }

  res.writeHead(statusCode, headers);
  res.end(JSON.stringify(safe));
}

// sendGraph
sendGraph(res, statusCode, raw, extraHeaders = {}, req = null) {
  if (res.headersSent) return;
  const cors = this._buildCorsHeaders(req, extraHeaders);
  const headers = Object.assign({ 'Content-Type':'application/json; charset=utf-8' }, cors);

  try {
    const existing = (res.getHeader && res.getHeader('Set-Cookie')) || null;
    if (existing) headers['Set-Cookie'] = existing;
  } catch (e) {}

  res.writeHead(statusCode, headers);
  res.end(JSON.stringify(raw));
}

// sendHtml
sendHtml(res, statusCode, html, nonce = null, extraHeaders = {}, req = null) {
  if (res.headersSent) return;
  let csp = `default-src 'self'; base-uri 'self'; frame-ancestors 'none'`;
  if (nonce) {
    csp += `; script-src 'nonce-${nonce}' 'strict-dynamic'`;
    csp += `; style-src 'nonce-${nonce}'`;
    csp += `; object-src 'none'`;
    csp += `; img-src 'self' data:`;
  } else {
    csp += `; object-src 'none'; img-src 'self' data:`;
  }

  const cors = this._buildCorsHeaders(req, extraHeaders);
  const headers = Object.assign({
    'Content-Type':'text/html; charset=utf-8',
    'Content-Security-Policy': csp
  }, cors);

  try {
    const existing = (res.getHeader && res.getHeader('Set-Cookie')) || null;
    if (existing) headers['Set-Cookie'] = existing;
  } catch (e) {}

  res.writeHead(statusCode, headers);
  res.end(html);
}

  redirectHtml(res, location, status = 302) {
    if (res.headersSent) return;
    const headers = Object.assign({ 'Location': location, 'Content-Type':'text/html; charset=utf-8' }, this.securityHeaders);
    res.writeHead(status, headers);
    res.end(`<html><body>Redirecting to <a href="${location}">${location}</a></body></html>`);
  }

  // ---------- routing ----------
  addRoute(method, pathPattern, handler, options = {}) {
    const route = { method: method.toUpperCase(), path: pathPattern, handler, options };
    this.routes.push(route);
    if (options.rateLimit) {
      const key = `${route.method}:${route.path}`;
      if (!this.customRateStores.has(key)) this.customRateStores.set(key, new Map());
    }
  }

  findRoute(method, pathname) {
    method = method.toUpperCase();
    for (const r of this.routes) {
      if (r.method !== method) continue;
      if (r.path === pathname) return r;
      if (r.path.includes('/:') && this._matchDynamicRoute(r.path, pathname)) return r;
    }
    return null;
  }

  _matchDynamicRoute(routePath, actualPath) {
    const rp = routePath.split('/');
    const ap = actualPath.split('/');
    if (rp.length !== ap.length) return false;
    for (let i=0;i<rp.length;i++){
      if (rp[i].startsWith(':')) continue;
      if (rp[i] !== ap[i]) return false;
    }
    return true;
  }

  extractParams(routePath, actualPath) {
    const params = {};
    const rp = routePath.split('/');
    const ap = actualPath.split('/');
    if (rp.length !== ap.length) return params;
    for (let i=0;i<rp.length;i++) {
      if (rp[i].startsWith(':')) params[rp[i].slice(1)] = decodeURIComponent(ap[i]);
    }
    return params;
  }

  // ---------- rate checks ----------
  _globalRateCheck(ip) {
    const now = Date.now();
    const entry = this.globalRateStore.get(ip) || { count: 0, ts: now };
    if (now - entry.ts > this.globalRateWindowMs) {
      this.globalRateStore.set(ip, { count: 1, ts: now });
      return false;
    }
    if (entry.count >= this.maxRequestsPerMinute) return true;
    entry.count++;
    this.globalRateStore.set(ip, entry);
    return false;
  }

  _customRateCheck(route, ip) {
    const cfg = route.options && route.options.rateLimit;
    if (!cfg) return false;
    const key = `${route.method}:${route.path}`;
    if (!this.customRateStores.has(key)) this.customRateStores.set(key, new Map());
    const store = this.customRateStores.get(key);
    const now = Date.now();
    const entry = store.get(ip) || { count: 0, ts: now };
    const windowMs = cfg.windowMs || 60_000;
    if (now - entry.ts > windowMs) { store.set(ip, { count: 1, ts: now }); return false; }
    if (entry.count >= (cfg.max || 10)) return true;
    entry.count++;
    store.set(ip, entry);
    return false;
  }

  // ---------- multipart streaming parser ----------
  _handleMultipartStream(req, res, routeOptions, cb) {
    const contentType = req.headers['content-type'] || '';
    const m = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
    if (!m) { res.writeHead(400); res.end('Missing boundary'); return; }
    const boundary = Buffer.from(`--${(m[1]||m[2]).trim()}`);

    const decoder = new StringDecoder('utf8');
    let buffer = Buffer.alloc(0);
    const fields = {};
    const files = [];
    let finished = false;

    const maxBytes = routeOptions?.upload?.maxBytes || this.uploadDefaultLimit;
    const maxKBps = routeOptions?.upload?.maxKBps || this.uploadDefaultMaxKBps || null;
    const accept = routeOptions?.upload?.accept || [];

    let folder = this.publicPath;
    if (routeOptions?.upload?.folder) folder = path.join(this.publicPath, routeOptions.upload.folder);
    if (!fs.existsSync(folder)) fs.mkdirSync(folder, { recursive: true });

    let totalBytes = 0, lastTick = Date.now(), bytesSinceLast = 0;
    let state = { headers:null, name:null, origFilename:null, filename:null, contentType:null, stream:null, tempPath:null };

    const pushCurrentFile = () => {
      if (state.filename) {
        files.push({
          fieldname: state.name,
          filename: state.filename,
          originalName: state.origFilename || null,
          path: state.tempPath,
          contentType: state.contentType || null
        });
      }
    };

    const endCurrentPart = () => {
      if (state.stream) {
        state.stream.end();
        pushCurrentFile();
      }
      state = { headers:null, name:null, origFilename:null, filename:null, contentType:null, stream:null, tempPath:null };
    };

    const triggerCallback = () => {
      if (finished) return;
      finished = true;
      try { cb({ fields, files }); } catch(e) { console.error(e); }
    };

    req.on('data', chunk => {
      if (finished) return;
      totalBytes += chunk.length;
      bytesSinceLast += chunk.length;
      if (totalBytes > maxBytes) { this.sendJson(res, 413, { success: false, message: "Payload too large" }); req.destroy(); return; }

      const now = Date.now();
      if (now - lastTick >= 1000) {
        const kbps = (bytesSinceLast / 1024) / ((now - lastTick)/1000);
        if (maxKBps && kbps > maxKBps) { this.sendJson(res, 429, { success: false, message: "Upload rate limit exceeded" }); req.destroy(); return; }
        lastTick = now; bytesSinceLast = 0;
      }

      buffer = Buffer.concat([buffer, chunk]);

      while (true) {
        const idx = buffer.indexOf(boundary);
        if (idx === -1) break;

        const before = buffer.slice(0, idx);
        if (before.length && state.stream) {
          let toWrite = before;
          if (toWrite.length >= 2 && toWrite.slice(-2).toString()==='\r\n') toWrite = toWrite.slice(0,-2);
          state.stream.write(toWrite);
        }

        buffer = buffer.slice(idx + boundary.length);
        if (buffer.slice(0,2).toString() === '--') { endCurrentPart(); triggerCallback(); return; }
        if (buffer.slice(0,2).toString() === '\r\n') buffer = buffer.slice(2);

        const headerEndIdx = buffer.indexOf('\r\n\r\n');
        if (headerEndIdx === -1) break;

        const headerPart = buffer.slice(0, headerEndIdx).toString('utf8');
        buffer = buffer.slice(headerEndIdx + 4);

        const headerLines = headerPart.split('\r\n').map(l=>l.trim()).filter(Boolean);
        const parsedHeaders = {};
        headerLines.forEach(l=>{ const i=l.indexOf(':'); if(i===-1) return; parsedHeaders[l.slice(0,i).toLowerCase()]=l.slice(i+1).trim(); });
        state.headers = parsedHeaders;

        const cd = parsedHeaders['content-disposition'] || '';
        state.name = cd.match(/name="([^"]+)"/i)?.[1] || null;
        const orig = cd.match(/filename="([^"]+)"/i)?.[1] || null;
        state.origFilename = orig ? path.basename(orig) : null;
        state.contentType = parsedHeaders['content-type'] || null;

        if (state.origFilename) {
          if (accept.length && !accept.includes(state.contentType)) { this.sendJson(res,415,{success:false,message:'Unsupported Media Type'}); req.destroy(); return; }

          let finalName = state.origFilename;
          if (routeOptions?.upload?.naming && typeof routeOptions.upload.naming === 'function') {
            try { finalName = routeOptions.upload.naming(state.origFilename, req); } catch(e) { finalName = this._randomFilename(state.origFilename); }
          } else {
            finalName = this._randomFilename(state.origFilename);
          }

          const tempPath = path.join(folder, finalName);

          if (fs.existsSync(tempPath)) {
            this.sendJson(res, 409, {
              success: false,
              message: 'File with the same name already exists',
              filename: finalName
            });
            req.destroy();
            return;
          }

          state.tempPath = tempPath;
          state.filename = finalName;
          state.stream = fs.createWriteStream(tempPath);
        }
      }
    });

    req.on('end', () => {
      if (finished) return;
      // finalize: if still open, close and push
      if (state.stream) {
        try { state.stream.end(); } catch(e) {}
        pushCurrentFile();
      }
      triggerCallback();
    });

    req.on('error', e => {
      console.error('upload stream error', e);
      try { res.writeHead(500); res.end('Upload error'); } catch(e) {}
    });
  }

  // wrapper: choose multipart parser or raw buffered upload
  _handleUpload(req, res, routeOptions, cb) {
    const contentType = req.headers['content-type'] || '';
    if (contentType.includes('multipart/form-data')) return this._handleMultipartStream(req, res, routeOptions, cb);

    // raw body upload (small)
    const maxBytes = (routeOptions && routeOptions.upload && routeOptions.upload.maxBytes) || this.uploadDefaultLimit;
    const maxKBps = (routeOptions && routeOptions.upload && routeOptions.upload.maxKBps) || this.uploadDefaultMaxKBps || null;
    let total = 0; let lastTick = Date.now(); let bytesSince = 0;
    const chunks = [];
    req.on('data', chunk => {
      total += chunk.length; bytesSince += chunk.length; chunks.push(chunk);
      if (total > maxBytes) { res.writeHead(413); res.end('Payload too large'); req.destroy(); return; }
      const now = Date.now();
      if (now - lastTick >= 1000) {
        const kbps = (bytesSince / 1024) / ((now - lastTick)/1000);
        if (maxKBps && kbps > maxKBps) { res.writeHead(429); res.end('Upload rate limit exceeded'); req.destroy(); return; }
        lastTick = now; bytesSince = 0;
      }
    });
    req.on('end', () => cb({ buffer: Buffer.concat(chunks), contentType }));
    req.on('error', e => { console.error('upload error', e); try { res.writeHead(500); res.end('Upload error'); } catch(e) {} });
  }

  // ---------- asset serving ----------
  _serveAsset(req, res, relPath) {
    const fp = this._safeJoin(this.publicPath, relPath);
    if (!fp) return this.sendJson(res, 403, { success:false, message:'Forbidden' });
    if (!fs.existsSync(fp)) return this.sendJson(res, 404, { success:false, message:'Not Found' });
    const mime = this.mimeMap[path.extname(fp).toLowerCase()] || 'application/octet-stream';
    const headers = Object.assign({ 'Content-Type': mime, 'Cache-Control':'public, max-age=604800, immutable' }, this.securityHeaders);
    res.writeHead(200, headers);
    const stream = fs.createReadStream(fp);
    stream.pipe(res);
    stream.on('error', e => { console.error('asset stream error', e); try { res.end(); } catch(e){} });
  }

  // ---------- body collector ----------
  _collectBody(req, res, maxLen=10_000_000) {
    return new Promise((resolve, reject) => {
      const decoder = new StringDecoder('utf8');
      let raw = '';
      req.on('data', chunk => { raw += decoder.write(chunk); if (raw.length > maxLen) { req.destroy(); reject({ code:413, message:'Payload too large' }); } });
      req.on('end', () => {
        raw += decoder.end();
        resolve({ raw });
      });
      req.on('error', e => reject({ code:400, message:'Request stream error', details:e?.message }));
    });
  }

  _getCookie(req, name) {
    const cookie = req.headers.cookie || '';
    const parts = cookie.split(';').map(c => c.trim()).filter(Boolean);
    for (const p of parts) {
      const idx = p.indexOf('=');
      if (idx === -1) continue;
      const k = p.slice(0, idx); const v = p.slice(idx+1);
      if (k === name) return decodeURIComponent(v);
    }
    return null;
  }

  // ---------- helpers for index.html CSP / hoist ----------
  /**
   * convert inline style attributes into class names and build a style block (returns new html)
   * - scans for style="..." on elements and replaces with class="is-<hash>"
   * - collects `.is-<hash> { ... }` rules and injects <style nonce="..."> into <head>
   *
   * NOTE: this is a heuristic helper. It strips inline event handlers (onclick=...) for safety.
   */
  _hoistInlineStylesAndStripEvents(html, nonce) {
    const styleMap = Object.create(null);

    html = html.replace(/(<[a-zA-Z0-9\-]+)([^>]*?)\sstyle\s*=\s*(['"])(.*?)\3([^>]*?)(\/?)>/gi,
      (match, startTag, beforeAttrs, q, styleStr, afterAttrs, endSlash) => {

        const styleNormalized = styleStr.trim();
        if (!styleNormalized) return match;

        const hash = crypto.createHash('sha1').update(styleNormalized).digest('hex').slice(0,8);
        const cls = `is-${hash}`;
        styleMap[cls] = styleNormalized;

        // remove any inline event handlers in the remaining attrs
        let combined = (beforeAttrs + ' ' + afterAttrs).trim();
        combined = combined.replace(/\s*on\w+\s*=\s*(['"])[\s\S]*?\1/gi, '');

        const classMatch = combined.match(/class\s*=\s*(['"])(.*?)\1/i);
        let newAttrs;
        if (classMatch) {
          const existing = classMatch[2];
          newAttrs = combined.replace(classMatch[0], `class="${existing} ${cls}"`);
        } else {
          newAttrs = `${combined} class="${cls}"`.trim();
        }

        return `${startTag} ${newAttrs}${endSlash}>`;
      });

    const keys = Object.keys(styleMap);
    if (keys.length) {
      let styleBlock = `<style nonce="${nonce}">\n`;
      for (const k of keys) styleBlock += `.${k} { ${styleMap[k]} }\n`;
      styleBlock += `</style>\n`;

      if (/<head[^>]*>/i.test(html)) {
        html = html.replace(/<head([^>]*)>/i, `<head$1>\n${styleBlock}`);
      } else {
        html = styleBlock + html;
      }
    }
    return html;
  }

  _addNonceToScriptAndStyleTags(html, nonce) {
    html = html.replace(/<script\b([^>]*)>/gi, (match, attrs) => {
      if (/nonce\s*=\s*['"]?[\w+/=.-]+['"]?/i.test(attrs)) return `<script${attrs}>`;
      return `<script nonce="${nonce}"${attrs}>`;
    });
    html = html.replace(/<style\b([^>]*)>/gi, (match, attrs) => {
      if (/nonce\s*=\s*['"]?[\w+/=.-]+['"]?/i.test(attrs)) return `<style${attrs}>`;
      return `<style nonce="${nonce}"${attrs}>`;
    });
    return html;
  }

  async _authenticateRequest(req, res, route) {
    // 1) Authorization header → Bearer
    let token = null;
    const authHeader = req.headers['authorization'] || '';
    if (authHeader.startsWith('Bearer ')) {
      token = authHeader.slice(7);
    }

    // 2) Cookie fallback
    if (!token) {
      token = this._getCookie(req, 'auth_token');
    }

    if (!token) {
      if (route.options.redirect && (req.headers.accept || '').includes('text/html')) {
        this.redirectHtml(res, route.options.redirect);
        return null;
      }
      this.sendJson(res, 401, { success: false, message: 'Unauthorized' });
      return null;
    }

    if (!this.authService) {
      this.sendJson(res, 500, { success: false, message: 'AuthService missing' });
      return null;
    }

    const verified = await this.authService.verifyJWT(token);
    if (!verified) {
      if (route.options.redirect && (req.headers.accept || '').includes('text/html')) {
        this.redirectHtml(res, route.options.redirect);
        return null;
      }
      this.sendJson(res, 401, { success: false, message: 'Invalid token' });
      return null;
    }

    const user = verified.user || verified.payload || verified;

    // role check
    if (route.options.roles) {
      const allowed = Array.isArray(route.options.roles) ? route.options.roles : [route.options.roles];
      const has = (user && (allowed.includes(user.role) || (user.roles && user.roles.some(r => allowed.includes(r)))));
      if (!has) {
        this.sendJson(res, 403, { success: false, message: 'Forbidden' });
        return null;
      }
    }

    return user;
  }


  // ---------- main request handler ----------
  async handleRequest(req, res) {
    try {
      if (req.method === 'OPTIONS') {
        const headers = this._buildCorsHeaders(req);
        // for preflight, typically 204 no-content
        res.writeHead(204, headers);
        return res.end();
      }

      const ip = this._getIp(req);
      if (this._globalRateCheck(ip)) return this.sendJson(res, 429, { success:false, message:'Too many requests' });

      const parsed = url.parse(req.url || '', true);
      const pathname = decodeURIComponent(parsed.pathname || '/');

      // static assets
      if (pathname.startsWith('/assets/')) {
        const rel = pathname.replace(/^\/assets\//,'');
        return this._serveAsset(req, res, rel);
      }

      const route = this.findRoute(req.method, pathname);
      if (!route) {
        // fallback index.html
        if (req.method === 'GET') {
          const indexFile = this._safeJoin(this.publicPath, 'index.html');
          if (indexFile && fs.existsSync(indexFile)) {
            let html = fs.readFileSync(indexFile, 'utf8');
            const nonce = crypto.randomBytes(16).toString('base64');

            // 1) move inline style attrs into a nonce'd <style>
            html = this._hoistInlineStylesAndStripEvents(html, nonce);

            // 2) add nonce to existing <script> and <style> tags
            html = this._addNonceToScriptAndStyleTags(html, nonce);

            // 3) send html with CSP referencing nonce
            return this.sendHtml(res, 200, html, nonce);
          }
        }
        return this.sendJson(res, 404, { success:false, message:'Not found' });
      }

      if (this._customRateCheck(route, ip)) return this.sendJson(res, 429, { success:false, message:'Too many requests for this endpoint' });

      // -------- auth (route-level) --------
      let user = null;
      if (route.options && route.options.auth) {
        const authHeader = req.headers['authorization'] || '';
        const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : (this._getCookie(req, 'auth_token') || authHeader || '');
        if (!token) {
          if (route.options.redirect && (req.headers.accept || '').includes('text/html')) return this.redirectHtml(res, route.options.redirect);
          return this.sendJson(res, 401, { success:false, message:'Unauthorized' });
        }
        if (!this.authService) return this.sendJson(res, 500, { success:false, message:'AuthService missing' });
        const verified = await this.authService.verifyJWT(token);
        if (!verified) {
          if (route.options.redirect && (req.headers.accept || '').includes('text/html')) return this.redirectHtml(res, route.options.redirect);
          return this.sendJson(res, 401, { success:false, message:'Invalid token' });
        }
        user = verified.user || verified.payload || verified;
        // role check
        if (route.options.roles) {
          const allowed = Array.isArray(route.options.roles) ? route.options.roles : [route.options.roles];
          const has = (user && (allowed.includes(user.role) || (user.roles && user.roles.some(r=>allowed.includes(r)))));
          if (!has) return this.sendJson(res, 403, { success:false, message:'Forbidden' });
        }
      }

      if (route.path.includes('/:')) req.params = this.extractParams(route.path, pathname);
      req.user = user;

      // small helper send() for handlers
      const send = (status, payload, headers) => {
        if (route.options && route.options.graph) return this.sendGraph(res, status, payload, headers);
        return this.sendJson(res, status, payload, headers);
      };

      // ---------- upload handling ----------
      if (route.options && (route.options.multipart || (req.headers['content-type']||'').includes('multipart/form-data') || route.options.upload)) {
        return this._handleUpload(req, res, route.options, async (uploadResult) => {
          req.body = uploadResult;
          // validate files if accept list provided
          if (uploadResult.files && uploadResult.files.length) {
            for (const f of uploadResult.files) {
              const ext = path.extname(f.filename).toLowerCase();
              const detected = f.contentType || this.mimeMap[ext] || 'application/octet-stream';
              if (route.options.upload && route.options.upload.accept && route.options.upload.accept.length) {
                if (!route.options.upload.accept.includes(detected)) {
                  try { fs.unlinkSync(f.path); } catch(e) {}
                  return this.sendJson(res, 415, { success:false, message:'Unsupported Media Type' });
                }
              }
            }
          }

          // allow handler to use send helper or return value
          let handled = false;
          const wrappedSend = (status, payload, headers) => { handled = true; return send(status, payload, headers); };

          const maybe = route.handler.length >= 3 ? await route.handler(req, res, wrappedSend) : await route.handler(req, res, wrappedSend);
          if (handled) return;
          if (maybe === true || (maybe && maybe.redirect === true)) {
            const loc = (maybe && maybe.location) || (route.options && route.options.redirect) || '/';
            if ((req.headers.accept || '').includes('text/html')) return this.redirectHtml(res, loc);
            return this.sendJson(res, 204, { success:true, redirect: loc });
          }
          if (route.options && route.options.graph) return this.sendGraph(res, 200, maybe);
          return this.sendJson(res, 200, maybe);
        });
      }

      // ---------- normal (non-upload) body handling ----------
      const collected = await this._collectBody(req, res, 10_000_000);
      req.rawBody = collected.raw || '';

      if (route.options && route.options.graph) {
        // GraphQL-special parsing: attempt to parse JSON; fallback to treating raw as { query: raw }
        const contentType = String(req.headers['content-type'] || '').toLowerCase();
        if (contentType.includes('application/graphql') || contentType === 'graphql') {
          // some clients send raw GraphQL string; try to parse JSON first (legacy compat)
          try { req.body = collected.raw ? JSON.parse(collected.raw) : {}; } catch { req.body = { query: collected.raw }; }
        } else if (contentType.includes('application/json')) {
          try { req.body = collected.raw ? JSON.parse(collected.raw) : {}; } catch {
            return this.sendJson(res, 400, { error: 'Invalid JSON' });
          }
        } else {
          // best-effort
          try { req.body = collected.raw ? JSON.parse(collected.raw) : {}; } catch {
            req.body = { query: collected.raw };
          }
        }
      } else {
        try {
          req.body = collected.raw ? JSON.parse(collected.raw) : {};
        } catch {
          try { req.body = Object.fromEntries(new URLSearchParams(collected.raw)); } catch { req.body = collected.raw || {}; }
        }
        if (req.body && typeof req.body === 'object') req.body = this._sanitizeObject(req.body);
      }

      // ---------- call handler ----------
      let handled = false;
      const wrappedSend = (status, payload, headers) => { handled = true; return send(status, payload, headers); };

      const maybe = route.handler.length >= 3 ? await route.handler(req, res, wrappedSend) : await route.handler(req, res, wrappedSend);
      if (handled) return;

      if (maybe === true || (maybe && maybe.redirect === true)) {
        const loc = (maybe && maybe.location) || (route.options && route.options.redirect) || '/';
        if ((req.headers.accept || '').includes('text/html')) return this.redirectHtml(res, loc);
        return this.sendJson(res, 204, { success:true, redirect: loc });
      }

      if (route.options && route.options.graph) return this.sendGraph(res, 200, maybe);
      return this.sendJson(res, 200, maybe);

    } catch (err) {
      console.error('Request handling error', err);
      if (!res.headersSent) res.writeHead(500, this.securityHeaders);
      try { res.end('Internal Server Error'); } catch(e) {}
    }
  }

  listen(port = 3000, cb) {
    const srv = http.createServer((req, res) => this.handleRequest(req, res));
    srv.listen(port, cb || (() => console.log(`HttpService listening on ${port}`)));
    return srv;
  }
}

module.exports = HttpService;
