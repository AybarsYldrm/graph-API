'use strict';
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { execSync } = require('child_process');
const { createSign, createVerify, randomUUID } = require('crypto');

class PKISystem {
  constructor(baseDir) {
    this.BASE = baseDir || path.join(process.cwd(), 'pki');
    this.CA_DIR = path.join(this.BASE, 'ca');
    this.KEYS_DIR = path.join(this.BASE, 'keys');
    this.CSRS_DIR = path.join(this.BASE, 'csrs');
    this.CERTS_DIR = path.join(this.BASE, 'certs');

    this.ensureDirs();
    this.CA = this.ensureCA();
  }

  ensureDirs() {
    [this.BASE, this.CA_DIR, this.KEYS_DIR, this.CSRS_DIR, this.CERTS_DIR].forEach(d => {
      if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    });
  }

  sh(cmd, opts = {}) {
    try {
      return execSync(cmd, { stdio: 'pipe', encoding: 'utf8', ...opts });
    } catch (e) {
      console.error('Command failed:', cmd);
      throw e;
    }
  }

  sanitizeSubjectValue(v) {
    if (!v) return '';
    return String(v).replace(/\//g, ' ').replace(/\n/g, '').replace(/"/g, '');
  }

  ensureCA() {
    const caKey = path.join(this.CA_DIR, 'ca.key.pem');
    const caCert = path.join(this.CA_DIR, 'ca.crt.pem');
    if (fs.existsSync(caKey) && fs.existsSync(caCert)) return { caKey, caCert };

    console.log('Creating CA (self-signed P-256)...');
    this.sh(`openssl ecparam -name prime256v1 -genkey -noout -out "${caKey}"`);
    this.sh(`openssl req -x509 -new -nodes -key "${caKey}" -sha256 -days 3650 -subj "/CN=MyInternalRootCA" -out "${caCert}"`);
    return { caKey, caCert };
  }

  writeExtFileForUser(tmpPath, user) {
    const role = this.sanitizeSubjectValue(user.role || '');
    const uid = this.sanitizeSubjectValue(user.id || '');
    const email = this.sanitizeSubjectValue(user.email || '');
    const cfg = `
[ usr_cert ]
basicConstraints=CA:FALSE
keyUsage=digitalSignature, nonRepudiation
extendedKeyUsage=clientAuth, emailProtection
subjectAltName=email:${email}
1.2.3.4.5.6.7.1=ASN1:UTF8String:${role}
1.2.3.4.5.6.7.2=ASN1:UTF8String:${uid}
`;
    fs.writeFileSync(tmpPath, cfg, 'utf8');
  }

  createCertForUser(user) {
    const id = user.id;
    if (!id) throw new Error('User must have id field');

    const keyPath = path.join(this.KEYS_DIR, `${id}.key.pem`);
    const csrPath = path.join(this.CSRS_DIR, `${id}.csr.pem`);
    const certPath = path.join(this.CERTS_DIR, `${id}.crt.pem`);
    const extPath = path.join(this.CSRS_DIR, `${id}.ext.cnf`);

    if (fs.existsSync(keyPath) && fs.existsSync(certPath)) return { id, skipped: true };

    this.sh(`openssl ecparam -name prime256v1 -genkey -noout -out "${keyPath}"`);
    this.sh(`openssl ec -in "${keyPath}" -pubout -out "${keyPath}.pub"`);

    const cn = this.sanitizeSubjectValue(user.name || user.email || id);
    const email = this.sanitizeSubjectValue(user.email || '');
    const org = this.sanitizeSubjectValue(user.role || '');
    this.sh(`openssl req -new -key "${keyPath}" -subj "/CN=${cn}/O=${org}/emailAddress=${email}" -out "${csrPath}"`);
    this.writeExtFileForUser(extPath, user);
    this.sh(`openssl x509 -req -in "${csrPath}" -CA "${this.CA.caCert}" -CAkey "${this.CA.caKey}" -CAcreateserial -out "${certPath}" -days 365 -sha256 -extfile "${extPath}" -extensions usr_cert`);

    return { id, keyPath, certPath, skipped: false };
  }

  sign(userId, payload, options = {}) {
    const keyPath = path.join(this.KEYS_DIR, `${userId}.key.pem`);
    const certPath = path.join(this.CERTS_DIR, `${userId}.crt.pem`);
    const privPem = fs.readFileSync(keyPath, 'utf8');
    const certPem = fs.readFileSync(certPath, 'utf8');

    const ts = new Date().toISOString();
    const nonce = options.nonce || randomUUID();
    const signingString = `INTERNAL_OP_V1\n${ts}\n${nonce}\n${this.canonicalize(payload)}`;

    const signer = createSign('SHA256');
    signer.update(signingString);
    signer.end();
    const sig = options.passphrase ? signer.sign({ key: privPem, passphrase: options.passphrase }, 'base64') : signer.sign(privPem, 'base64');

    return { ts, nonce, payload, signingString, sig, certPem, sigAlg: 'ecdsa-with-SHA256' };
  }

  verify(envelope) {
    const payloadCanonical = this.canonicalize(envelope.payload);
    const signingString = `INTERNAL_OP_V1\n${envelope.ts}\n${envelope.nonce}\n${payloadCanonical}`;
    const verifier = createVerify('SHA256');
    verifier.update(signingString);
    verifier.end();
    const isValid = verifier.verify(envelope.certPem, envelope.sig, 'base64');

    return { isValid, signingString, subjectInfo: '(not parsed)' };
  }

  canonicalize(obj) {
    if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
    if (Array.isArray(obj)) return `[${obj.map(x => this.canonicalize(x)).join(',')}]`;
    const keys = Object.keys(obj).sort();
    return `{${keys.map(k => JSON.stringify(k)+':'+this.canonicalize(obj[k])).join(',')}}`;
  }
}

module.exports = { PKISystem };
