'use strict';
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');
const { SCHEMAS, validateDoc } = require('./schemas');

class NoSQL {
  constructor(rootDir) {
    this.rootDir = rootDir || path.join(__dirname, '../../data');
    this.locks = new Map(); // collection -> Promise chain
  }

  async init() {
    await fsp.mkdir(this.rootDir, { recursive: true });
    for (const coll of Object.keys(SCHEMAS)) {
      await this.#ensureFile(coll);
    }
  }

  async #ensureFile(collection) {
    const file = path.join(this.rootDir, `${collection}.json`);
    try {
      await fsp.access(file, fs.constants.F_OK);
    } catch {
      await fsp.writeFile(file, '[]', 'utf8');
    }
  }

  #file(collection) {
    return path.join(this.rootDir, `${collection}.json`);
  }

  async #read(collection) {
    const data = await fsp.readFile(this.#file(collection), 'utf8');
    return JSON.parse(data);
  }

  async #write(collection, arr) {
    // atomic write: write temp then rename
    const file = this.#file(collection);
    const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
    await fsp.writeFile(tmp, JSON.stringify(arr, null, 2), 'utf8');
    await fsp.rename(tmp, file);
  }

  async #withLock(collection, fn) {
    const prev = this.locks.get(collection) || Promise.resolve();
    let resolve;
    const next = new Promise(r => (resolve = r));
    this.locks.set(collection, prev.then(() => next));
    try {
      const res = await fn();
      resolve();
      return res;
    } catch (e) {
      resolve();
      throw e;
    } finally {
      // clear chain tail occasionally
      if (this.locks.get(collection) === next) this.locks.delete(collection);
    }
  }

  // ----- public api -----

  async insert(collection, doc) {
    const schema = SCHEMAS[collection];
    if (!schema) throw new Error(`Unknown collection: ${collection}`);

    const toInsert = {
      id: crypto.randomUUID(),
      type: schema.type,
      schemaVersion: schema.version,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      ...doc
    };

    const err = validateDoc(schema, toInsert);
    if (err) throw new Error(`ValidationError: ${err}`);

    return this.#withLock(collection, async () => {
      const arr = await this.#read(collection);
      arr.push(toInsert);
      await this.#write(collection, arr);
      return toInsert;
    });
  }

  async find(collection, filter = {}, options = {}) {
    const arr = await this.#read(collection);
    let results = arr.filter(d => matchFilter(d, filter));
    if (options.sort && typeof options.sort === 'function') {
      results = results.sort(options.sort);
    }
    if (typeof options.limit === 'number') {
      results = results.slice(0, options.limit);
    }
    return results;
  }

  async findOne(collection, filter = {}) {
    const arr = await this.#read(collection);
    return arr.find(d => matchFilter(d, filter)) || null;
  }

  async update(collection, id, patch) {
    const schema = SCHEMAS[collection];
    if (!schema) throw new Error(`Unknown collection: ${collection}`);

    return this.#withLock(collection, async () => {
      const arr = await this.#read(collection);
      const i = arr.findIndex(d => d.id === id);
      if (i === -1) return null;

      const updated = {
        ...arr[i],
        ...patch,
        updatedAt: new Date().toISOString()
      };

      const err = validateDoc(schema, updated);
      if (err) throw new Error(`ValidationError: ${err}`);

      arr[i] = updated;
      await this.#write(collection, arr);
      return updated;
    });
  }

  async remove(collection, id) {
    return this.#withLock(collection, async () => {
      const arr = await this.#read(collection);
      const before = arr.length;
      const filtered = arr.filter(d => d.id !== id);
      if (filtered.length === before) return false;
      await this.#write(collection, filtered);
      return true;
    });
  }
}

/** simple filter matcher supporting equality, $in, $and, $or */
function matchFilter(doc, filter) {
  if (!filter || Object.keys(filter).length === 0) return true;

  if (Array.isArray(filter.$and)) {
    return filter.$and.every(f => matchFilter(doc, f));
  }
  if (Array.isArray(filter.$or)) {
    return filter.$or.some(f => matchFilter(doc, f));
  }

  for (const [k, v] of Object.entries(filter)) {
    if (k === '$and' || k === '$or') continue;
    const val = get(doc, k);
    if (isPlainObject(v)) {
      if ('$in' in v) {
        if (!Array.isArray(v.$in) || !v.$in.includes(val)) return false;
      } else {
        // unknown operator -> fail safe
        if (JSON.stringify(val) !== JSON.stringify(v)) return false;
      }
    } else {
      if (val !== v) return false;
    }
  }
  return true;
}

function get(obj, path) {
  return String(path).split('.').reduce((a, p) => (a ? a[p] : undefined), obj);
}
function isPlainObject(x) {
  return x && typeof x === 'object' && !Array.isArray(x);
}

module.exports = { NoSQL };
