'use strict';

// AST value -> JS
function astToJS(v) {
  switch (v.kind) {
    case 'StringValue': case 'IntValue': case 'FloatValue':
    case 'BooleanValue': return v.value;
    case 'NullValue': return null;
    case 'EnumValue': return v.value;
    case 'ListValue': return v.values.map(astToJS);
    case 'ObjectValue': {
      const o = {}; for (const f of v.fields) o[f.name] = astToJS(f.value); return o;
    }
  }
  return null;
}
function isObj(x) { return x && typeof x === 'object' && !Array.isArray(x); }

/**
 * permission check helpers
 * - fieldMeta: object possibly containing { auth, roles }
 * - args: parsed args object for the field
 * - ctx: contextValue passed into execute (expect ctx.req and ctx.user available)
 */
function checkPermissions(fieldMeta, args, ctx) {
  // no meta -> allow
  if (!fieldMeta) return;

  const req = ctx && ctx.req;
  const user = ctx && ctx.user;

  // auth required
  if (fieldMeta.auth) {
    if (!user) throw new Error('Authentication required');
  }

  // role check (roles: ['admin', 'moderator'])
  if (Array.isArray(fieldMeta.roles) && fieldMeta.roles.length) {
    if (!user) throw new Error('Authentication required for role check');
    const hasRole = fieldMeta.roles.includes(user.role) || (Array.isArray(user.roles) && user.roles.some(r => fieldMeta.roles.includes(r)));
    if (!hasRole) throw new Error('Forbidden: insufficient role');
  }
}

/**
 * execute({ schema, document, contextValue })
 * - schema: your existing schema object where fields may be either:
 *   - a function/object { resolve: fn, ...meta } or
 *   - a direct resolver function (old style)
 * - contextValue: make sure you set contextValue.user = req.user in your /graphql handler
 */
async function execute({ schema, document, contextValue = {} }) {
  const op = document.definitions[0];
  const root = op.operation === 'mutation' ? schema.Mutation : schema.Query;
  if (!root) return { data: null, errors: [{ message: `Missing root type` }] };

  const data = {};
  const errors = [];

  for (const sel of op.selectionSet.selections) {
    const key = sel.alias || sel.name;
    try {
      const fieldDef = root[sel.name];
      if (!fieldDef) throw new Error(`Unknown field "${sel.name}"`);

      // normalize: fieldDef can be a function (resolver) or an object { resolve, auth, roles }
      let resolver = null;
      let meta = null;
      if (typeof fieldDef === 'function') {
        resolver = fieldDef;
      } else if (typeof fieldDef === 'object') {
        // If fieldDef has a .resolve, use it; otherwise if it's a plain object but callable? handle.
        resolver = (typeof fieldDef.resolve === 'function') ? fieldDef.resolve : null;
        // extract meta keys (auth, roles)
        meta = {
          auth: fieldDef.auth || false,
          roles: Array.isArray(fieldDef.roles) ? fieldDef.roles : (fieldDef.roles ? [fieldDef.roles] : []),
        };
      } else {
        throw new Error(`Invalid field definition for "${sel.name}"`);
      }

      // collect arguments
      const args = {};
      for (const a of sel.arguments || []) args[a.name] = astToJS(a.value);

      // Permission check BEFORE resolver runs
      try {
        checkPermissions(meta, args, contextValue);
      } catch (permErr) {
        throw permErr;
      }

      // call resolver (some resolvers might not exist and return undefined)
      const result = await (resolver ? resolver(null, args, contextValue, { fieldName: sel.name, selectionSet: sel.selectionSet }) : undefined);

      if (sel.selectionSet) {
        if (Array.isArray(result)) {
          data[key] = [];
          for (const item of result) {
            data[key].push(await resolveSelectionSet(schema, item, sel.selectionSet, contextValue));
          }
        } else if (isObj(result) || result == null) {
          data[key] = result == null ? null : await resolveSelectionSet(schema, result, sel.selectionSet, contextValue);
        } else {
          throw new Error(`Subselection requires object/list result for "${sel.name}"`);
        }
      } else {
        data[key] = result;
      }
    } catch (e) {
      data[key] = null;
      errors.push({ message: e.message, path: [key] });
    }
  }

  return errors.length ? { data, errors } : { data };
}

async function resolveSelectionSet(schema, parent, selectionSet, ctx) {
  const out = {};
  for (const sel of selectionSet.selections) {
    const key = sel.alias || sel.name;

    // decide resolver: either type-specific resolver in schema.types or a default property access
    const resolver = parent.__type && schema.types?.[parent.__type]?.[sel.name]
      ? schema.types[parent.__type][sel.name].resolve
      : (obj => obj[sel.name]);

    // collect args
    const args = {};
    for (const a of sel.arguments || []) args[a.name] = (a.value ? (a.value.value ?? null) : null);

    // If the resolver is an object with meta, handle permission checks similarly
    let meta = null;
    let actualResolver = null;
    if (typeof resolver === 'function') actualResolver = resolver;
    else if (resolver && typeof resolver === 'object') {
      actualResolver = typeof resolver.resolve === 'function' ? resolver.resolve : null;
      meta = {
        auth: resolver.auth || false,
        roles: Array.isArray(resolver.roles) ? resolver.roles : (resolver.roles ? [resolver.roles] : []),
      };
    }

    // permission check for field-level type resolvers (optional)
    if (meta) {
      try {
        checkPermissions(meta, args, ctx);
      } catch (permErr) {
        out[key] = null;
        continue;
      }
    }

    const res = await (actualResolver ? actualResolver(parent, args, ctx, { fieldName: sel.name, selectionSet: sel.selectionSet }) : (parent ? parent[sel.name] : null));
    if (sel.selectionSet) {
      if (Array.isArray(res)) {
        const arr = [];
        for (const item of res) arr.push(await resolveSelectionSet(schema, item, sel.selectionSet, ctx));
        out[key] = arr;
      } else if (res && typeof res === 'object') {
        out[key] = await resolveSelectionSet(schema, res, sel.selectionSet, ctx);
      } else out[key] = res ?? null;
    } else out[key] = res;
  }
  return out;
}

module.exports = { execute };
