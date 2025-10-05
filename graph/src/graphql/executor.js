'use strict';

function astToJS(v, variables = {}) {
  switch (v?.kind) {
    case 'StringValue':
    case 'IntValue':
    case 'FloatValue':
    case 'BooleanValue':
      return v.value;
    case 'NullValue':
      return null;
    case 'EnumValue':
      return v.value;
    case 'Variable': {
      const name = typeof v.name === 'string' ? v.name : v.name?.value;
      return variables && Object.prototype.hasOwnProperty.call(variables, name)
        ? variables[name]
        : undefined;
    }
    case 'ListValue':
      return Array.isArray(v.values) ? v.values.map(item => astToJS(item, variables)) : [];
    case 'ObjectValue': {
      const o = {};
      for (const f of v.fields || []) o[f.name] = astToJS(f.value, variables);
      return o;
    }
  }
  return null;
}

function isObj(x) {
  return x && typeof x === 'object' && !Array.isArray(x);
}

function unwrapTypeName(type) {
  if (!type || typeof type !== 'string') return null;
  return type.replace(/[[\]!]/g, '').trim() || null;
}

function getRuntimeType(value, fallback) {
  if (value && typeof value === 'object') {
    if (typeof value.__typename === 'string') return value.__typename;
    if (typeof value.__type === 'string') return value.__type;
  }
  return fallback || null;
}

function shouldIncludeNode(node, variables) {
  if (!node || !Array.isArray(node.directives) || !node.directives.length) return true;
  for (const dir of node.directives) {
    if (!dir || dir.kind !== 'Directive') continue;
    const name = dir.name;
    if (name !== 'skip' && name !== 'include') continue;
    const ifArg = (dir.arguments || []).find(arg => arg.name === 'if');
    const value = astToJS(ifArg?.value, variables);
    if (name === 'skip' && value === true) return false;
    if (name === 'include' && value === false) return false;
  }
  return true;
}

function matchesTypeCondition(condition, typeName, value) {
  if (!condition) return true;
  const runtime = getRuntimeType(value, typeName);
  if (!runtime) return false;
  return runtime === condition;
}

function checkPermissions(fieldMeta, args, ctx) {
  if (!fieldMeta) return;
  const user = ctx && ctx.user;
  if (fieldMeta.auth && !user) {
    throw new Error('Authentication required');
  }
  if (Array.isArray(fieldMeta.roles) && fieldMeta.roles.length) {
    if (!user) throw new Error('Authentication required for role check');
    const hasRole = fieldMeta.roles.includes(user.role)
      || (Array.isArray(user.roles) && user.roles.some(r => fieldMeta.roles.includes(r)));
    if (!hasRole) throw new Error('Forbidden: insufficient role');
  }
}

function collectFields(selectionSet, typeName, sourceValue, fragments, variables, visited, out) {
  for (const selection of selectionSet.selections || []) {
    if (!shouldIncludeNode(selection, variables)) continue;
    if (selection.kind === 'Field') {
      out.push(selection);
      continue;
    }
    if (selection.kind === 'InlineFragment') {
      if (!matchesTypeCondition(selection.typeCondition, typeName, sourceValue)) continue;
      collectFields(selection.selectionSet, selection.typeCondition || typeName, sourceValue, fragments, variables, visited, out)
;
      continue;
    }
    if (selection.kind === 'FragmentSpread') {
      const name = typeof selection.name === 'string' ? selection.name : selection.name?.value;
      if (!name) continue;
      if (visited.has(name)) continue;
      visited.add(name);
      const fragment = fragments[name];
      if (!fragment) throw new Error(`Unknown fragment "${name}"`);
      if (!shouldIncludeNode(fragment, variables)) continue;
      if (!matchesTypeCondition(fragment.typeCondition, typeName, sourceValue)) continue;
      collectFields(fragment.selectionSet, fragment.typeCondition || typeName, sourceValue, fragments, variables, visited, out);
    }
  }
}

async function execute({
  schema,
  document,
  contextValue = {},
  variableValues = {},
  operationName = null,
  rootValue = null
}) {
  if (!document || !Array.isArray(document.definitions)) {
    throw new Error('Invalid GraphQL document');
  }

  const fragments = Object.create(null);
  const operations = [];
  for (const def of document.definitions) {
    if (def.kind === 'FragmentDefinition') {
      fragments[def.name] = def;
    } else if (def.kind === 'OperationDefinition') {
      operations.push(def);
    }
  }

  let operation = null;
  if (operationName) {
    operation = operations.find(op => op.name === operationName || op.name?.value === operationName) || null;
    if (!operation) {
      return { data: null, errors: [{ message: `Unknown operation "${operationName}"` }] };
    }
  } else if (operations.length === 1) {
    operation = operations[0];
  } else if (operations.length === 0) {
    return { data: null, errors: [{ message: 'No operation found in document' }] };
  } else {
    return { data: null, errors: [{ message: 'Must provide operationName when document contains multiple operations.' }] };
  }

  const rootTypeName = operation.operation === 'mutation'
    ? 'Mutation'
    : operation.operation === 'subscription'
      ? 'Subscription'
      : 'Query';
  const rootType = schema && schema[rootTypeName];
  if (!rootType) {
    return { data: null, errors: [{ message: `Missing root type "${rootTypeName}"` }] };
  }

  const providedVars = Object.assign({}, variableValues || {});
  const prepErrors = [];
  for (const def of operation.variableDefinitions || []) {
    const varName = typeof def.variable?.name === 'string' ? def.variable.name : def.variable?.name?.value;
    if (!Object.prototype.hasOwnProperty.call(providedVars, varName)) {
      if (def.defaultValue !== undefined) {
        providedVars[varName] = astToJS(def.defaultValue, providedVars);
      } else if (def.type && def.type.nonNull) {
        prepErrors.push({ message: `Variable "${varName}" of required type is missing.` });
      } else {
        providedVars[varName] = undefined;
      }
    }
  }
  if (prepErrors.length) {
    return { data: null, errors: prepErrors };
  }

  const execCtx = Object.assign({}, contextValue, {
    variables: providedVars,
    operation,
    operationName: operation.name || operationName || null
  });

  const errors = [];
  let data = Object.create(null);
  try {
    data = await executeSelectionSet({
      schema,
      selectionSet: operation.selectionSet,
      typeName: rootTypeName,
      typeDefs: rootType,
      source: rootValue,
      ctx: execCtx,
      variables: providedVars,
      fragments,
      errors
    });
  } catch (e) {
    errors.push({ message: e.message });
  }

  return errors.length ? { data, errors } : { data };
}

async function executeSelectionSet({
  schema,
  selectionSet,
  typeName,
  typeDefs,
  source,
  ctx,
  variables,
  fragments,
  errors
}) {
  const result = {};
  const visited = new Set();
  const collected = [];
  collectFields(selectionSet, typeName, source, fragments, variables, visited, collected);

  for (const fieldNode of collected) {
    const responseKey = fieldNode.alias || fieldNode.name;
    if (Object.prototype.hasOwnProperty.call(result, responseKey)) continue;
    try {
      result[responseKey] = await resolveField({
        schema,
        fieldNode,
        typeName,
        typeDefs,
        source,
        ctx,
        variables,
        fragments,
        errors
      });
    } catch (e) {
      result[responseKey] = null;
      errors.push({ message: e.message, path: [responseKey] });
    }
  }

  return result;
}

async function resolveField({ schema, fieldNode, typeName, typeDefs, source, ctx, variables, fragments, errors }) {
  const fieldName = fieldNode.name;
  const fieldDef = typeDefs ? typeDefs[fieldName] : undefined;
  let resolver = null;
  let meta = null;
  let typeHint = null;

  if (typeof fieldDef === 'function') {
    resolver = fieldDef;
  } else if (fieldDef && typeof fieldDef === 'object') {
    resolver = typeof fieldDef.resolve === 'function' ? fieldDef.resolve : null;
    meta = {
      auth: !!fieldDef.auth,
      roles: Array.isArray(fieldDef.roles)
        ? fieldDef.roles
        : (fieldDef.roles ? [fieldDef.roles] : [])
    };
    if (fieldDef.type) typeHint = fieldDef.type;
  } else if (fieldDef !== undefined) {
    throw new Error(`Invalid field definition for "${fieldName}" on type "${typeName}"`);
  }

  if (!fieldDef && (typeName === 'Query' || typeName === 'Mutation' || typeName === 'Subscription')) {
    throw new Error(`Unknown field "${fieldName}" on root type "${typeName}"`);
  }

  const args = {};
  for (const arg of fieldNode.arguments || []) {
    args[arg.name] = astToJS(arg.value, variables);
  }

  if (meta) {
    checkPermissions(meta, args, ctx);
  }

  const info = {
    fieldName,
    parentType: typeName,
    selectionSet: fieldNode.selectionSet,
    returnType: typeHint
  };

  let resolved;
  if (resolver) {
    resolved = await resolver(source, args, ctx, info);
  } else if (isObj(source) && Object.prototype.hasOwnProperty.call(source, fieldName)) {
    resolved = source[fieldName];
  } else if (source != null && typeof source === 'object') {
    resolved = source[fieldName];
  } else {
    resolved = undefined;
  }

  return completeValue({
    schema,
    fieldNode,
    value: resolved,
    ctx,
    variables,
    fragments,
    errors,
    typeHint
  });
}

async function completeValue({ schema, fieldNode, value, ctx, variables, fragments, errors, typeHint }) {
  if (!fieldNode.selectionSet) return value;
  if (value == null) return null;

  if (Array.isArray(value)) {
    const results = [];
    for (const item of value) {
      results.push(await completeValue({
        schema,
        fieldNode,
        value: item,
        ctx,
        variables,
        fragments,
        errors,
        typeHint
      }));
    }
    return results;
  }

  if (!isObj(value)) {
    throw new Error(`Subselection requires object/list result for "${fieldNode.name}"`);
  }

  const nextTypeName = getRuntimeType(value, unwrapTypeName(typeHint));
  const nextTypeDefs = nextTypeName && schema.types ? schema.types[nextTypeName] : undefined;

  return executeSelectionSet({
    schema,
    selectionSet: fieldNode.selectionSet,
    typeName: nextTypeName,
    typeDefs: nextTypeDefs,
    source: value,
    ctx,
    variables,
    fragments,
    errors
  });
}

module.exports = { execute };
