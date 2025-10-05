'use strict';
const { Lexer } = require('./lexer');

class Parser {
  constructor(src) {
    this.lexer = new Lexer(src);
    this.la = this.lexer.nextToken();
  }

  eat(kind, value = null) {
    const token = this.la;
    if (token.kind !== kind || (value != null && token.value !== value)) {
      throw this.err(`Expected ${value || kind}, got ${token.value || token.kind}`);
    }
    this.la = this.lexer.nextToken();
    return token;
  }

  check(kind, value = null) {
    return this.la.kind === kind && (value == null || this.la.value === value);
  }

  err(message) {
    const e = new SyntaxError(`${message}`);
    e.line = this.la.loc?.line;
    e.col = this.la.loc?.col;
    return e;
  }

  parse() {
    const definitions = [];
    while (this.la.kind !== 'EOF') {
      definitions.push(this.parseDefinition());
    }
    return { kind: 'Document', definitions };
  }

  parseDefinition() {
    if (this.check('NAME', 'query') || this.check('NAME', 'mutation') || this.check('NAME', 'subscription')) {
      return this.parseOperationDefinition();
    }
    if (this.check('PUNCT', '{')) {
      return this.parseOperationDefinition(true);
    }
    if (this.check('NAME', 'fragment')) {
      return this.parseFragmentDefinition();
    }
    throw this.err('Unexpected definition');
  }

  parseOperationDefinition(shortForm = false) {
    let operation = 'query';
    let name = null;
    let variableDefinitions = [];
    let directives = [];

    if (!shortForm) {
      operation = this.eat('NAME').value;
      if (this.check('NAME')) name = this.eat('NAME').value;
      if (this.check('PUNCT', '(')) variableDefinitions = this.parseVariableDefinitions();
      directives = this.parseDirectives();
    }

    const selectionSet = this.parseSelectionSet();
    return {
      kind: 'OperationDefinition',
      operation,
      name,
      variableDefinitions,
      directives,
      selectionSet
    };
  }

  parseVariableDefinitions() {
    this.eat('PUNCT', '(');
    const defs = [];
    while (!this.check('PUNCT', ')')) {
      defs.push(this.parseVariableDefinition());
      if (this.check('PUNCT', ',')) this.eat('PUNCT', ',');
    }
    this.eat('PUNCT', ')');
    return defs;
  }

  parseVariableDefinition() {
    this.eat('PUNCT', '$');
    const name = this.eat('NAME').value;
    this.eat('PUNCT', ':');
    const type = this.parseType();
    let defaultValue = undefined;
    if (this.check('PUNCT', '=')) {
      this.eat('PUNCT', '=');
      defaultValue = this.parseValue();
    }
    return { kind: 'VariableDefinition', variable: { kind: 'Variable', name }, type, defaultValue };
  }

  parseType() {
    let type;
    if (this.check('PUNCT', '[')) {
      this.eat('PUNCT', '[');
      const inner = this.parseType();
      this.eat('PUNCT', ']');
      type = { kind: 'ListType', type: inner, nonNull: false };
    } else {
      const name = this.eat('NAME').value;
      type = { kind: 'NamedType', name, nonNull: false };
    }
    if (this.check('PUNCT', '!')) {
      this.eat('PUNCT', '!');
      type.nonNull = true;
    }
    return type;
  }

  parseSelectionSet() {
    this.eat('PUNCT', '{');
    const selections = [];
    while (!this.check('PUNCT', '}')) selections.push(this.parseSelection());
    this.eat('PUNCT', '}');
    return { kind: 'SelectionSet', selections };
  }

  parseSelection() {
    if (this.check('PUNCT', '...')) return this.parseFragment();
    return this.parseField();
  }

  parseField() {
    const first = this.eat('NAME');
    let alias = null;
    let name = first.value;
    if (this.check('PUNCT', ':')) {
      this.eat('PUNCT', ':');
      alias = name;
      name = this.eat('NAME').value;
    }
    let args = [];
    if (this.check('PUNCT', '(')) args = this.parseArguments();
    const directives = this.parseDirectives();
    let selectionSet = null;
    if (this.check('PUNCT', '{')) selectionSet = this.parseSelectionSet();
    return { kind: 'Field', name, alias, arguments: args, directives, selectionSet };
  }

  parseArguments() {
    this.eat('PUNCT', '(');
    const out = [];
    while (!this.check('PUNCT', ')')) {
      const name = this.eat('NAME').value;
      this.eat('PUNCT', ':');
      const value = this.parseValue();
      out.push({ kind: 'Argument', name, value });
      if (this.check('PUNCT', ',')) this.eat('PUNCT', ',');
    }
    this.eat('PUNCT', ')');
    return out;
  }

  parseValue() {
    const t = this.la;
    switch (t.kind) {
      case 'STRING':
        this.eat('STRING');
        return { kind: 'StringValue', value: t.value };
      case 'INT':
        this.eat('INT');
        return { kind: 'IntValue', value: parseInt(t.value, 10) };
      case 'FLOAT':
        this.eat('FLOAT');
        return { kind: 'FloatValue', value: parseFloat(t.value) };
      case 'NAME': {
        const v = this.eat('NAME').value;
        if (v === 'true' || v === 'false') return { kind: 'BooleanValue', value: v === 'true' };
        if (v === 'null') return { kind: 'NullValue', value: null };
        return { kind: 'EnumValue', value: v };
      }
      case 'PUNCT':
        if (t.value === '[') return this.parseList();
        if (t.value === '{') return this.parseObject();
        if (t.value === '$') return this.parseVariable();
        break;
    }
    throw this.err('Invalid value');
  }

  parseVariable() {
    this.eat('PUNCT', '$');
    const name = this.eat('NAME').value;
    return { kind: 'Variable', name };
  }

  parseList() {
    this.eat('PUNCT', '[');
    const values = [];
    while (!this.check('PUNCT', ']')) {
      values.push(this.parseValue());
      if (this.check('PUNCT', ',')) this.eat('PUNCT', ',');
    }
    this.eat('PUNCT', ']');
    return { kind: 'ListValue', values };
  }

  parseObject() {
    this.eat('PUNCT', '{');
    const fields = [];
    while (!this.check('PUNCT', '}')) {
      const name = this.eat('NAME').value;
      this.eat('PUNCT', ':');
      const value = this.parseValue();
      fields.push({ kind: 'ObjectField', name, value });
      if (this.check('PUNCT', ',')) this.eat('PUNCT', ',');
    }
    this.eat('PUNCT', '}');
    return { kind: 'ObjectValue', fields };
  }

  parseFragment() {
    this.eat('PUNCT', '...');
    if (this.check('NAME', 'on')) {
      return this.parseInlineFragment();
    }
    const name = this.eat('NAME').value;
    const directives = this.parseDirectives();
    return { kind: 'FragmentSpread', name, directives };
  }

  parseInlineFragment() {
    let typeCondition = null;
    if (this.check('NAME', 'on')) {
      this.eat('NAME', 'on');
      typeCondition = this.eat('NAME').value;
    }
    const directives = this.parseDirectives();
    const selectionSet = this.parseSelectionSet();
    return { kind: 'InlineFragment', typeCondition, directives, selectionSet };
  }

  parseFragmentDefinition() {
    this.eat('NAME', 'fragment');
    const name = this.eat('NAME').value;
    this.eat('NAME', 'on');
    const typeCondition = this.eat('NAME').value;
    const directives = this.parseDirectives();
    const selectionSet = this.parseSelectionSet();
    return { kind: 'FragmentDefinition', name, typeCondition, directives, selectionSet };
  }

  parseDirectives() {
    const directives = [];
    while (this.check('PUNCT', '@')) {
      this.eat('PUNCT', '@');
      const name = this.eat('NAME').value;
      let args = [];
      if (this.check('PUNCT', '(')) args = this.parseArguments();
      directives.push({ kind: 'Directive', name, arguments: args });
    }
    return directives;
  }
}

function parse(src) {
  return new Parser(src).parse();
}

module.exports = { parse };
