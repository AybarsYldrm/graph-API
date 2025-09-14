'use strict';
const { Lexer } = require('./lexer');

class Parser {
  constructor(src) {
    this.lexer = new Lexer(src);
    this.la = this.lexer.nextToken();
  }
  eat(kind, v=null) {
    const t = this.la;
    if (t.kind !== kind || (v!=null && t.value !== v)) throw this.err(`Expected ${v||kind}, got ${t.value||t.kind}`);
    this.la = this.lexer.nextToken();
    return t;
  }
  check(kind, v=null){ return this.la.kind===kind && (v==null || this.la.value===v); }
  err(msg){ const e=new SyntaxError(`${msg}`); e.line=this.la.loc?.line; e.col=this.la.loc?.col; return e; }

  parse() {
    let op = 'query', name=null;
    if (this.check('NAME','query') || this.check('NAME','mutation')) { op=this.la.value; this.eat('NAME'); if (this.check('NAME')) name=this.eat('NAME').value; }
    const selectionSet = this.parseSelectionSet();
    return { kind:'Document', definitions:[{ kind:'OperationDefinition', operation:op, name, selectionSet }] };
  }
  parseSelectionSet(){
    this.eat('PUNCT','{');
    const selections=[];
    while(!this.check('PUNCT','}')) selections.push(this.parseField());
    this.eat('PUNCT','}');
    return { kind:'SelectionSet', selections };
  }
  parseField(){
    const first = this.eat('NAME');
    let alias=null, name=first.value;
    if (this.check('PUNCT',':')) { this.eat('PUNCT',':'); alias=name; name=this.eat('NAME').value; }
    let args=[];
    if (this.check('PUNCT','(')) args=this.parseArguments();
    let selectionSet=null;
    if (this.check('PUNCT','{')) selectionSet=this.parseSelectionSet();
    return { kind:'Field', name, alias, arguments:args, selectionSet };
  }
  parseArguments(){
    this.eat('PUNCT','(');
    const out=[];
    while(!this.check('PUNCT',')')){
      const name=this.eat('NAME').value;
      this.eat('PUNCT',':');
      const value=this.parseValue();
      out.push({ kind:'Argument', name, value });
      if (this.check('PUNCT',',')) this.eat('PUNCT',',');
    }
    this.eat('PUNCT',')');
    return out;
  }
  parseValue(){
    const t=this.la;
    switch(t.kind){
      case 'STRING': this.eat('STRING'); return { kind:'StringValue', value:t.value };
      case 'INT': this.eat('INT'); return { kind:'IntValue', value:parseInt(t.value,10) };
      case 'FLOAT': this.eat('FLOAT'); return { kind:'FloatValue', value:parseFloat(t.value) };
      case 'NAME': {
        const v=this.eat('NAME').value;
        if (v==='true'||v==='false') return { kind:'BooleanValue', value:v==='true' };
        if (v==='null') return { kind:'NullValue', value:null };
        return { kind:'EnumValue', value:v };
      }
      case 'PUNCT':
        if (t.value==='[') return this.parseList();
        if (t.value==='{') return this.parseObject();
    }
    throw this.err('Invalid value');
  }
  parseList(){
    this.eat('PUNCT','[');
    const vals=[];
    while(!this.check('PUNCT',']')){
      vals.push(this.parseValue());
      if (this.check('PUNCT',',')) this.eat('PUNCT',',');
    }
    this.eat('PUNCT',']');
    return { kind:'ListValue', values: vals };
  }
  parseObject(){
    this.eat('PUNCT','{');
    const fields=[];
    while(!this.check('PUNCT','}')){
      const name=this.eat('NAME').value;
      this.eat('PUNCT',':');
      const value=this.parseValue();
      fields.push({ kind:'ObjectField', name, value });
      if (this.check('PUNCT',',')) this.eat('PUNCT',',');
    }
    this.eat('PUNCT','}');
    return { kind:'ObjectValue', fields };
  }
}
function parse(src){ return new Parser(src).parse(); }
module.exports = { parse };
