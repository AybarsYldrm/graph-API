'use strict';

class Lexer {
  constructor(source) {
    this.source = String(source);
    this.pos = 0;
    this.line = 1;
    this.col = 1;
  }
  peek() { return this.source[this.pos]; }
  next() {
    const ch = this.source[this.pos++];
    if (ch === '\n') { this.line++; this.col = 1; } else { this.col++; }
    return ch;
  }
  eof() { return this.pos >= this.source.length; }
  isNameStart(c) { return /[A-Za-z_]/.test(c); }
  isName(c) { return /[A-Za-z0-9_]/.test(c); }
  isDigit(c) { return /[0-9]/.test(c); }

  skipIgnored() {
    for (;;) {
      while (!this.eof() && /[\s,]/.test(this.peek())) this.next();
      if (this.peek() === '#') { while (!this.eof() && this.peek() !== '\n') this.next(); continue; }
      break;
    }
  }

  readName() {
    const start = { line: this.line, col: this.col };
    let v = '';
    while (!this.eof() && this.isName(this.peek())) v += this.next();
    return { kind: 'NAME', value: v, loc: start };
  }
  readNumber() {
    const start = { line: this.line, col: this.col };
    let r = '';
    if (this.peek() === '-') r += this.next();
    if (!this.isDigit(this.peek())) throw this.err('Invalid number');
    while (!this.eof() && this.isDigit(this.peek())) r += this.next();
    if (this.peek() === '.') {
      r += this.next();
      if (!this.isDigit(this.peek())) throw this.err('Invalid float');
      while (!this.eof() && this.isDigit(this.peek())) r += this.next();
      return { kind: 'FLOAT', value: r, loc: start };
    }
    return { kind: 'INT', value: r, loc: start };
  }
  readString() {
    const start = { line: this.line, col: this.col };
    let v = '';
    this.next(); // "
    for (;;) {
      if (this.eof()) throw this.err('Unterminated string');
      const ch = this.next();
      if (ch === '"') break;
      if (ch === '\\') {
        const e = this.next();
        const map = { '"':'"', '\\':'\\', '/':'/', b:'\b', f:'\f', n:'\n', r:'\r', t:'\t' };
        if (map[e]) v += map[e];
        else if (e === 'u') {
          let hex = ''; for (let i=0;i<4;i++) hex += this.next();
          v += String.fromCharCode(parseInt(hex,16));
        } else throw this.err('Bad escape');
      } else v += ch;
    }
    return { kind: 'STRING', value: v, loc: start };
  }
  readPunct() {
    const start = { line: this.line, col: this.col };
    if (this.source.slice(this.pos, this.pos+3) === '...') { this.pos+=3; this.col+=3; return { kind:'PUNCT', value:'...', loc:start }; }
    return { kind: 'PUNCT', value: this.next(), loc: start };
  }
  err(msg) {
    const e = new SyntaxError(`${msg} at ${this.line}:${this.col}`);
    e.line = this.line; e.col = this.col; return e;
  }
  nextToken() {
    this.skipIgnored();
    if (this.eof()) return { kind: 'EOF' };
    const ch = this.peek();
    if (this.isNameStart(ch)) return this.readName();
    if (ch === '"') return this.readString();
    if (ch === '-' || this.isDigit(ch)) return this.readNumber();
    return this.readPunct();
  }
}
module.exports = { Lexer };
