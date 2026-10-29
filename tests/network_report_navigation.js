// Exercise the actual report navigation function without a browser dependency.
'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync(process.argv[2], 'utf8');
const script = html.slice(html.indexOf('let traceBuffer,'), html.indexOf('function actions(ev)'));
const bytes = new Uint8Array([1, 2, 3]).buffer;
const listeners = new Set();
const navigations = [], messages = [], statuses = [];
let opens = 0, reads = 0;
const target = {
  closed: false,
  focus() {},
  set location(url) { navigations.push(url); },
  postMessage(data, origin) {
    assert.equal(origin, 'https://ui.perfetto.dev');
    if (data === 'PING') {
      for (const listener of listeners) {
        // An unrelated popup / origin must not complete the handshake.
        listener({source: {}, origin, data: 'PONG'});
        listener({source: target, origin: 'https://attacker.example', data: 'PONG'});
        listener({source: target, origin, data: 'PONG'});
      }
    } else messages.push(data);
  },
};
const context = vm.createContext({
  URL, Uint8Array, setInterval, clearInterval, setTimeout, clearTimeout,
  crypto: crypto.webcrypto,
  location: {protocol: 'http:', hostname: '127.0.0.1'},
  report: {trace: {name: 'test', sha256: crypto.createHash('sha256').update(new Uint8Array(bytes)).digest('hex')}},
  show: status => statuses.push(status),
  fetch: async () => { reads++; return {ok: true, arrayBuffer: async () => bytes}; },
  window: {
    open(url) { opens++; target.closed=false; target.location=url; return target; },
    addEventListener(type, listener) { listeners.add(listener); },
    removeEventListener(type, listener) { listeners.delete(listener); },
  },
  evidence: {perfetto_url: 'https://ui.perfetto.dev/#!/?ts=9007199254740993&dur=1', selection: 'slice'},
});
(async () => {
  vm.runInContext(script, context);
  await vm.runInContext('openEvidence(evidence)', context);
  await vm.runInContext('openEvidence(evidence)', context);
  assert.equal(opens, 1, 'Repeated navigation must reuse the popup');
  assert.equal(reads, 1, 'The local trace buffer is cached');
  assert.equal(messages.length, 2, 'Each new Perfetto document receives the trace');
  assert.notEqual(navigations[0], navigations[1], 'Same-tag clicks must force a fresh document');
  for (const url of navigations) assert.ok(url.endsWith('#!/?ts=9007199254740993&dur=1'));
  assert.ok(messages.every(m => m.perfetto.keepApiOpen !== true));
  assert.equal(listeners.size, 0, 'Handshake listeners must be removed');
  target.closed = true;
  await vm.runInContext('openEvidence(evidence)', context);
  assert.equal(opens, 2, 'Closing the popup permits reopening');
  assert.equal(messages.length, 3);
  console.log('Perfetto popup reuse, document reload, exact time, and handshake checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
