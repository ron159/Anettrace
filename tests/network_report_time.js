'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync(process.argv[2], 'utf8');
const source = html.slice(html.indexOf('function formatDuration('), html.indexOf('let traceBuffer,'));
const base = 9007199254740993n;
const utc = BigInt(Date.UTC(2026, 9, 29, 16, 0, 0))*1000000n+123456789n;
const context = vm.createContext({report:{time:{trace_start_ns:String(base),realtime_by_ts:{
  [String(base)]:String(utc-1000000000n), [String(base+1n)]:String(utc),
}}}});
vm.runInContext(source,context);
assert.equal(vm.runInContext(`utc8('${utc}')`,context),'2026-10-30 00:00:00.123456');
assert.equal(vm.runInContext("formatDuration('140000000')",context),'140.000 ms');
assert.equal(vm.runInContext("formatDuration('1400000000')",context),'1.400000 s');
assert.equal(vm.runInContext("formatDuration('-1')",context),'未完成');
assert.equal(vm.runInContext("formatDuration(null)",context),'未知');
assert.equal(vm.runInContext(`formatTime('${base+1n}')`,context),'2026-10-30 00:00:00.123456\n+<0.001 ms');
vm.runInContext("timeMode='relative'",context);
assert.equal(vm.runInContext(`formatTime('${base+1n}')`,context),'+<0.001 ms');
assert.equal(vm.runInContext(`formatTime('${base-1400000000n}')`,context),'-1.400000 s');
vm.runInContext("timeMode='utc8'",context);
assert.match(vm.runInContext(`formatTime('${base+1000000n}')`,context),/墙钟未观测/);
assert.equal(vm.runInContext('formatTime(null)',context),'未观测');
console.log('UTC+8 rollover, relative time, missing clocks, and exact integer checks passed');
