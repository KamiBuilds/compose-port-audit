import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { auditCompose } from '../src/audit.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ambiguous = /ambiguous YAML integer.*leading.zero/i;
const cases = [
  ['privileged implicit integer', 'services: {a: {image: nginx, ports: [{target: 80, published: 01777, host_ip: 127.0.0.1}]}}'],
  ['privileged explicit integer tag', 'services: {a: {image: nginx, ports: [{target: 80, published: !!int 01777, host_ip: 127.0.0.1}]}}'],
  ['nonprivileged collision', 'services: {a: {image: nginx, ports: [{target: 80, published: 02000, host_ip: 127.0.0.1}]}, b: {image: nginx, ports: ["127.0.0.1:1024:81"]}}'],
  ['inherited numeric mapping collision', 'x-port: &port {target: 80, published: 02000, host_ip: 127.0.0.1}\nservices: {a: {image: nginx, ports: [*port]}, b: {image: nginx, ports: ["127.0.0.1:1024:81"]}}'],
];

for (const [name, source] of cases) {
  test(`rejects cross-parser leading-zero ${name}`, () => {
    assert.throws(() => auditCompose(source), ambiguous);
  });

  test(`CLI fails closed for cross-parser leading-zero ${name}`, () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'compose-port-numeric-'));
    const file = path.join(dir, 'input.yml');
    try {
      writeFileSync(file, source);
      for (const args of [[file], ['--json', file]]) {
        const result = spawnSync(process.execPath, ['src/cli.js', ...args], {
          cwd: root, encoding: 'utf8', timeout: 5000,
        });
        assert.equal(result.error, undefined);
        assert.equal(result.status, 2);
        assert.equal(result.stdout, '');
        assert.match(result.stderr, ambiguous);
      }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
}

test('rejects leading-zero integer spellings throughout the YAML AST before alias conversion', async (t) => {
  const sources = [
    'services: {web: {ports: [{target: 0100, published: 9000, host_ip: 127.0.0.1}]}}',
    'services: {web: {ports: [01777]}}',
    'x-port: &port {target: 80, published: 02000, host_ip: 127.0.0.1}\nservices: {web: {ports: [{<<: *port}]}}',
    'services: {web: {ports: [{target: 80, published: !!int "01777", host_ip: 127.0.0.1}]}}',
    "services: {web: {ports: [{target: 80, published: !!int '01777', host_ip: 127.0.0.1}]}}",
    'services: {web: {ports: [{target: 80, published: !!int "\\x301777", host_ip: 127.0.0.1}]}}',
    ...['+01777', '-01777', '00', '0080', '0_1777'].map((value) => `x-number: ${value}\nservices: {}`),
    '%YAML 1.1\n---\nx-number: 0_1777\nservices: {}',
  ];
  for (const source of sources) {
    await t.test(source, () => assert.throws(() => auditCompose(source), ambiguous));
  }
});

test('preserves leading-zero strings as decimal ports rather than legacy octal integers', () => {
  for (const value of ['"01777"', "'01777'", '!!str 01777', '!!str "01777"']) {
    assert.deepEqual(auditCompose(`services: {web: {ports: [{target: "0100", published: ${value}, host_ip: 127.0.0.1}]}}`), []);
  }
  const inherited = 'x-port: &port {target: "0100", published: "02000", host_ip: 127.0.0.1}\nservices: {a: {ports: [*port]}, b: {ports: ["127.0.0.1:1024:81"]}, c: {ports: ["127.0.0.1:2000:81"]}}';
  assert.deepEqual(auditCompose(inherited).map(({ code, service, conflictsWith, hostPort }) => ({ code, service, conflictsWith, hostPort })), [
    { code: 'DUPLICATE_HOST_PORT', service: 'c', conflictsWith: 'a', hostPort: 2000 },
  ]);
  assert.deepEqual(auditCompose('x-strings: ["00", "0_1777", !!str +01777]\nservices: {}'), []);
});

test('preserves unambiguous numeric core tags and zero host-allocation findings', () => {
  assert.deepEqual(auditCompose('services: {web: {ports: [{target: !!int 80, published: !!int "1777", host_ip: 127.0.0.1}]}}'), []);
  assert.deepEqual(auditCompose('services: {web: {ports: [{target: 80, published: 0}]}}').map(({ code }) => code), ['EPHEMERAL_PORT']);
});
