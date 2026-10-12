import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import test from 'node:test';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function withInput(source, callback) {
  const dir = mkdtempSync(path.join(tmpdir(), 'compose-port-audit-'));
  const file = path.join(dir, 'input.yml');
  writeFileSync(file, source);
  try { callback(file); } finally { rmSync(dir, { recursive: true, force: true }); }
}

function run(...args) {
  return spawnSync(process.execPath, ['src/cli.js', ...args], { cwd: root, encoding: 'utf8', timeout: 5000 });
}

test('CLI escapes terminal controls in findings, paths and errors without corrupting JSON', () => {
  const service = 'evil\u001b[2J\r\n\u009b31m\u202e';
  withInput(`services: { ${JSON.stringify(service)}: { ports: ["8080:80"] } }`, (file) => {
    const human = run(file);
    assert.equal(human.status, 1);
    assert.doesNotMatch(human.stdout, /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u202e]/);
    assert.match(human.stdout, /\\u001b/);
    const json = run('--json', file);
    assert.equal(json.status, 1);
    assert.doesNotMatch(json.stdout, /[\u009b\u202e]/);
    assert.equal(JSON.parse(json.stdout).findings[0].service, service);
  });
  const missing = run(`missing${service}.yml`);
  assert.equal(missing.status, 2);
  assert.doesNotMatch(missing.stderr, /[\u001b\u000d\u009b\u202e]/);
  withInput(`services: { ${JSON.stringify(service)}: null }`, (file) => {
    const invalid = run(file);
    assert.equal(invalid.status, 2);
    assert.doesNotMatch(invalid.stderr, /[\u001b\u000d\u009b\u202e]/);
  });
});

test('CLI refuses FIFOs instead of blocking on attacker-controlled input', { skip: process.platform !== 'linux' }, () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'compose-port-audit-'));
  const file = path.join(dir, 'pipe.yml');
  try {
    assert.equal(spawnSync('mkfifo', [file]).status, 0);
    const result = run(file);
    assert.equal(result.error, undefined);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /regular file/i);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('CLI distinguishes clean audits, unsafe mappings and input failures', () => {
  assert.equal(run('examples/clean.compose.yml').status, 0);
  assert.equal(run('examples/inherited.compose.yml').status, 1);
  for (const args of [[], ['--unknown'], ['missing.yml'], ['examples/clean.compose.yml', 'extra.yml']]) {
    const result = run(...args);
    assert.equal(result.status, 2);
    assert.equal(result.stdout, '');
    assert.notEqual(result.stderr, '');
  }
  for (const source of ['services: []', 'services: {web: {ports: "$PORT"}}', 'services: [',
    'x-deep: ' + '['.repeat(2000) + '0' + ']'.repeat(2000) + '\nservices: {}',
    '#'.repeat(1024 * 1024 + 1), 'services: !reset {}',
    'a: &a [x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b]\nd: [*c,*c,*c,*c,*c]\nservices: {}']) {
    withInput(source, (file) => {
      const result = run('--json', file);
      assert.equal(result.error, undefined);
      assert.equal(result.status, 2);
      assert.equal(result.stdout, '');
      assert.match(result.stderr, /compose-port-audit:/);
    });
  }
  for (const source of ['services: {web: {ports: [80]}}', 'services: {web: {ports: [null]}}']) {
    withInput(source, (file) => {
      const result = run('--json', file);
      assert.equal(result.status, 1);
      assert.ok(JSON.parse(result.stdout).findings.some(({ severity }) => severity === 'error'));
    });
  }
});

test('CLI fails closed for tagged representations and unsupported network attachments', () => {
  for (const source of [
    'services: !!omap [web: {ports: ["8080:80"]}]',
    'services: !!set {web: null}',
    'services: {web: !!omap [ports: ["8080:80"]]}',
    'services: {web: !!timestamp 2026-10-08}',
    'networks: {unsafe: {driver: host}}\nservices: {web: {networks: [unsafe]}}',
    'networks: {default: {external: true, name: host}}\nservices: {web: {}}',
    'networks: {unsafe: {external: true}}\nservices: {web: {networks: {unsafe: null}}}',
  ]) {
    withInput(source, (file) => {
      for (const args of [[file], ['--json', file]]) {
        const result = run(...args);
        assert.equal(result.error, undefined);
        assert.equal(result.status, 2, source);
        assert.equal(result.stdout, '');
        assert.match(result.stderr, /unsupported YAML|unsupported Compose.*network/i);
      }
    });
  }
});

test('CLI reports source IP bracket errors while preserving bridge and merge audits', () => {
  for (const entry of ['"[127.0.0.1:8080:80"', '"127.0.0.1]:8080:80"',
    '{target: 80, published: 8080, host_ip: "[::1"}', '{target: 80, published: 8080, host_ip: "::1]"}']) {
    withInput(`services: {web: {ports: [${entry}]}}`, (file) => {
      const result = run('--json', file);
      assert.equal(result.error, undefined);
      assert.equal(result.status, 1);
      assert.equal(result.stderr, '');
      assert.deepEqual(JSON.parse(result.stdout).findings.map(({ code }) => code), ['INVALID_PORT_MAPPING']);
    });
  }
  const source = 'x-defaults: &defaults {ports: ["127.0.0.1:8080:80"], networks: [local]}\nnetworks: {local: {driver: bridge}}\nservices: {web: {<<: *defaults}}';
  withInput(source, (file) => {
    const result = run('--json', file);
    assert.equal(result.status, 0);
    assert.equal(result.stderr, '');
    assert.deepEqual(JSON.parse(result.stdout).findings, []);
  });
});

test('CLI emits JSON and exits 1 when findings exist', () => {
  const result = spawnSync(process.execPath, ['src/cli.js', '--json', 'examples/risky.compose.yml'], {
    cwd: root,
    encoding: 'utf8',
  });

  assert.equal(result.status, 1);
  assert.equal(result.stderr, '');
  const report = JSON.parse(result.stdout);
  assert.equal(report.file, 'examples/risky.compose.yml');
  assert.ok(report.findings.some(({ code }) => code === 'DUPLICATE_HOST_PORT'));
});
