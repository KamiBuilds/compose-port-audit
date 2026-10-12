import assert from 'node:assert/strict';
import test from 'node:test';

import { auditCompose } from '../src/audit.js';

test('flags short and long automatically allocated host ports instead of skipping them', () => {
  for (const entry of [80, '"80"', '"53/udp"', '{ target: 80 }', '{ target: 80, published: 0 }']) {
    const findings = auditCompose(`services: { web: { ports: [${entry}] } }`);
    assert.ok(findings.some(({ code }) => code === 'EPHEMERAL_PORT'), entry);
  }
});

test('rejects unresolved Compose interpolation rather than trusting literal bindings', () => {
  for (const value of ['$PORT', '${PORT}', '${IP:-127.0.0.1}:9000:80', '127.0.0.1:9000:80/${PROTO}']) {
    assert.throws(() => auditCompose(`services: { web: { ports: [${JSON.stringify(value)}] } }`), /interpolation/i);
  }
  assert.throws(() => auditCompose('services: { web: { ports: [{ target: 80, published: 9000, host_ip: "${IP}" }] } }'), /interpolation/i);
  assert.throws(() => auditCompose('services: { web: { network_mode: "$MODE" } }'), /interpolation/i);
  assert.deepEqual(auditCompose('services: { web: { command: "echo $$HOME" } }'), []);
});

test('rejects malformed Compose containers as input errors', () => {
  for (const source of ['', 'null', '[]', '42', '{}', 'services: null', 'services: []', 'services: false',
    'services: {web: null}', 'services: {web: []}', 'services: {web: 80}',
    'services: {web: {ports: null}}', 'services: {web: {ports: "8080:80"}}', 'services: {web: {ports: {a: 80}}}']) {
    assert.throws(() => auditCompose(source), /Compose structure/i, source);
  }
  assert.deepEqual(auditCompose('services: {}'), []);
  assert.deepEqual(auditCompose('services: {web: {expose: [80]}}'), []);
});

test('reports every malformed port entry instead of skipping or coercing it', () => {
  for (const entry of ['null', 'true', 'false', '[]', '[80]', '{}', '"junk"', '""',
    '{published: 8080}', '{target: true, published: 9000}', '{target: 80, published: false}',
    '{target: 80, published: "9e3"}', '{target: 80, published: [9000]}',
    '{target: 80, published: 9000, host_ip: false}', '{target: 80, published: 9000, host_ip: localhost}',
    '{target: 80, published: 9000, protocol: null}', '{target: 80, published: 9000, publised: 9001}',
    '"localhost:9000:80"']) {
    const findings = auditCompose(`services: {web: {ports: [${entry}]}}`);
    assert.ok(findings.some(({ code }) => code === 'INVALID_PORT_MAPPING'), entry);
  }
});

test('rejects oversized YAML before parsing', () => {
  assert.throws(() => auditCompose(`#${'x'.repeat(1024 * 1024)}`), /input.*limit/i);
});

test('rejects deeply nested YAML before converting it to JavaScript', () => {
  const source = `x-deep: ${'['.repeat(80)}0${']'.repeat(80)}\nservices: {}`;
  assert.throws(() => auditCompose(source), /nesting.*limit/i);
});

test('rejects YAML exceeding the structural node budget', () => {
  assert.throws(() => auditCompose(`x-many: [${Array(10001).fill('0').join(',')}]\nservices: {}`), /node.*limit/i);
});

test('rejects cyclic YAML aliases without silently returning a clean audit', () => {
  assert.throws(() => auditCompose('x-cycle: &cycle {self: *cycle}\nservices: {}'), /cyclic.*alias/i);
});

test('refuses Compose composition or host networking that hides bindings', () => {
  for (const source of [
    'include: other.yml\nservices: {}',
    'services: { web: { extends: {file: other.yml, service: web} } }',
    'services: { web: { network_mode: host } }',
    'services: { web: { network_mode: "service:other" } }',
    'services: { web: { network_mode: [] } }',
  ]) assert.throws(() => auditCompose(source), /unsupported Compose/i, source);
});

test('refuses network attachments whose exposure cannot be audited statically', async (t) => {
  const sources = [
    'networks: {unsafe: {driver: host}}\nservices: {web: {networks: [unsafe]}}',
    'networks: {unsafe: {driver: host}}\nservices: {web: {networks: {unsafe: null}}}',
    'networks: {default: {driver: host}}\nservices: {web: {}}',
    'networks: {default: {driver: host}}\nservices: {web: {networks: []}}',
    'networks: {default: {driver: host}}\nservices: {web: {networks: {}}}',
    'networks: {default: {driver: host}}\nservices: {web: {networks: null}}',
    'networks: {unsafe: {external: true, name: host}}\nservices: {web: {networks: [unsafe]}}',
    'networks: {unsafe: {external: true}}\nservices: {web: {networks: {unsafe: {aliases: [web]}}}}',
    'networks: {default: {external: true}}\nservices: {web: {}}',
    'networks: {unsafe: {external: {name: host}}}\nservices: {web: {networks: [unsafe]}}',
    'networks: {unsafe: {name: host}}\nservices: {web: {networks: [unsafe]}}',
    'services: {web: {networks: [host]}}',
    'services: {web: {networks: [undeclared]}}',
    'networks: {unsafe: {driver: custom}}\nservices: {web: {networks: [unsafe]}}',
    'x-network: &network {driver: host}\nnetworks: {unsafe: {<<: *network}}\nservices: {web: {networks: [unsafe]}}',
  ];
  for (const source of sources) {
    await t.test(source, () => assert.throws(() => auditCompose(source), /unsupported Compose.*network/i));
  }
});

test('preserves ordinary bridge attachments and safe inherited network definitions', () => {
  const source = `
x-network: &bridge {driver: bridge, external: false}
networks:
  default: null
  local: {<<: *bridge, internal: true}
  ordinary: {}
  unused-host: {driver: host}
  unused-external: {external: true}
services:
  implicit: {ports: ["127.0.0.1:8080:80"]}
  sequence: {networks: [local, ordinary], ports: ["127.0.0.1:8081:80"]}
  mapping: {networks: {local: {aliases: [web]}, ordinary: null}, ports: ["8082:80"]}
`;
  assert.deepEqual(auditCompose(source).map(({ code, service }) => ({ code, service })), [
    { code: 'PUBLIC_BINDING', service: 'mapping' },
  ]);
  for (const mode of ['bridge', 'none', 'default']) {
    assert.deepEqual(auditCompose(`networks: {default: {driver: host}}\nservices: {web: {network_mode: ${mode}}}`), []);
  }
  assert.deepEqual(auditCompose('services: {web: {networks: [default]}}'), []);
  assert.deepEqual(auditCompose('networks: {host: {driver: bridge}}\nservices: {web: {networks: [host]}}'), []);
});

test('rejects malformed network containers rather than ignoring attachments', () => {
  for (const source of [
    'networks: []\nservices: {}',
    'networks: {local: false}\nservices: {web: {networks: [local]}}',
    'services: {web: {networks: host}}',
    'services: {web: {networks: [null]}}',
    'services: {web: {networks: [""]}}',
    'networks: {local: {}}\nservices: {web: {networks: {local: false}}}',
    'networks: {local: {external: "false"}}\nservices: {web: {networks: [local]}}',
    'networks: {local: {name: null}}\nservices: {web: {networks: [local]}}',
    'services: {web: {network_mode: bridge, networks: [default]}}',
  ]) assert.throws(() => auditCompose(source), /Compose structure|unsupported Compose.*network/i, source);
});

test('rejects unsupported YAML tags instead of ignoring Compose reset semantics', () => {
  for (const tag of ['!reset', '!override', '!unknown']) {
    assert.throws(() => auditCompose(`services: ${tag} {}`), /unsupported YAML/i);
  }
});

test('rejects recognized YAML representations that could hide Compose values', async (t) => {
  const sources = [
    '!!omap [services: {web: {ports: ["8080:80"]}}]',
    'services: !!omap [web: {ports: ["8080:80"]}]',
    'services: !!set {web: null}',
    'services: {web: !!omap [ports: ["8080:80"]]}',
    'services: {web: !!timestamp 2026-10-08}',
    'services: {web: {ports: [!!omap [target: 80, published: 8080]]}}',
    'x-defaults: &defaults !!omap [ports: ["8080:80"]]\nservices: {web: *defaults}',
    'x-hidden: !!timestamp 2026-10-08\nservices: {}',
    'x-hidden: !!pairs [ports: ["8080:80"]]\nservices: {}',
    'x-hidden: !!binary SGVsbG8=\nservices: {}',
    '%YAML 1.1\n---\nx-hidden: 2026-10-08\nservices: {}',
  ];
  for (const source of sources) {
    await t.test(source, () => assert.throws(() => auditCompose(source), /unsupported YAML/i));
  }
});

test('preserves core YAML tags and ordinary shared anchors with merge overrides', () => {
  const source = `
x-defaults: &defaults !!map
  ports: !!seq ["8080:80"]
services: !!map
  inherited: {<<: *defaults}
  overridden: {<<: *defaults, ports: ["127.0.0.1:9000:80"]}
  shared: {ports: &local ["127.0.0.2:9000:80"]}
  reused: {ports: *local}
`;
  const findings = auditCompose(source);
  assert.deepEqual(findings.map(({ code, service }) => ({ code, service })), [
    { code: 'PUBLIC_BINDING', service: 'inherited' },
    { code: 'DUPLICATE_HOST_PORT', service: 'reused' },
  ]);
});

test('rejects excessive total alias references even across different anchors', () => {
  const anchors = Array.from({ length: 101 }, (_, i) => `x-a${i}: &a${i} 0`).join('\n');
  const refs = Array.from({ length: 101 }, (_, i) => `*a${i}`).join(',');
  assert.throws(() => auditCompose(`${anchors}\nx-refs: [${refs}]\nservices: {}`), /alias.*limit/i);
});

test('rejects non-string YAML mapping keys before lossy conversion', () => {
  for (const source of ['services: { [web]: {} }', 'services: {null: {}}', 'services: {true: {}}']) {
    assert.throws(() => auditCompose(source), /mapping keys/i, source);
  }
});

test('bounds total audited port mappings including inherited sequences', () => {
  const source = `x-ports: &ports [${Array(501).fill('"127.0.0.1:9000:80"').join(',')}]\nservices: {a: {ports: *ports}, b: {ports: *ports}}`;
  assert.throws(() => auditCompose(source), /port mapping.*limit/i);
});

test('reports an implicit public host binding', () => {
  const compose = `
services:
  web:
    image: nginx
    ports:
      - "8080:80"
`;

  const findings = auditCompose(compose);

  assert.deepEqual(findings.map(({ code, service, hostPort }) => ({ code, service, hostPort })), [
    { code: 'PUBLIC_BINDING', service: 'web', hostPort: 8080 },
  ]);
});

test('reports duplicate host ports across services', () => {
  const compose = `
services:
  api:
    image: example/api
    ports:
      - "127.0.0.1:9000:9000"
  metrics:
    image: example/metrics
    ports:
      - "127.0.0.1:9000:9090"
`;

  const duplicates = auditCompose(compose).filter(({ code }) => code === 'DUPLICATE_HOST_PORT');

  assert.equal(duplicates.length, 1);
  assert.equal(duplicates[0].service, 'metrics');
  assert.equal(duplicates[0].conflictsWith, 'api');
  assert.equal(duplicates[0].hostPort, 9000);
});

test('treats wildcard bindings as conflicting with specific interfaces', () => {
  const compose = `
services:
  public:
    image: example/public
    ports:
      - "3000:3000"
  local:
    image: example/local
    ports:
      - "127.0.0.1:3000:3000"
`;

  const duplicates = auditCompose(compose).filter(({ code }) => code === 'DUPLICATE_HOST_PORT');

  assert.equal(duplicates.length, 1);
  assert.equal(duplicates[0].service, 'local');
  assert.equal(duplicates[0].conflictsWith, 'public');
});

test('keeps conflicting wildcard bindings for later conflict checks', () => {
  const compose = `
services:
  first:
    ports: ["127.0.0.1:3000:3000"]
  wildcard:
    ports: ["3000:3000"]
  second:
    ports: ["127.0.0.2:3000:3000"]
`;

  const duplicates = auditCompose(compose).filter(({ code }) => code === 'DUPLICATE_HOST_PORT');

  assert.equal(duplicates.length, 2);
  assert.equal(duplicates[1].service, 'second');
  assert.equal(duplicates[1].conflictsWith, 'wildcard');
});

test('normalizes bracketed IPv6 addresses across port syntaxes', () => {
  const compose = `
services:
  short:
    ports: ["[::1]:9000:9000"]
  long:
    ports:
      - target: 9001
        published: 9000
        host_ip: "::1"
`;

  const duplicates = auditCompose(compose).filter(({ code }) => code === 'DUPLICATE_HOST_PORT');

  assert.equal(duplicates.length, 1);
  assert.equal(duplicates[0].conflictsWith, 'short');
});

test('reports malformed source IP brackets without repairing the token', async (t) => {
  const shortTokens = ['[127.0.0.1:8080:80', '127.0.0.1]:8080:80', '[127.0.0.1]:8080:80'];
  const longTokens = ['[::1', '::1]', '[127.0.0.1', '127.0.0.1]', '[127.0.0.1]', '[[::1]]', '[::1]]', '[]'];
  const entries = [
    ...shortTokens.map((token) => JSON.stringify(token)),
    ...longTokens.map((token) => `{target: 80, published: 8080, host_ip: ${JSON.stringify(token)}}`),
  ];
  for (const entry of entries) {
    await t.test(entry, () => {
      const findings = auditCompose(`services: {web: {ports: [${entry}]}}`);
      assert.deepEqual(findings.map(({ code }) => code), ['INVALID_PORT_MAPPING']);
    });
  }
});

test('accepts exact literal IP forms without changing valid loopback behavior', () => {
  for (const ip of ['127.0.0.1', '::1', '[::1]']) {
    assert.deepEqual(auditCompose(`services: {web: {ports: [{target: 80, published: 8080, host_ip: ${JSON.stringify(ip)}}]}}`), []);
  }
});

test('does not conflate explicit IPv4 and IPv6 bindings', () => {
  const compose = `
services:
  ipv4:
    ports: ["0.0.0.0:9443:443"]
  ipv6:
    ports: ["[::1]:9443:443"]
`;

  const duplicates = auditCompose(compose).filter(({ code }) => code === 'DUPLICATE_HOST_PORT');

  assert.equal(duplicates.length, 0);
});

test('canonicalizes expanded IPv6 addresses and detects wildcard exposure', () => {
  const compose = `
services:
  public:
    ports: ["[0:0:0:0:0:0:0:0]:9443:443"]
  local:
    ports: ["[0:0:0:0:0:0:0:1]:9000:9000"]
  compressed:
    ports: ["[::1]:9000:9001"]
`;

  const findings = auditCompose(compose);

  assert.equal(findings.filter(({ code }) => code === 'PUBLIC_BINDING').length, 1);
  assert.equal(findings.filter(({ code }) => code === 'DUPLICATE_HOST_PORT').length, 1);
});

test('reports privileged ports in long syntax', () => {
  const compose = `
services:
  dns:
    image: example/dns
    ports:
      - target: 53
        published: 53
        host_ip: 127.0.0.1
        protocol: udp
`;

  const privileged = auditCompose(compose).filter(({ code }) => code === 'PRIVILEGED_PORT');

  assert.equal(privileged.length, 1);
  assert.equal(privileged[0].service, 'dns');
  assert.equal(privileged[0].hostPort, 53);
  assert.equal(privileged[0].protocol, 'udp');
});

test('reports unsupported protocols', () => {
  const compose = `
services:
  probe:
    image: example/probe
    ports:
      - target: 7
        published: 10007
        protocol: icmp
`;

  const invalid = auditCompose(compose).filter(({ code }) => code === 'INVALID_PROTOCOL');

  assert.equal(invalid.length, 1);
  assert.equal(invalid[0].protocol, 'icmp');
});

test('reports unsupported protocols in short syntax', () => {
  const compose = `
services:
  probe:
    ports: ["10007:7/icmp"]
`;

  const invalid = auditCompose(compose).filter(({ code }) => code === 'INVALID_PROTOCOL');

  assert.equal(invalid.length, 1);
  assert.equal(invalid[0].protocol, 'icmp');
});

test('reports unsupported short-syntax port ranges', () => {
  const compose = `
services:
  web:
    ports: ["8000-8002:80-82"]
`;

  const unsupported = auditCompose(compose).filter(({ code }) => code === 'UNSUPPORTED_PORT_RANGE');

  assert.equal(unsupported.length, 1);
  assert.equal(unsupported[0].service, 'web');
});

test('reports invalid long-syntax port values', () => {
  const compose = `
services:
  broken:
    ports:
      - target: 80
        published: not-a-port
`;

  const invalid = auditCompose(compose).filter(({ code }) => code === 'INVALID_PORT_MAPPING');

  assert.equal(invalid.length, 1);
  assert.equal(invalid[0].service, 'broken');
});

test('reports out-of-range short-syntax ports', () => {
  const compose = `
services:
  broken:
    ports: ["70000:80"]
`;

  const invalid = auditCompose(compose).filter(({ code }) => code === 'INVALID_PORT_MAPPING');

  assert.equal(invalid.length, 1);
});

test('reports malformed published short-syntax mappings', () => {
  const compose = `
services:
  broken:
    ports: ["8080:not-a-port"]
  internal:
    ports: [80]
`;

  const invalid = auditCompose(compose).filter(({ code }) => code === 'INVALID_PORT_MAPPING');

  assert.equal(invalid.length, 1);
  assert.equal(invalid[0].service, 'broken');
});

test('audits ports inherited through a YAML merge key', () => {
  const compose = `
x-published: &published
  ports:
    - "8080:80"
services:
  web:
    <<: *published
    image: nginx
`;

  const publicBindings = auditCompose(compose).filter(({ code }) => code === 'PUBLIC_BINDING');

  assert.equal(publicBindings.length, 1);
  assert.equal(publicBindings[0].service, 'web');
  assert.equal(publicBindings[0].hostPort, 8080);
});
