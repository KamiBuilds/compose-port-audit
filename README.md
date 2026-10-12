# compose-port-audit

A Docker-free CLI that statically checks published ports in a single Docker Compose YAML file before deployment.

It reports conflicting host-port/protocol bindings, all-interface exposure, privileged host ports below 1024, invalid mappings/protocols, and port forms it cannot safely audit. Warnings deliberately fail the audit. The tool only reads its input: it never contacts Docker, starts containers, reads `.env`, changes configuration, or opens network listeners.

The implementation passed independent security/correctness review within its documented static-audit scope. Unsupported or ambiguous inputs fail closed rather than receiving deployment approval.

## Requirements and installation

- Git for cloning/updating.
- Node.js 20 or newer and npm.
- Linux test runs additionally require `mkfifo` (normally provided by coreutils) for the local, temporary FIFO regression. Other platforms skip that Linux-specific test.
- No Docker, root permissions, global npm installation, or running server is required.

Clone and install with:

```sh
git clone https://github.com/KamiBuilds/compose-port-audit.git
cd compose-port-audit
npm ci
node src/cli.js examples/clean.compose.yml
npm test
```

For an existing local copy, start at `npm ci`. All examples run from the repository directory. Run the included CLI directly; no global npm package installation is required.

## Run

```text
node src/cli.js [--json] <compose.yml>
```

Human-readable findings (intentionally exits 1):

```sh
node src/cli.js examples/risky.compose.yml
```

Machine-readable findings (also exits 1):

```sh
node src/cli.js --json examples/risky.compose.yml
```

Inherited YAML ports (exits 1) and a clean mapping (exits 0):

```sh
node src/cli.js examples/inherited.compose.yml
node src/cli.js examples/clean.compose.yml
```

Human output escapes untrusted control characters, line breaks, and bidirectional formatting controls as visible `\uXXXX` sequences, including in file paths and errors. JSON output escapes terminal controls while preserving original values when parsed.

### Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Audit completed with no port findings within the supported static model |
| 1 | One or more warnings or errors: risky, invalid, conflicting, or unsupported port mappings |
| 2 | Invalid arguments, unreadable/non-regular input, invalid YAML/Compose containers, unresolved interpolation, unsupported composition/networking, or resource limits |

In JSON mode, completed audits write `{ "file": "...", "findings": [...] }` to stdout. Input/usage failures write an escaped diagnostic to stderr, leave stdout empty, and exit 2. An error is never a clean audit.

## Supported forms and fail-closed behavior

Explicit short syntax:

```yaml
services:
  app:
    ports:
      - "127.0.0.1:8080:80"
      - "[::1]:8081:80"
      - "127.0.0.1:5353:53/udp"
```

Explicit long syntax:

```yaml
services:
  app:
    ports:
      - target: 80
        published: "8080"
        host_ip: 127.0.0.1
        protocol: tcp
```

Ports must be decimal values in 1–65535, and host IPs must be literal IPv4/IPv6 addresses. Brackets are allowed only as a single matched pair around an IPv6 literal; short-syntax IPv6 requires brackets, while long `host_ip` accepts bare or bracketed IPv6. Unmatched/nested brackets and bracketed IPv4 are invalid, not silently repaired. An omitted host IP is treated conservatively as all-interface exposure. `tcp`, `udp`, and `sctp` are recognized. Long-syntax `name`, `app_protocol`, and `mode` metadata are validated but do not change collision checks; unknown non-extension port fields produce an error finding.

- **Automatic host allocation:** `ports: [80]`, `"80"`, `"53/udp"`, a long mapping without `published`, and long `published: 0` are **not internal-only ports**. They can publish on automatically allocated host ports. They produce an `EPHEMERAL_PORT` error because runtime exposure/conflicts cannot be established. Specify an explicit host port and IP instead. Short `0:80` is also rejected, never ignored.
- **Port ranges:** reported as `UNSUPPORTED_PORT_RANGE`; list explicit mappings instead.
- **Malformed entries:** nulls, arrays, booleans, missing targets, invalid IPs/values, and unknown long-syntax fields produce `INVALID_PORT_MAPPING`, not a silent skip.
- **Interpolation:** unresolved `$VAR` and `${...}` in YAML values are input errors, even when a default currently looks safe or the variable appears outside `ports`. The CLI does not consult the current environment or `.env`. Audit a fully resolved file prepared by your trusted deployment tooling. Compose `$$` literals are allowed, but must still form valid port values if used in a mapping.
- **YAML inheritance:** ordinary anchors, aliases, and `<<` merge keys are supported, including explicit merge overrides. The resolved inherited ports are audited. Only core YAML tags (`!!map`, `!!seq`, `!!str`, `!!int`, `!!float`, `!!bool`, `!!null`) and merge keys are accepted. Recognized non-core representations such as `!!omap`, `!!set`, `!!timestamp`, `!!pairs`, and `!!binary` are rejected before conversion, even in extension fields. Non-plain converted objects (including implicit YAML 1.1 dates) are also rejected before enumeration. Duplicate YAML keys, custom tags (including `!reset`/`!override`), cyclic aliases, and non-string mapping keys are rejected.
- **YAML numeric schema limitation:** legacy leading-zero integer spellings such as unquoted `01777` or `02000` can mean decimal to JavaScript YAML core but octal to Compose's Go YAML loader. These spellings are rejected in the YAML AST before conversion, throughout the document (including `target`, `published`, extension fields, and anchor/merge sources), with an input error and exit 2. Signed, zero-padded, and underscore variants are also refused. Explicit numeric tags do not make these safe: `!!int 01777` and even `!!int "01777"` are rejected. Use unpadded decimal integers or actual strings: `"01777"`, `'01777'`, and `!!str 01777` remain decimal port strings, not octal integers. Ordinary `0` still produces the existing automatic-allocation finding when used as `published`. This restriction is fail-closed, not a claim that all YAML numeric schemas are interchangeable.
- **Document structure:** the root and `services` must be plain mappings, each service must be a plain mapping, and a present `ports` field must be a sequence. `services: {}` is accepted as an empty audit; a missing `services` field is not.
- **External composition:** `include` and service `extends` are refused. Combine these through trusted tooling first. Host/container/service-shared or unknown `network_mode` values are refused; only omitted, `bridge`, `none`, and `default` modes are accepted.
- **Network attachments:** ordinary declared bridge networks (omitted driver or `driver: bridge`, with omitted `external` or `external: false`) are supported, including null/empty definitions, service sequences/mappings, and YAML merges. Omitted/null/empty service `networks` is checked against the implicit `default` network. Attached `driver: host` or engine `name: host` networks are refused: applications may bind directly on the host without any `ports` entry. All external attachments are refused, even if a name or declared driver looks safe, because the actual network driver cannot be established without runtime inspection. Undeclared attachments (except the implicit bridge `default`), non-bridge drivers, malformed network containers, and combining `networks` with `network_mode` are also refused. Unused host/external network declarations do not imply an attachment and are not exposure findings. Explicit accepted `network_mode` values bypass Compose network attachments; an ordinary declared bridge with logical key `host` is not confused with the host driver.
- **Internal exposure:** `expose` is not host publication and is outside this port audit.

### Resource limits and scope

Input is limited to a regular file of at most 1 MiB, 10,000 YAML nodes, nesting depth 64, 100 alias references, the YAML library's alias-expansion limit of 100, and 1,000 port mappings across services (including inherited/reused sequences). Limit violations exit 2. CLI reads are bounded even if a file grows, and Linux FIFO input is opened nonblocking and refused.

This is a static port audit, not a complete Compose schema validator, firewall inspection, deployment approval, or proof of network isolation. It does not inspect existing host listeners, external network drivers, other projects/files, image internals, runtime-assigned ports, Swarm scheduling, host-specific dual-stack behavior, or firewall rules. Host, external, and non-bridge network attachments are excluded by input errors rather than reported clean; runtime network inspection is deliberately unavailable. Collision checks compare explicit IPv4/IPv6 families separately; an omitted wildcard IP overlaps both. All-interface bindings always warn regardless of host configuration. Profiles do not suppress audits: every listed service is checked.

## Tests and local gates

```sh
npm ci
npm test
npm run check
npm audit --omit=dev
```

The Node test suite uses local fixtures and temporary files only, including malformed/interpolated/oversized input, aliases, inherited ports, control-character output, CLI exit codes, and a Linux FIFO. It never uses Docker or real server operations.

On a POSIX shell, exercise both output formats and expected failing audits without masking unexpected exit codes:

```sh
node src/cli.js examples/risky.compose.yml || test $? -eq 1
node src/cli.js --json examples/risky.compose.yml > compose-port-audit-report.json || test $? -eq 1
node src/cli.js examples/inherited.compose.yml || test $? -eq 1
node src/cli.js examples/clean.compose.yml
rm compose-port-audit-report.json
```

Windows users can run each `node` command separately and check `$LASTEXITCODE` in PowerShell. The JSON report is disposable; no report is written unless you explicitly redirect stdout.

No GitHub Actions workflow is included: the available publication credential lacks workflow scope. The commands above are local gates, not a claim of remote CI execution. A future CI job can run `npm ci`, `npm test`, `npm run check`, and `node src/cli.js --json compose.yml`; the last step should fail for any finding.

## Update

From a clean clone:

```sh
git pull --ff-only
npm ci
npm test
npm run check
```

Do not overwrite locally modified Compose files when updating.

## Uninstall and cleanup

There is no global package, daemon, Docker change, or external configuration to uninstall. To remove installed dependencies from inside the clone (cross-platform Node command):

```sh
node --input-type=module -e "import { rmSync } from 'node:fs'; rmSync('node_modules', { recursive: true, force: true });"
```

Delete any explicitly saved reports with your file manager. To remove the tool entirely, leave the repository directory and delete only that clone with your file manager, after preserving your own Compose files or other local work. Reinstall dependencies with `npm ci` if keeping the clone.

## Platform support

| Platform | Evidence |
| --- | --- |
| Linux x86_64, Node.js 24.20.0 / npm 11.19.0 | Live-tested local install, tests, syntax checks, and CLI flows |
| Linux ARM64, Node.js 20/22/24 | Designed for cross-platform Node APIs; not live-tested |
| macOS, Node.js 20+ | Designed; not live-tested; Linux FIFO test is skipped |
| Windows, Node.js 20+ | Designed; not live-tested; Linux FIFO test is skipped |

Other Node versions, operating systems, CPUs, Docker engines, and CI environments are not verified by this repair.

## License

MIT
