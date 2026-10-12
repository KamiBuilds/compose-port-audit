import { parseDocument, isMap, isSeq, isAlias, isScalar } from 'yaml';
import { isIP } from 'node:net';

const SUPPORTED_YAML_TAGS = new Set(
  ['map', 'seq', 'str', 'int', 'float', 'bool', 'null', 'merge'].map((name) => `tag:yaml.org,2002:${name}`),
);

function isMapping(value) {
  if (value === null || typeof value !== 'object') return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function normalizeHostIp(value) {
  if (value == null || value === '') return '*';
  const unwrapped = value.startsWith('[') ? value.slice(1, -1) : value;
  if (!unwrapped.includes(':')) return unwrapped;
  return new URL(`http://[${unwrapped}]/`).hostname.slice(1, -1);
}

function addressesOverlap(left, right) {
  if (left === right || left === '*' || right === '*') return true;
  const leftFamily = left.includes(':') ? 6 : 4;
  const rightFamily = right.includes(':') ? 6 : 4;
  if (leftFamily !== rightFamily) return false;
  return left === '0.0.0.0' || right === '0.0.0.0' || left === '::' || right === '::';
}

function checkNetworkAttachments(networks, service, definition) {
  const unsupported = (reason) => {
    throw new Error(`Unsupported Compose networking in service "${service}": ${reason}; bindings cannot be determined statically`);
  };
  if ('network_mode' in definition) {
    if ('networks' in definition) unsupported('networks and network_mode cannot be combined');
    return;
  }
  const attachments = definition.networks;
  let names;
  if (attachments == null) {
    names = ['default'];
  } else if (Array.isArray(attachments)) {
    if (attachments.some((name) => typeof name !== 'string' || name === '')) unsupported('network references must be names');
    names = attachments;
  } else if (isMapping(attachments)) {
    if (Object.values(attachments).some((value) => value !== null && !isMapping(value))) {
      unsupported('network attachment options must be mappings or null');
    }
    names = Object.keys(attachments);
  } else {
    unsupported('networks must be a sequence or mapping');
  }
  if (names.length === 0) names = ['default'];
  for (const name of names) {
    if (!Object.hasOwn(networks, name) && name !== 'default') unsupported(`undeclared network "${name}"`);
    const network = Object.hasOwn(networks, name) ? networks[name] ?? {} : {};
    if (network.driver === 'host' || network.name === 'host') unsupported(`host network "${name}"`);
    if ('external' in network && network.external !== false) unsupported(`external network "${name}" requires runtime inspection`);
    if ('driver' in network && network.driver !== 'bridge') unsupported(`unsupported driver for network "${name}"`);
    if ('name' in network && (typeof network.name !== 'string' || network.name === '')) unsupported(`invalid name for network "${name}"`);
  }
}

function parsePort(value) {
  const invalid = {
    issueCode: 'INVALID_PORT_MAPPING',
    issueMessage: 'Malformed port mapping: use decimal ports from 1 through 65535, a literal IP, and valid long-syntax fields',
  };
  const ephemeral = {
    issueCode: 'EPHEMERAL_PORT',
    issueMessage: 'Automatically allocated host port cannot be checked for conflicts and may publish on all interfaces; specify an explicit host port and IP',
  };
  const range = {
    issueCode: 'UNSUPPORTED_PORT_RANGE',
    issueMessage: 'Port ranges are not supported; list each published port explicitly',
  };
  const decimal = (port) => (typeof port === 'string' || typeof port === 'number') && /^\d+$/.test(String(port));
  const validPort = (port) => decimal(port) && Number(port) >= 1 && Number(port) <= 65535;
  const validIp = (ip) => {
    if (typeof ip !== 'string') return false;
    if (ip.includes('[') || ip.includes(']')) {
      return /^\[[^\[\]]+\]$/.test(ip) && isIP(ip.slice(1, -1)) === 6;
    }
    return isIP(ip) !== 0;
  };
  if (isMapping(value)) {
    const allowed = ['target', 'published', 'host_ip', 'protocol', 'app_protocol', 'mode', 'name'];
    if (Object.keys(value).some((key) => !allowed.includes(key) && !key.startsWith('x-')) ||
        !('target' in value) ||
        ('host_ip' in value && !validIp(value.host_ip)) ||
        ['protocol', 'app_protocol', 'name'].some((key) => key in value && typeof value[key] !== 'string') ||
        ('mode' in value && !['host', 'ingress'].includes(value.mode))) return invalid;
    if (/^\d+-\d+$/.test(String(value.published)) || /^\d+-\d+$/.test(String(value.target))) return range;
    if (!validPort(value.target)) return invalid;
    if (!('published' in value) || value.published === 0 || value.published === '0') return ephemeral;
    if (!validPort(value.published)) return invalid;
    return {
      hostIp: normalizeHostIp(value.host_ip),
      hostPort: Number(value.published),
      containerPort: Number(value.target),
      protocol: (value.protocol ?? 'tcp').toLowerCase(),
    };
  }
  if (typeof value !== 'string' && typeof value !== 'number') return invalid;
  const text = String(value);
  if (/\d+-\d+/.test(text)) return range;
  const single = text.match(/^(\d+)(?:\/([a-z][a-z0-9]*))?$/i);
  if (single) return validPort(single[1]) ? ephemeral : invalid;
  const match = text.match(/^(?:(\[[^\]]+\]|[^:]+):)?(\d+):(\d+)(?:\/([a-z][a-z0-9]*))?$/i);
  if (!match || !validPort(match[2]) || !validPort(match[3]) || (match[1] && !validIp(match[1]))) return invalid;
  return {
    hostIp: normalizeHostIp(match[1]),
    hostPort: Number(match[2]),
    containerPort: Number(match[3]),
    protocol: (match[4] ?? 'tcp').toLowerCase(),
  };
}

export const MAX_SOURCE_BYTES = 1024 * 1024;

export function auditCompose(source) {
  if (typeof source !== 'string' || Buffer.byteLength(source, 'utf8') > MAX_SOURCE_BYTES) {
    throw new Error('Input limit: expected a YAML string of at most 1 MiB');
  }
  const document = parseDocument(source, { merge: true, prettyErrors: true, uniqueKeys: true });
  if (document.errors.length > 0) {
    throw new Error(document.errors.map((error) => error.message).join('\n'));
  }

  if (document.warnings.length > 0) {
    throw new Error('Unsupported YAML constructs: resolve parser warnings and custom tags before auditing');
  }
  const nodes = [{ node: document.contents, depth: 0 }];
  let nodeCount = 0;
  let aliasCount = 0;
  while (nodes.length) {
    const { node, depth } = nodes.pop();
    if (++nodeCount > 10000) throw new Error('YAML node limit: maximum is 10000');
    if (isAlias(node) && ++aliasCount > 100) throw new Error('YAML alias limit: maximum is 100 references');
    if (depth > 64) throw new Error('YAML nesting limit: maximum depth is 64');
    if (node?.tag && !SUPPORTED_YAML_TAGS.has(node.tag)) {
      throw new Error('Unsupported YAML tag: only core values and ordinary merge keys are supported');
    }
    // Compose's Go YAML loader may read legacy leading-zero integers as octal.
    // Check scalar spelling before toJS erases it, without rejecting real strings.
    if (isScalar(node) && /^[+-]?0[0-9_]+$/.test(node.source ?? '') &&
        (typeof node.value === 'number' ||
         (node.type === 'PLAIN' && node.tag !== 'tag:yaml.org,2002:str'))) {
      throw new Error('Ambiguous YAML integer: leading-zero spellings are unsupported; use an unambiguous decimal integer or a quoted string without a numeric tag');
    }
    if (isMap(node)) {
      for (const pair of node.items) {
        const mergeKey = isScalar(pair.key) && typeof pair.key.value === 'symbol' && pair.key.value.description === '<<';
        if (!isScalar(pair.key) || (typeof pair.key.value !== 'string' && !mergeKey)) {
          throw new Error('Compose YAML mapping keys must be strings (YAML merge keys are supported)');
        }
        nodes.push({ node: pair.key, depth: depth + 1 }, { node: pair.value, depth: depth + 1 });
      }
    } else if (isSeq(node)) {
      for (const item of node.items) nodes.push({ node: item, depth: depth + 1 });
    }
  }
  const compose = document.toJS({ maxAliasCount: 100 });
  const pending = [{ value: compose, leaving: false }];
  const seen = new Set();
  const active = new Set();
  while (pending.length) {
    const { value, leaving } = pending.pop();
    if (leaving) { active.delete(value); continue; }
    if (typeof value === 'string' && /\$(?:[A-Za-z_]|\{)/.test(value.replace(/\$\$/g, ''))) {
      throw new Error('Unresolved Compose interpolation; audit fully resolved YAML without environment substitutions');
    }
    if (value && typeof value === 'object') {
      if (!Array.isArray(value) && !isMapping(value)) {
        throw new Error('Unsupported YAML representation: expected a plain mapping or sequence');
      }
      if (active.has(value)) throw new Error('Cyclic YAML alias is not supported');
      if (seen.has(value)) continue;
      seen.add(value);
      active.add(value);
      pending.push({ value, leaving: true });
      for (const child of Object.values(value)) pending.push({ value: child, leaving: false });
    }
  }
  if (!isMapping(compose) || !isMapping(compose.services)) {
    throw new Error('Invalid Compose structure: root and services must be mappings');
  }
  if ('include' in compose) throw new Error('Unsupported Compose include: audit a fully combined document');
  const networks = compose.networks ?? {};
  if (!isMapping(networks) || Object.values(networks).some((value) => value !== null && !isMapping(value))) {
    throw new Error('Invalid Compose structure: networks and their definitions must be mappings (network definitions may be null)');
  }
  let mappingCount = 0;
  for (const [service, definition] of Object.entries(compose.services)) {
    if (!isMapping(definition) || ('ports' in definition && !Array.isArray(definition.ports))) {
      throw new Error(`Invalid Compose structure: service "${service}" must be a mapping with a ports sequence when present`);
    }
    if ('extends' in definition || ('network_mode' in definition && !['bridge', 'none', 'default'].includes(definition.network_mode))) {
      throw new Error(`Unsupported Compose extends or network_mode in service "${service}": bindings cannot be determined statically`);
    }
    checkNetworkAttachments(networks, service, definition);
    mappingCount += definition.ports?.length ?? 0;
    if (mappingCount > 1000) throw new Error('Port mapping limit: maximum is 1000 across all services');
  }
  const findings = [];
  const published = [];

  for (const [service, definition] of Object.entries(compose.services)) {
    for (const value of definition.ports ?? []) {
      const port = parsePort(value);
      if (port.issueCode) {
        findings.push({
          code: port.issueCode,
          severity: 'error',
          message: `Service "${service}": ${port.issueMessage}`,
          service,
        });
        continue;
      }

      if (!['tcp', 'udp', 'sctp'].includes(port.protocol)) {
        findings.push({
          code: 'INVALID_PROTOCOL',
          severity: 'error',
          message: `Service "${service}" uses unsupported protocol "${port.protocol}"`,
          service,
          ...port,
        });
      }

      if (port.hostPort < 1024) {
        findings.push({
          code: 'PRIVILEGED_PORT',
          severity: 'warning',
          message: `Service "${service}" publishes privileged host port ${port.hostPort}`,
          service,
          ...port,
        });
      }

      if (port.hostIp === '*' || port.hostIp === '0.0.0.0' || port.hostIp === '::') {
        findings.push({
          code: 'PUBLIC_BINDING',
          severity: 'warning',
          message: `Service "${service}" publishes host port ${port.hostPort} on all interfaces`,
          service,
          ...port,
        });
      }

      const previous = published.findLast((entry) =>
        entry.hostPort === port.hostPort &&
        entry.protocol === port.protocol &&
        addressesOverlap(entry.hostIp, port.hostIp)
      );
      if (previous) {
        findings.push({
          code: 'DUPLICATE_HOST_PORT',
          severity: 'error',
          message: `Service "${service}" conflicts with "${previous.service}" on ${port.hostIp}:${port.hostPort}/${port.protocol}`,
          service,
          conflictsWith: previous.service,
          ...port,
        });
      }
      published.push({ service, ...port });
    }
  }
  return findings;
}
