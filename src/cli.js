#!/usr/bin/env node

import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { auditCompose, MAX_SOURCE_BYTES } from './audit.js';

async function readSource(file) {
  // Nonblocking open prevents a file-to-FIFO race from hanging the CLI.
  const handle = await open(file, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error('Input must be a regular file');
    if (stat.size > MAX_SOURCE_BYTES) throw new Error('Input limit: maximum file size is 1 MiB');
    const buffer = Buffer.alloc(MAX_SOURCE_BYTES + 1);
    let total = 0;
    while (total < buffer.length) {
      const { bytesRead } = await handle.read(buffer, total, buffer.length - total, null);
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    if (total > MAX_SOURCE_BYTES) throw new Error('Input limit: maximum file size is 1 MiB');
    return buffer.subarray(0, total).toString('utf8');
  } finally { await handle.close(); }
}

function escapeCharacter(character) {
  return `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`;
}

function terminalSafe(text) {
  return String(text).replace(/[\u0000-\u001f\u007f-\u009f\u2028-\u202e\u2066-\u2069]/g, escapeCharacter);
}

function usage() {
  return 'Usage: compose-port-audit [--json] <compose.yml>\n';
}

const args = process.argv.slice(2);
const json = args.includes('--json');
const files = args.filter((arg) => arg !== '--json');
if (files.length !== 1 || args.some((arg) => arg.startsWith('-') && arg !== '--json')) {
  process.stderr.write(usage());
  process.exitCode = 2;
} else {
  const file = files[0];
  try {
    const findings = auditCompose(await readSource(file));
    if (json) {
      const report = JSON.stringify({ file, findings }, null, 2)
        .replace(/[\u007f-\u009f\u2028-\u202e\u2066-\u2069]/g, escapeCharacter);
      process.stdout.write(`${report}\n`);
    } else if (findings.length === 0) {
      process.stdout.write(`${terminalSafe(file)}: no port issues found\n`);
    } else {
      for (const finding of findings) {
        process.stdout.write(`[${finding.severity.toUpperCase()}] ${finding.code} ${terminalSafe(finding.message)}\n`);
      }
      process.stdout.write(`${findings.length} finding(s) in ${terminalSafe(file)}\n`);
    }
    process.exitCode = findings.length === 0 ? 0 : 1;
  } catch (error) {
    process.stderr.write(`compose-port-audit: ${terminalSafe(error.message)}\n`);
    process.exitCode = 2;
  }
}
