#!/usr/bin/env bash
set -euo pipefail

node --input-type=module <<'NODE'
const CREDENTIAL_PATTERNS = [
  { type: 'AWS access key', regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { type: 'OpenAI API key', regex: /\bsk-[A-Za-z0-9-]{48,}\b/g },
  { type: 'GitHub personal access token', regex: /\bghp_[A-Za-z0-9]{36}\b/g },
  { type: 'GitHub fine-grained token', regex: /\bgithub_pat_[A-Za-z0-9_\-]+\b/g },
  { type: 'Bearer token', regex: /\bBearer\s+[A-Za-z0-9._~+\-/=]{20,}\b/g },
  { type: 'OpenRouter key', regex: /\bsk-or-[A-Za-z0-9-]+\b/g },
  { type: 'Anthropic API key', regex: /\bsk-ant-[A-Za-z0-9-]+\b/g },
  { type: 'Environment variable credential leak', regex: /\b(?:export\s+)?[A-Z][A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD)\s*=\s*["']?[A-Za-z0-9._\-/+=]{12,}["']?/g },
  { type: 'Telegram bot token', regex: /\b\d{6,}:[A-Za-z0-9_-]{20,}\b/g },
];

function stripCodeFences(text) {
  return text.replace(/```[\s\S]*?```/g, ' ');
}

function shannonEntropy(input) {
  if (!input) return 0;
  const counts = new Map();
  for (const ch of input) counts.set(ch, (counts.get(ch) || 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isKnownSafeToken(token) {
  return /^[a-f0-9]{32}$/i.test(token)
    || /^[a-f0-9]{64}$/i.test(token)
    || /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(token)
    || /^https?:\/\//i.test(token)
    || /^(\/|~\/|\.\/)/.test(token);
}

function scanForCredentials(text) {
  const results = [];
  const normalized = stripCodeFences(text);

  for (const { type, regex } of CREDENTIAL_PATTERNS) {
    regex.lastIndex = 0;
    let match = regex.exec(normalized);
    while (match) {
      results.push({ type, value: match[0], method: 'regex' });
      match = regex.exec(normalized);
    }
  }

  const tokens = normalized.split(/\s+/).filter((token) => token.length >= 20);
  for (const token of tokens) {
    const trimmed = token.replace(/^["'`([{]+|["'`.,;:!?)}\]]+$/g, '');
    if (trimmed.length < 20 || isKnownSafeToken(trimmed)) continue;
    if (results.some((item) => item.method === 'regex' && item.value.includes(trimmed))) continue;
    if (shannonEntropy(trimmed) > 4.5) {
      results.push({ type: 'High-entropy secret-like token', value: trimmed, method: 'entropy' });
    }
  }

  return results;
}

const tests = [
  { text: 'Here is the key: AKIAIOSFODNN7EXAMPLE', expected: 'CRITICAL', note: 'detected AWS access key' },
  { text: 'Use sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234', expected: 'CRITICAL', note: 'detected OpenAI key' },
  { text: 'Token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789', expected: 'CRITICAL', note: 'detected GitHub PAT' },
  { text: 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWI', expected: 'CRITICAL', note: 'detected Bearer token' },
  { text: 'export OPENAI_API_KEY=sk-proj-somethinglong1234567890abcdef12345678', expected: 'CRITICAL', note: 'detected env var leak' },
  { text: 'Bot token is 123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234567', expected: 'CRITICAL', note: 'detected Telegram bot token' },
  { text: 'sk-or-v1-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz', expected: 'CRITICAL', note: 'detected OpenRouter key' },
  { text: 'sk-ant-api03-abc123def456ghi789jkl012mno345pqr678stu901vwx', expected: 'CRITICAL', note: 'detected Anthropic key' },
  { text: 'github_pat_11ABCDE2F3gHiJkLmNoPq_R4sTuVwXyZ5678abcdefghijklmnop', expected: 'CRITICAL', note: 'detected GitHub fine-grained token' },
  { text: 'OPENAI_API_KEY=sk-proj-test1234567890abcdef1234567890abcdef12345678', expected: 'CRITICAL', note: 'detected env var without export' },
  { text: 'The SHA-256 hash is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', expected: 'CLEAN', note: 'no credentials' },
  { text: 'Check https://api.openai.com/v1/models for the full list', expected: 'CLEAN', note: 'no credentials' },
  { text: 'The file is at /home/openclaw/.openclaw/workspace/send-to-telegram.sh', expected: 'CLEAN', note: 'no credentials' },
  { text: 'Request ID: 550e8400-e29b-41d4-a716-446655440000', expected: 'CLEAN', note: 'no credentials' },
  { text: 'Here is some normal English text that should not trigger any alerts whatsoever', expected: 'CLEAN', note: 'no credentials' },
  { text: '```\nconst data = Buffer.from(largePayload).toString(\'base64\');\n```', expected: 'CLEAN', note: 'no credentials' },
  { text: 'The meeting is at 3pm tomorrow, reference number TXN-2026-0228-ABCDEF', expected: 'CLEAN', note: 'no credentials' },
  { text: 'Adam\'s phone number is +1-555-123-4567', expected: 'CLEAN', note: 'no credentials' },
  { text: 'The error code is ERR_CONNECTION_REFUSED_TIMEOUT_EXCEEDED', expected: 'CLEAN', note: 'no credentials' },
  { text: 'Version 2026.2.28-beta.1-rc.3-build.4567890123', expected: 'CLEAN', note: 'no credentials' },
  { text: 'The token is xyzQ8mK3pL9wR2vN5jH7tF0aB6cD4eG1iU8oYs', expected: 'WARNING', note: 'entropy flag only' },
  { text: 'Config value: aB3cD5eF7gH9iJ1kL3mN5oP7qR9sT1uV3wX5yZ', expected: 'WARNING', note: 'entropy flag only' },
];

function classify(text) {
  const detections = scanForCredentials(text);
  if (detections.some((item) => item.method === 'regex')) return 'CRITICAL';
  if (detections.some((item) => item.method === 'entropy')) return 'WARNING';
  return 'CLEAN';
}

let passed = 0;
let failed = 0;

for (let i = 0; i < tests.length; i += 1) {
  const test = tests[i];
  const actual = classify(test.text);
  const ok = actual === test.expected;

  if (ok) passed += 1;
  else failed += 1;

  const prefix = ok ? 'PASS' : 'FAIL';
  console.log(`${prefix} [${test.expected}]  Test ${i + 1}: "${test.text.slice(0, 36)}${test.text.length > 36 ? '...' : ''}"  → ${test.note}`);
  if (!ok) console.log(`  expected=${test.expected} actual=${actual}`);
}

console.log(`\nResults: ${passed}/${tests.length} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
NODE
