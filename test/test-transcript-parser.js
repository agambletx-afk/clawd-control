import { readFileSync } from 'fs';
import { join } from 'path';
import { parseTranscriptContent } from '../lib/session-transcript-parser.mjs';

const fixturesDir = join(process.cwd(), 'test', 'fixtures', 'transcripts');

function runFixture(name, checks, opts = {}) {
  const content = readFileSync(join(fixturesDir, name), 'utf8');
  const result = parseTranscriptContent(content, opts);
  for (const check of checks) {
    if (!check(result)) {
      throw new Error(`Fixture ${name} failed: ${check.name || 'anonymous check'}`);
    }
  }
  console.log(`PASS ${name}`);
}

try {
  runFixture('normal-linear.jsonl', [
    function count(r) { return r.entries.length === 11; },
    function hasTool(r) { return r.entries.some((e) => e.type === 'tool_call'); },
    function status(r) { return r.transcriptStatus === 'available'; },
  ]);

  runFixture('tool-heavy.jsonl', [
    function count(r) { return r.entries.length === 18; },
    function toolCallCount(r) { return r.entries.filter((e) => e.type === 'tool_call').length >= 4; },
    function toolResultCount(r) { return r.entries.filter((e) => e.type === 'tool_result').length >= 4; },
  ]);

  runFixture('with-compaction.jsonl', [
    function hasCompaction(r) { return r.entries.some((e) => e.type === 'compaction'); },
    function hasSystem(r) { return r.entries.some((e) => e.type === 'system_internal'); },
  ]);

  runFixture('with-branches.jsonl', [
    function hasBranch(r) { return r.entries.some((e) => e.type === 'branch_summary'); },
    function branchDetected(r) { return r.branchDetected === true; },
  ]);

  runFixture('malformed-final-line.jsonl', [
    function noCorruption(r) { return r.corruptionCount === 0; },
    function keepsValid(r) { return r.entries.length === 5; },
    function liveStatus(r) { return r.transcriptStatus === 'live'; },
  ], { active: true });

  runFixture('malformed-interior-line.jsonl', [
    function hasCorruption(r) { return r.corruptionCount === 1; },
    function markerPresent(r) { return r.entries.some((e) => e.type === 'corruption'); },
  ]);

  console.log('All transcript parser tests passed.');
  process.exit(0);
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
