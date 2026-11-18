import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluate } from './corpus.ts';

test('scanner corpus: no legitimate tool is blocked, known attack classes are all detected, misses are the documented ones', () => {
  const r = evaluate();
  assert.equal(r.benign.blocked, 0, `false positive blocks: ${r.benign.flagged.join(', ')}`);
  assert.ok(r.benign.review <= 3, 'review prompts on legitimate tools should stay rare');
  assert.equal(r.attackClassesCovered.detected, r.attackClassesCovered.total);
  assert.ok(r.malicious.blocked / r.malicious.total >= 0.65, 'most poisoned tools should be hard blocked, not just reviewed');
  assert.deepEqual(r.malicious.missed.map((m) => m.split('/')[0]), ['euphemism', 'euphemism', 'euphemism'], 'the only misses are the documented euphemism evasions');
});
