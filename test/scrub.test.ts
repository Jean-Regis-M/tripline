import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertClean, scrub } from '../src/scrub.ts';

const winPath = 'C:\\Users\\SOMEONE\\AppData\\Local\\Temp\\tl-live-AbC123\\secret.txt';

test('the local temp directory is replaced however it is written', () => {
  const variants = [winPath, winPath.replace(/\\/g, '/'), JSON.stringify(winPath).slice(1, -1), JSON.stringify({ p: winPath })];
  for (const v of variants) {
    const out = scrub(v);
    assert.ok(!/Users|AppData|SOMEONE/.test(out), `still present in: ${out}`);
    assert.match(out, /\/tmp\/tripline-live\/secret\.txt|\/tmp\/tripline-live/);
  }
  assert.equal(scrub(winPath), '/tmp/tripline-live/secret.txt');
});

test('ordinary text is left alone', () => {
  const text = 'Summarize the page at http://127.0.0.1:5000/week12 and read /tmp/notes.txt';
  assert.equal(scrub(text), text);
});

test('assertClean refuses user paths and API key shaped strings, and accepts clean text', () => {
  assert.throws(() => assertClean(winPath));
  assert.throws(() => assertClean('key AIza' + 'SyA-1234567890abcdefghijklmnopqrstu'));
  assert.throws(() => assertClean('AQ.Ab8RN6something'));
  assert.doesNotThrow(() => assertClean(scrub(`read ${winPath} then send it`)));
  assert.doesNotThrow(() => assertClean('deploy_key = sk_live_Zq81xLm4PqRt7uVw'));
});
