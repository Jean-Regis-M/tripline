import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectSecrets, luhn, ibanValid, type SecretKind } from '../src/detect.ts';
import { b64 } from '../src/util.ts';

// Every value below is synthetic or a published documentation example. None is a live credential.
const SAMPLES: Record<string, string> = {
  'aws-access-key': 'AKIAIOSFODNN7EXAMPLE',
  'aws-secret-key': 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  'github-token': 'ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8',
  'google-api-key': 'AIza' + 'SyA-1234567890abcdefghijklmnopqrstu',
  'slack-token': 'xoxb-123456789012-abcdefghijkl',
  'stripe-key': 'sk_live_Zq81xLm4PqRt7uVw',
  'jwt': 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop',
  'private-key': '-----BEGIN OPENSSH PRIVATE KEY-----',
  'credit-card': '4111 1111 1111 1111',
  'us-ssn': '123-45-6789',
  'iban': 'GB82 WEST 1234 5698 7654 32',
  'bearer-token': 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345',
  'connection-string': 'postgres://admin:hunter2pass@db.internal/prod',
};

test('detects every supported kind of secret on its own', () => {
  for (const [kind, text] of Object.entries(SAMPLES)) {
    const kinds = detectSecrets(`please store this: ${text} thanks`).map((f) => f.kind);
    assert.ok(kinds.includes(kind as SecretKind), `${kind} not detected in: ${text}`);
  }
});

test('detects many different kinds in ONE payload at the same time', () => {
  const payload = Object.values(SAMPLES).join('\n');
  const kinds = new Set(detectSecrets(payload).map((f) => f.kind));
  for (const kind of Object.keys(SAMPLES)) assert.ok(kinds.has(kind as SecretKind), `${kind} missing from the mixed payload`);
  assert.ok(kinds.size >= Object.keys(SAMPLES).length);
});

test('finds secrets hidden inside base64, hex and percent encoding without any provenance', () => {
  const key = SAMPLES['stripe-key'];
  assert.ok(detectSecrets(`data=${b64(key)}`).some((f) => f.kind === 'stripe-key' && f.encoded === 'base64'));
  assert.ok(detectSecrets(`data=${Buffer.from(key).toString('hex')}`).some((f) => f.kind === 'stripe-key' && f.encoded === 'hex'));
  assert.ok(detectSecrets(`data=${encodeURIComponent('xoxb-123456789012-abcdefghijkl')}`).some((f) => f.kind === 'slack-token'));
  assert.ok(detectSecrets(b64(SAMPLES['private-key'] + '\nMIIEvQ')).some((f) => f.kind === 'private-key'));
});

test('an encoded secret is reported as the secret, not as a vague high entropy blob, and conclusive findings come first', () => {
  const f = detectSecrets('backup=' + b64('stripe: sk_live_Zq81xLm4PqRt7uVw'));
  assert.equal(f[0].kind, 'stripe-key');
  assert.equal(f[0].encoded, 'base64');
  assert.ok(!f.some((x) => x.kind === 'high-entropy-token'));
});

test('a secret that a conclusive rule explains is not also reported as a vague high entropy blob', () => {
  const kinds = detectSecrets(Object.values(SAMPLES).join('\n')).map((f) => f.kind);
  assert.ok(!kinds.includes('high-entropy-token'), 'no duplicate vague findings');
  assert.equal(new Set(kinds).size, Object.keys(SAMPLES).length, 'one finding per kind, 13 kinds in the mixed payload');
});

test('validators reject look-alikes: bad Luhn, bad IBAN checksum, impossible SSNs, plain prose', () => {
  assert.ok(luhn('4111111111111111') && !luhn('4111111111111112'));
  assert.ok(ibanValid('GB82WEST12345698765432') && !ibanValid('GB82WEST12345698765433'));
  const none = detectSecrets('Order 4111 1111 1111 1112 shipped. Call 000-12-3456 or 666-12-3456. GB82 WEST 1234 5698 7654 33. Meeting on friday about the thesis.');
  assert.deepEqual(none.map((f) => f.kind), [], 'no false findings on near misses');
});

test('ordinary text, code and hashes do not look like definite secrets', () => {
  const benign = [
    'Summary: exam timetable update; IT notice. See you in January.',
    'function add(a, b) { return a + b; } // returns the sum',
    'commit 9fceb02d0ae598e95dc970b74767f19372d61af8 fixes the layout bug',
    'The quick brown fox jumps over the lazy dog 1234567890 times.',
    'https://github.com/Jean-Regis-M/tripline/blob/main/README.md',
  ];
  for (const text of benign) assert.deepEqual(detectSecrets(text).filter((f) => f.definite), [], text);
});

test('findings never contain the full secret', () => {
  for (const text of Object.values(SAMPLES)) for (const f of detectSecrets(text)) assert.ok(f.sample.length < 24 && f.sample !== text, `sample too revealing: ${f.sample}`);
});
