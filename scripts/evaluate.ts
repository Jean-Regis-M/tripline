// Prints the scanner evaluation as markdown. Usage: npm run evaluate
import { evaluate } from '../test/corpus.ts';

const r = evaluate();
console.log('| Measure | Result |\n|---|---|');
console.log(`| Legitimate tools hard blocked (false positives) | ${r.benign.blocked} of ${r.benign.total} |`);
console.log(`| Legitimate tools sent to review | ${r.benign.review} of ${r.benign.total} (${r.benign.flagged.join(', ')}) |`);
console.log(`| Poisoned tools detected (block or review) | ${r.malicious.detected} of ${r.malicious.total} |`);
console.log(`| Poisoned tools hard blocked | ${r.malicious.blocked} of ${r.malicious.total} |`);
console.log(`| Known misses | ${r.malicious.missed.length} (${[...new Set(r.malicious.missed.map((m) => m.split('/')[0]))].join(', ')}) |`);
