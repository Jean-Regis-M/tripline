// Stand in for a human approver. Exit code 0 approves, anything else denies.
// TRIPLINE_APPROVE_RESULT=yes|no|crash decides the answer; the environment variables Tripline passes are validated.
import { writeFileSync } from 'node:fs';

if (process.env.TRIPLINE_TOOL !== 'send_email') process.exit(3);
if (!/R2/.test(process.env.TRIPLINE_RULES ?? '')) process.exit(4);
if (!/elsewhere\.test/.test(process.env.TRIPLINE_ARGS ?? '')) process.exit(5);
if (process.env.TRIPLINE_APPROVE_LOG) writeFileSync(process.env.TRIPLINE_APPROVE_LOG, `${process.env.TRIPLINE_TOOL} ${process.env.TRIPLINE_RULES}`);
const r = process.env.TRIPLINE_APPROVE_RESULT;
if (r === 'crash') throw new Error('approver crashed');
process.exit(r === 'yes' ? 0 : 1);
