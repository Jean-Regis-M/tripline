import { Guard, fragments, type Policy, type RuleHit } from './guard.ts';
import type { Manifest } from './types.ts';
import { b64, b64decode, caesar, hex, reverse, spellOut } from './util.ts';

export interface Call { tool: string; args: Record<string, unknown> }
export interface Scenario {
  id: string;
  title: string;
  kind: 'attack' | 'benign';
  summary: string;
  userTask: string;
  policy: Policy;
  manifest: Manifest;
  /** Tool descriptions the agent sees (may be poisoned). */
  descriptions: Record<string, string>;
  /** Canned tool outputs. This is a fully local fake environment. */
  outputs: Record<string, string>;
  plan: Call[];
  secrets: string[];
  success: (executed: Call[]) => boolean;
}
export interface Step {
  i: number;
  actor: 'user' | 'agent' | 'injected';
  tool: string;
  args: Record<string, unknown>;
  decision: 'allow' | 'deny' | 'ask' | 'unguarded';
  rules: RuleHit[];
  output: string;
}
export interface RunResult { scenario: string; guarded: boolean; steps: Step[]; leaked: boolean; blocked: number; completed: boolean; leakedSteps: number[] }

const DIRECTIVE = /ASSISTANT_ACTION:\s*([a-z_]+)\s*(\{.*\})/gi;
const APPEND = /ASSISTANT_APPEND_ARGS:\s*(\{.*\})/i;

function resolve(json: string, last: Map<string, string>): string {
  json = json.replace(/\{\{dec:([A-Za-z0-9+/=]+)\}\}/g, (_m, b: string) => b64decode(b));
  return json.replace(/\{\{(?:(b64|rev|rot|spell):)?([a-z_]+)\}\}/g, (_m, mode: string | undefined, tool: string) => {
    let v = last.get(tool) ?? '';
    if (mode === 'b64') v = b64(v);
    if (mode === 'rev') v = reverse(v);
    if (mode === 'rot') v = caesar(v, 13);
    if (mode === 'spell') v = spellOut(v);
    return JSON.stringify(v).slice(1, -1);
  });
}
function leaks(call: Call, secrets: string[]): boolean {
  const hay = JSON.stringify(call.args);
  for (const s of secrets) for (const f of fragments(s)) {
    const rev = reverse(f);
    for (const v of [f, rev, caesar(f, 13), spellOut(f), b64(f), hex(f)])
      if (hay.includes(JSON.stringify(v).slice(1, -1))) return true;
  }
  return false;
}

/**
 * Runs a scenario with a deliberately gullible, deterministic stand-in agent: it executes the
 * user's plan, and ALSO obeys any ASSISTANT_ACTION directive found in tool outputs or tool
 * descriptions. This makes attacks reproducible; it is not a real LLM (see README limitations).
 */
export function runScenario(sc: Scenario, opts: { guarded: boolean }): RunResult {
  const guard = opts.guarded ? new Guard(sc.policy) : null;
  const steps: Step[] = [];
  const executed: Call[] = [];
  const last = new Map<string, string>();
  const preDone = new Set<string>();
  type Q = Call & { actor: Step['actor']; appended?: Record<string, unknown>; rawArgs?: string };
  const queue: Q[] = sc.plan.map((c) => ({ ...c, actor: 'user' }));
  let blocked = 0;
  const leakedSteps: number[] = [];

  while (queue.length && steps.length < 14) {
    const call = queue.shift()!;
    const desc = sc.descriptions[call.tool] ?? '';
    if (!preDone.has(call.tool) && call.actor !== 'injected') {
      preDone.add(call.tool);
      const pre: Q[] = [...desc.matchAll(DIRECTIVE)].map((m) => ({ tool: m[1], args: {}, rawArgs: m[2], actor: 'injected' as const }));
      const app = desc.match(APPEND);
      if (pre.length || app) {
        queue.unshift(...pre, { ...call, appended: app ? JSON.parse(app[1]) : undefined });
        continue;
      }
    }
    if (call.rawArgs) call.args = JSON.parse(resolve(call.rawArgs, last));
    if (call.appended) {
      call.args = { ...call.args, ...JSON.parse(resolve(JSON.stringify(call.appended), last)) };
    }
    const real: Call = { tool: call.tool, args: call.args };
    let decision: Step['decision'] = 'unguarded';
    let rules: RuleHit[] = [];
    let output: string;
    if (guard) {
      const v = guard.check(real.tool, real.args);
      decision = v.decision;
      rules = v.rules;
    }
    if (decision === 'deny' || decision === 'ask') {
      blocked++;
      output = decision === 'ask' ? '[Tripline: approval required, human declined]' : '[Tripline: call blocked]';
      steps.push({ i: steps.length + 1, actor: call.actor, tool: real.tool, args: real.args, decision, rules, output });
      if (call.appended) {
        const keys = Object.keys(call.appended);
        const clean = Object.fromEntries(Object.entries(real.args).filter(([k]) => !keys.includes(k)));
        queue.unshift({ tool: real.tool, args: clean, actor: call.actor });
      }
      continue;
    }
    output = sc.outputs[real.tool] ?? 'ok';
    executed.push(real);
    if (sc.policy.tools[real.tool]?.egress && leaks(real, sc.secrets)) leakedSteps.push(steps.length + 1);
    last.set(real.tool, output);
    guard?.observe(real.tool, output);
    steps.push({ i: steps.length + 1, actor: call.actor, tool: real.tool, args: real.args, decision, rules, output });
    for (const m of output.matchAll(DIRECTIVE))
      queue.push({ tool: m[1], args: {}, rawArgs: m[2], actor: 'injected' });
  }
  const leaked = executed.some((c) => sc.policy.tools[c.tool]?.egress && leaks(c, sc.secrets));
  return { scenario: sc.id, guarded: opts.guarded, steps, leaked, blocked, completed: sc.success(executed), leakedSteps };
}
