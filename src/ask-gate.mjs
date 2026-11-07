#!/usr/bin/env node
// Stops a question reaching the user unless it says why only they can answer it.
// In the app: nothing at runtime; Claude Code runs it before AskUserQuestion and the desktop app's wrap-up box.
// Used by: the agent's hook config (PreToolUse); tested by test/ask-gate.test.mjs.
// Uses: Node builtins; reads the hook's JSON on stdin.
// Run: not by hand. Claude Code pipes each matching tool call to it.
// When: before a tool that asks the user something. A question in plain chat text doesn't pass through it.
// Env: WHIPPLETREE_ASK_GATE (`off` and `log` both record and allow; default enforces).
// Writes: one line per question to ~/.whippletree/asks.jsonl (time, project, tag, question), so the count can be watched.
// Exit: 0 allowed; 2 refused, with the reason on stderr for the agent.
//
// Why a gate and not only a rule: users often click the recommended option without reading, so a
// question must say why it needs a human.
// The tag is the agent's own claim, so this is friction and a record, not proof; the record is how
// a bad pattern shows up.

import { appendFileSync, mkdirSync, readFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { pathToFileURL } from "node:url";

// Knob: the reasons a question may reach the user.
export const TAGS = ["irreversible", "only-you", "your-rule"];
const LOG_DIR = join(homedir(), ".whippletree");
const LOG_NAME = "asks.jsonl";

const REFUSAL = `Don't ask yet. Weigh the options and take the clear best one, saying what you chose. Only a question that is truly [irreversible], [only-you], or [your-rule] reaches the user: start it with that tag.`;

// The questions in one tool call's input: AskUserQuestion's list, or the wrap-up box's `ask`.
export const questionsIn = (input) => {
  if (Array.isArray(input?.questions)) return input.questions.map((each) => String(each?.question ?? ""));
  if (typeof input?.ask === "string" && input.ask.trim() !== "") return [input.ask];
  // Buttons with no question still put a choice in front of the user.
  return Array.isArray(input?.actions) && input.actions.length > 0 ? [""] : [];
};

// The tag a question opens with, or null.
export const tagOf = (question) => TAGS.find((tag) => question.trimStart().startsWith(`[${tag}]`)) ?? null;

// Returns { code, reason? } for one hook payload, and records each question through `record`.
export const judge = (payload, { mode = "enforce", record = () => {} } = {}) => {
  const questions = questionsIn(payload?.tool_input);
  const tags = questions.map(tagOf);
  questions.forEach((question, index) => record({ tag: tags[index], question: question.slice(0, 200) }));
  if (mode === "off" || mode === "log" || tags.every((tag) => tag !== null)) return { code: 0 };
  return { code: 2, reason: REFUSAL };
};

// The log is a convenience: failing to write it never blocks a question or an agent.
const appendRecord = (cwd, entry) => {
  try {
    mkdirSync(LOG_DIR, { recursive: true });
    appendFileSync(join(LOG_DIR, LOG_NAME), `${JSON.stringify({ at: new Date().toISOString(), project: basename(cwd), ...entry })}\n`, { mode: 0o600 });
  } catch {
    // Nothing to do: see above.
  }
};

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  let payload = null;
  try {
    payload = JSON.parse(readFileSync(0, "utf8"));
  } catch {
    // Unreadable input isn't a question this gate can judge: let it through.
    process.exit(0);
  }
  const mode = process.env.WHIPPLETREE_ASK_GATE ?? "enforce";
  const result = judge(payload, { mode, record: (entry) => appendRecord(payload?.cwd ?? process.cwd(), entry) });
  if (result.code !== 0) process.stderr.write(`${result.reason}\n`);
  process.exit(result.code);
}
