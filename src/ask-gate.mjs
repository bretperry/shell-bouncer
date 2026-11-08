// Stops a question reaching the user unless it says why only they can answer it: the ask gate.
// In the app: nothing at runtime; Claude Code runs it (through `reins ask-gate`) before a tool that asks the user something.
// Used by: bin/reins.mjs (`reins ask-gate`), and a caller that imports `askGate` from the package; tested by test/ask-gate.test.mjs.
// Uses: Node builtins; the hook's JSON on stdin; the project's reins.json → askTags (through loadRules()).
// Run: not by hand. Claude Code pipes each matching tool call to `reins ask-gate`.
// When: before a tool that asks the user something. A question in plain chat text doesn't pass through it.
// Env: REINS_ASK_GATE or WHIPPLETREE_ASK_GATE (`off` and `log` both record and allow; default enforces; `offEnv` replaces the names); CLAUDE_PROJECT_DIR (the project root, when the caller names none).
// Writes: one line per question to askTags.log when set (time, project, tag, question), so the count can be watched.
// Exit: 0 allowed; 2 refused, with the reason on stderr for the agent.
//
// Off by default: with no `askTags` (the config's, or the caller's `tags`), every question passes.
// Why a gate and not only a rule: users often click the recommended option without reading, so a
// question must say why it needs a human.
// The tag is the agent's own claim, so this is friction and a record, not proof; the record is how
// a bad pattern shows up. It fails open: unreadable input, or a config that doesn't load, lets the
// question through, since a gate that wedges an agent's every question costs more than one untagged ask.

import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";

import { DEFAULT_FILES, loadRules } from "./guard.mjs";

// The mode switch's names: the first one set wins. The second is the name the gate had before it was a package.
export const DEFAULT_OFF_ENV = Object.freeze(["REINS_ASK_GATE", "WHIPPLETREE_ASK_GATE"]);

// What an untagged question gets, naming the tags.
export const refusalFor = (tags) => {
  const named = tags.map((tag) => `[${tag}]`);
  const list = named.length <= 1 ? named.join("") : `${named.slice(0, -1).join(", ")}, or ${named.at(-1)}`;
  return `Don't ask yet. Weigh the options and take the clear best one, saying what you chose. Only a question that is truly ${list} reaches the user: start it with that tag.`;
};

// The questions in one tool call's input: AskUserQuestion's list, or a wrap-up box's `ask`.
export const questionsIn = (input) => {
  if (Array.isArray(input?.questions)) return input.questions.map((each) => String(each?.question ?? ""));
  if (typeof input?.ask === "string" && input.ask.trim() !== "") return [input.ask];
  // Buttons with no question still put a choice in front of the user.
  return Array.isArray(input?.actions) && input.actions.length > 0 ? [""] : [];
};

// The tag a question opens with, out of `tags`, or null.
export const tagOf = (question, tags) => tags.find((tag) => question.trimStart().startsWith(`[${tag}]`)) ?? null;

// The mode the environment sets through `offEnv` (the first name set), or "enforce".
export const modeOf = (offEnv = DEFAULT_OFF_ENV) => offEnv.map((name) => process.env[name]).find((value) => value !== undefined && value !== "") ?? "enforce";

// Returns { code, reason? } for one hook payload, and records each question through `record`.
// `tags`: the reasons a question may reach the user; none (the default) lets every question pass.
// `mode`: "off" or "log" record and allow; default from `offEnv`. `tools`: the tool names judged
// (a payload naming another tool passes); null judges every one. `refusal`: the text an untagged
// question gets (refusalFor() by default).
export const judge = (payload, { mode, tags = [], offEnv = DEFAULT_OFF_ENV, tools = null, refusal, record = () => {} } = {}) => {
  if (tags.length === 0) return { code: 0 };
  const tool = payload?.tool_name;
  if (tools !== null && typeof tool === "string" && !tools.includes(tool)) return { code: 0 };
  const questions = questionsIn(payload?.tool_input);
  const found = questions.map((question) => tagOf(question, tags));
  questions.forEach((question, index) => record({ tag: found[index], question: question.slice(0, 200) }));
  const current = mode ?? modeOf(offEnv);
  if (current === "off" || current === "log" || found.every((tag) => tag !== null)) return { code: 0 };
  return { code: 2, reason: refusal ?? refusalFor(tags) };
};

// The log is a convenience: failing to write it never blocks a question or an agent.
const appendRecord = (log, cwd, entry) => {
  try {
    const path = log.startsWith("~/") ? join(homedir(), log.slice(2)) : log;
    mkdirSync(dirname(path), { recursive: true });
    appendFileSync(path, `${JSON.stringify({ at: new Date().toISOString(), project: basename(cwd), ...entry })}\n`, { mode: 0o600 });
  } catch {
    // Nothing to do: see above.
  }
};

// The hook entry: reads the payload on stdin (or `input`), judges it, and returns the exit code
// (0 or 2) for the caller to exit with. `askTags` ({ tags, refusal, tools, log }) replaces the
// config's; else they come from the config at `root` (`files` renames it). A relative `log` is
// read from the project root.
export const run = ({ root, files = {}, askTags, offEnv = DEFAULT_OFF_ENV, input } = {}) => {
  let payload = null;
  try {
    payload = JSON.parse(input ?? readFileSync(0, "utf8"));
  } catch {
    // Unreadable input isn't a question this gate can judge: let it through.
    return 0;
  }
  const where = root ?? process.env["CLAUDE_PROJECT_DIR"] ?? process.cwd();
  let settings = askTags ?? null;
  if (settings === null) {
    // Only the config is read here: no sets.
    const rules = loadRules(where, { files: { ...DEFAULT_FILES, ...files }, sets: [] });
    settings = rules.error === "" ? rules.askTags : null;
  }
  if (settings === null) return 0;
  const cwd = String(payload?.cwd ?? process.cwd());
  const log = typeof settings.log === "string" && settings.log !== "" ? (settings.log.startsWith("~/") || settings.log.startsWith("/") ? settings.log : join(where, settings.log)) : null;
  const result = judge(payload, { tags: settings.tags, tools: settings.tools ?? null, refusal: settings.refusal, offEnv, record: log === null ? () => {} : (entry) => appendRecord(log, cwd, entry) });
  if (result.code !== 0) process.stderr.write(`${result.reason}\n`);
  return result.code;
};
