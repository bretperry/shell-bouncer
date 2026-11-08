// The `reins` command's subcommands, after bin/reins.mjs has loaded this module.
// In the app: nothing at runtime; bin/reins.mjs calls cli() with the subcommand and its arguments.
// Used by: bin/reins.mjs; tested by test/cli.test.mjs.
// Uses: src/guard.mjs (main, hookVerdict, loadRules), src/ask-gate.mjs (run, loaded only for `ask-gate`), the bundled sets in sets/.
// Run: through bin/reins.mjs: `reins hook claude|cursor`, `reins ask-gate`, `reins explain "<command>"`, `reins sets`, `reins help`.
// When: hook entries before every agent command or question; `explain` and `sets` by hand.
// Env: as src/guard.mjs and src/ask-gate.mjs read them; CLAUDE_PROJECT_DIR or CURSOR_PROJECT_DIR (the project root).
// Writes: stdout (an answer or a report); nothing on disk except the ask gate's optional log.
// Exit: cli() returns the code (undefined when main() exits by itself): hook 0; ask-gate 0 or 2; explain 0 (a report, whatever the verdict), 1 when the config doesn't load; sets 0; help 0; anything else 1.

import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// A namespace import, so a guard missing an export fails where it is used, inside the hook's own
// answer-or-block wrapper, not at load; the ask gate loads only for its own command.
import * as guard from "./guard.mjs";

const HELP = `reins: stops a coding agent's risky shell commands.

  reins hook claude|cursor   the hook entry: hook JSON on stdin; exit 0 answered, 2 blocked
  reins ask-gate             the ask gate's hook entry (off unless reins.json sets askTags)
  reins explain "<command>"  prints the verdict and the rule that gave it; runs nothing
  reins sets                 lists the bundled rule sets and what each adds
  reins help                 this text

The config is reins.json at the project root (CLAUDE_PROJECT_DIR, else the current folder).
REINS=off turns the guard off for a session.`;

// The project root for a person's command: `--root <dir>` among the arguments, else the hook's.
const rootArg = (args) => {
  const at = args.indexOf("--root");
  if (at === -1) return { root: undefined, args };
  return { root: args[at + 1], args: [...args.slice(0, at), ...args.slice(at + 2)] };
};

// `reins explain "<command>"`: the verdict the hook would give in this folder, and its reason
// (a rule file's reason names the file). Reads the same config the hook reads.
const explain = (args) => {
  const { root, args: rest } = rootArg(args);
  const command = rest.join(" ");
  if (command.trim() === "") {
    process.stdout.write('Usage: reins explain "<command>" [--root <dir>]\n');
    return 1;
  }
  const where = root ?? process.env["CLAUDE_PROJECT_DIR"] ?? process.cwd();
  const rules = guard.loadRules(where);
  const sets = rules.loaded?.length ? rules.loaded.join(", ") : "none";
  const verdict = guard.hookVerdict(command, process.cwd(), { root: where });
  const lines = [`command: ${command}`, `rule sets: ${rules.error === "" ? sets : "(the config didn't load)"}`];
  lines.push(verdict === null ? "verdict: allow (no rule fired)" : `verdict: ${verdict.decision}`);
  if (verdict !== null) lines.push(`reason: ${verdict.reason}`);
  process.stdout.write(`${lines.join("\n")}\n`);
  return rules.error === "" ? 0 : 1;
};

// The kinds of rule one set file adds, counted, for `reins sets`.
const KINDS = { deny: "deny rows", ask: "ask rows", protectedBranches: "protected branches", workflowOnlyBranches: "workflow-only branches", statusContexts: "status contexts", repoVariables: "repository variables", markerFiles: "marker files", freezeMarkers: "freeze markers", skipCi: "a skip-CI rule", pushEnvDeny: "push variables", gitConfigAsk: "git settings", guardFiles: "guard files" };

// `reins sets`: each bundled set, what it holds, and its own description.
const listSets = () => {
  const dir = fileURLToPath(new URL("../sets/", import.meta.url));
  const present = new Set(readdirSync(dir).filter((name) => name.endsWith(".json")).map((name) => name.slice(0, -5)));
  const out = [];
  for (const name of guard.BUNDLED_SETS) {
    if (!present.has(name)) {
      out.push(`${name}: missing from this install`);
      continue;
    }
    const data = JSON.parse(readFileSync(`${dir}${name}.json`, "utf8"));
    const held = Object.entries(KINDS).flatMap(([key, label]) => {
      const value = data[key];
      if (value === undefined) return [];
      return [Array.isArray(value) ? `${String(value.length)} ${label}` : label];
    });
    out.push(`${name}: ${held.join(", ")}`, `  ${String(data["$comment"] ?? "")}`, "");
  }
  out.push('Turn one on in reins.json: { "sets": ["draft-flow"] }');
  process.stdout.write(`${out.join("\n")}\n`);
  return 0;
};

// Runs one subcommand; returns its exit code, or undefined when it exits by itself (`hook`).
export const cli = async (command, args) => {
  switch (command) {
    case "hook": {
      const host = args[0];
      if (host !== "claude" && host !== "cursor") {
        process.stderr.write("reins hook: name the host, claude or cursor\n");
        return 2;
      }
      guard.main({ host });
      return undefined;
    }
    case "ask-gate":
      return (await import("./ask-gate.mjs")).run();
    case "explain":
      return explain(args);
    case "sets":
      return listSets();
    case "help":
    case "--help":
    case "-h":
      process.stdout.write(`${HELP}\n`);
      return 0;
    default:
      process.stderr.write(`reins: unknown command ${JSON.stringify(command)}\n\n${HELP}\n`);
      return 1;
  }
};
