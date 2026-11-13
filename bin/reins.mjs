#!/usr/bin/env node
// The `reins` command: the hook entries, and two read-only commands for a person.
// In the app: nothing at runtime; an agent's hook runs `reins hook claude|cursor` before every shell command, and `reins ask-gate` before a question.
// Used by: the agent's hook config, package.json "bin"; tested by test/cli.test.mjs.
// Uses: src/cli.mjs, loaded by a dynamic import, so a package that doesn't load is caught here.
// Run: `reins hook claude|cursor` (hook JSON on stdin), `reins ask-gate`, `reins explain "<command>"`, `reins sets`, `reins help`.
// When: hook entries before every agent command or question; `explain` and `sets` by hand.
// Env: SHELL_BOUNCER, REINS, or WHIPPLETREE_GUARD (`off`: the hook answers nothing, even when the guard doesn't load).
// Writes: the hook's answer on stdout (and a block reason on stderr); nothing on disk.
// Exit: hook: 0 answered (allow, ask, or deny as JSON), 2 blocked (the guard didn't load, or died without answering); others: see `reins help`.
//
// Claude Code reads a hook's exit code: 0 is its answer, 2 blocks, and anything else is a
// non-blocking error, so the command runs. The guard answers its own failures (an ask), but only
// once it has loaded: a syntax error, a missing file, or a crash outside main() exits 1, and every
// command would run unguarded. So this file imports nothing outside Node, loads the rest by a
// dynamic import, and for `hook` turns any exit but 0 or 2 into 2, with the reason on stderr.

import { writeSync } from "node:fs";

const [command = "help", ...rest] = process.argv.slice(2);
const hook = command === "hook";
const cursor = hook && rest[0] === "cursor";
const off = ["SHELL_BOUNCER", "REINS", "WHIPPLETREE_GUARD"].some((name) => process.env[name] === "off");

// Says why the command is blocked: Cursor reads a JSON answer, Claude Code reads stderr with exit 2.
// Each write may fail (a closed pipe); the exit code still blocks.
const blocked = (why) => {
  const message = `bouncer: ${why}, so this command is blocked. Tell the user: fix it (reinstall the package), or set SHELL_BOUNCER=off in the shell that starts the agent.`;
  if (cursor) {
    try {
      writeSync(1, JSON.stringify({ permission: "deny", user_message: message, agent_message: message }));
    } catch {
      // The exit code below still blocks.
    }
  }
  try {
    writeSync(2, `${message}\n`);
  } catch {
    // Nowhere left to say it.
  }
};

if (hook) {
  // Any exit but an answer (0) or a block (2) is a guard that died before answering.
  process.on("exit", (code) => {
    if (code === 0 || code === 2 || off) return;
    blocked(`the guard exited with code ${String(code)} without answering`);
    process.exitCode = 2;
  });
}

try {
  // A dynamic import, so a package that doesn't parse or isn't there throws here, where it is caught.
  const { cli } = await import("../src/cli.mjs");
  const code = await cli(command, rest);
  if (code !== undefined) process.exit(code);
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  if (hook) {
    if (off) process.exit(0);
    blocked(`the guard didn't load (${message})`);
    process.exit(2);
  }
  try {
    writeSync(2, `bouncer: ${message}\n`);
  } catch {
    // Nowhere left to say it.
  }
  process.exit(command === "ask-gate" ? 0 : 1);
}
