/*
  ask-gate.mjs: the verdict for each kind of question, and the real hook's exit code.
  In the app: nothing at runtime; runs in `node --test test/*.test.mjs`.
  Used by: node:test (`node --test`), with node:assert; no install needed.
  Uses: src/ask-gate.mjs.

  The hook must never wedge an agent: bad input and a call with no question pass.
*/
import "./tmpdir.mjs";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { judge, tagOf } from "../src/ask-gate.mjs";

const ask = (...questions) => ({ tool_input: { questions: questions.map((question) => ({ question })) } });
const SCRIPT = fileURLToPath(new URL("../src/ask-gate.mjs", import.meta.url));

const hook = (input, env = {}) => spawnSync("node", [SCRIPT], { input, encoding: "utf8", env: { ...process.env, HOME: mkdtempSync(join(tmpdir(), "ask-gate-")), ...env } });

describe("ask gate", () => {
  it("refuses an untagged question, and passes a tagged one", () => {
    assert.equal(judge(ask("Push the branch?")).code, 2);
    assert.match(judge(ask("Push the branch?")).reason, /Weigh the options/);
    for (const tag of ["irreversible", "only-you", "your-rule"]) assert.equal(judge(ask(`[${tag}] Which?`)).code, 0);
  });

  it("refuses when any one question in a call is untagged", () => {
    assert.equal(judge(ask("[only-you] Which face?", "Open the PR?")).code, 2);
  });

  it("reads the wrap-up box's ask, and passes a recap with no ask", () => {
    assert.equal(judge({ tool_input: { recap: "done", ask: "Merge it?" } }).code, 2);
    assert.equal(judge({ tool_input: { recap: "done", ask: "[irreversible] Ship it?" } }).code, 0);
    assert.equal(judge({ tool_input: { recap: "done" } }).code, 0);
    assert.equal(judge({ tool_input: { recap: "done", actions: [{ label: "Yes" }] } }).code, 2, "buttons with no question are still a choice");
  });

  it("only counts a tag at the start, and only a known one", () => {
    assert.equal(tagOf("Ship? [irreversible]"), null);
    assert.equal(tagOf("[trivial] Ship?"), null);
    assert.equal(tagOf("  [only-you] Ship?"), "only-you");
  });

  it("records every question in every mode, and `log` and `off` always pass", () => {
    for (const mode of ["log", "off"]) {
      const seen = [];
      assert.equal(judge(ask("Push?"), { mode, record: (entry) => seen.push(entry) }).code, 0);
      assert.deepEqual(seen, [{ tag: null, question: "Push?" }]);
    }
  });

  it("the real hook blocks with exit 2 and a reason, and bad input passes", () => {
    const blocked = hook(JSON.stringify(ask("Push?")));
    assert.equal(blocked.status, 2);
    assert.match(blocked.stderr, /Weigh the options/);
    assert.equal(hook("not json").status, 0);
    assert.equal(hook(JSON.stringify(ask("Push?")), { WHIPPLETREE_ASK_GATE: "off" }).status, 0);
  });
});
