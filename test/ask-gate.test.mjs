/*
  The ask gate: the verdict for each kind of question, its settings in reins.json, and the real hook's exit code.
  In the app: nothing at runtime; runs in `node --test test/*.test.mjs`.
  Used by: node:test (`node --test`), with node:assert; no install needed.
  Uses: src/ask-gate.mjs, bin/reins.mjs (`reins ask-gate`), a temp project with a reins.json.

  The hook must never wedge an agent: bad input, a call with no question, and a project with no
  askTags all pass.
*/
import "./tmpdir.mjs";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { judge, refusalFor, tagOf } from "../src/ask-gate.mjs";
import { askGate } from "../src/index.mjs";

const TAGS = ["irreversible", "only-you", "policy"];
const ask = (...questions) => ({ tool_input: { questions: questions.map((question) => ({ question })) } });
const BIN = fileURLToPath(new URL("../bin/reins.mjs", import.meta.url));

// A temp project root with this reins.json (none when `config` is undefined).
const project = (config) => {
  const root = mkdtempSync(join(tmpdir(), "ask-gate-root-"));
  if (config !== undefined) writeFileSync(join(root, "reins.json"), typeof config === "string" ? config : JSON.stringify(config));
  return root;
};
const hook = (root, input, env = {}) =>
  spawnSync("node", [BIN, "ask-gate"], { input, encoding: "utf8", env: { ...process.env, REINS_ASK_GATE: "", WHIPPLETREE_ASK_GATE: "", HOME: mkdtempSync(join(tmpdir(), "ask-gate-home-")), CLAUDE_PROJECT_DIR: root, ...env } });

describe("ask gate: judge()", () => {
  it("is exported as askGate from the package", () => assert.equal(askGate.judge, judge));

  it("refuses an untagged question, and passes a tagged one", () => {
    assert.equal(judge(ask("Push the branch?"), { tags: TAGS, mode: "enforce" }).code, 2);
    assert.match(judge(ask("Push the branch?"), { tags: TAGS, mode: "enforce" }).reason ?? "", /Weigh the options/);
    for (const tag of TAGS) assert.equal(judge(ask(`[${tag}] Which?`), { tags: TAGS, mode: "enforce" }).code, 0);
  });

  it("is off with no tags: every question passes", () => {
    assert.equal(judge(ask("Push the branch?"), { mode: "enforce" }).code, 0);
    assert.equal(judge(ask("Push the branch?"), { tags: [], mode: "enforce" }).code, 0);
  });

  it("refuses when any one question in a call is untagged", () => {
    assert.equal(judge(ask("[only-you] Which face?", "Open the PR?"), { tags: TAGS, mode: "enforce" }).code, 2);
  });

  it("reads the wrap-up box's ask, and passes a recap with no ask", () => {
    const on = { tags: TAGS, mode: "enforce" };
    assert.equal(judge({ tool_input: { recap: "done", ask: "Merge it?" } }, on).code, 2);
    assert.equal(judge({ tool_input: { recap: "done", ask: "[irreversible] Deploy it?" } }, on).code, 0);
    assert.equal(judge({ tool_input: { recap: "done" } }, on).code, 0);
    assert.equal(judge({ tool_input: { recap: "done", actions: [{ label: "Yes" }] } }, on).code, 2, "buttons with no question are still a choice");
  });

  it("only counts a tag at the start, and only a known one", () => {
    assert.equal(tagOf("Deploy? [irreversible]", TAGS), null);
    assert.equal(tagOf("[trivial] Deploy?", TAGS), null);
    assert.equal(tagOf("  [only-you] Deploy?", TAGS), "only-you");
  });

  it("records every question in every mode, and `log` and `off` always pass", () => {
    for (const mode of ["log", "off"]) {
      const seen = [];
      assert.equal(judge(ask("Push?"), { tags: TAGS, mode, record: (entry) => seen.push(entry) }).code, 0);
      assert.deepEqual(seen, [{ tag: null, question: "Push?" }]);
    }
  });

  it("reads the mode from offEnv: REINS_ASK_GATE, and the old WHIPPLETREE_ASK_GATE", () => {
    for (const name of ["REINS_ASK_GATE", "WHIPPLETREE_ASK_GATE"]) {
      const saved = process.env[name];
      process.env[name] = "off";
      try {
        assert.equal(judge(ask("Push?"), { tags: TAGS }).code, 0, name);
        assert.equal(judge(ask("Push?"), { tags: TAGS, offEnv: ["SOMETHING_ELSE"] }).code, 2, `${name} outside offEnv changes nothing`);
      } finally {
        if (saved === undefined) delete process.env[name];
        else process.env[name] = saved;
      }
    }
  });

  it("judges only the named tools, and uses a custom refusal", () => {
    const on = { tags: TAGS, mode: "enforce", tools: ["AskUserQuestion"] };
    assert.equal(judge({ tool_name: "OtherTool", ...ask("Push?") }, on).code, 0);
    assert.equal(judge({ tool_name: "AskUserQuestion", ...ask("Push?") }, on).code, 2);
    assert.equal(judge(ask("Push?"), { ...on, refusal: "Tag it." }).reason, "Tag it.");
    assert.match(refusalFor(["a", "b", "c"]), /\[a\], \[b\], or \[c\]/);
  });
});

describe("ask gate: the hook, `reins ask-gate`", () => {
  const on = { askTags: { tags: TAGS } };

  it("blocks with exit 2 and a reason when reins.json sets askTags, and bad input passes", () => {
    const root = project(on);
    const blocked = hook(root, JSON.stringify(ask("Push?")));
    assert.equal(blocked.status, 2);
    assert.match(blocked.stderr, /Weigh the options/);
    assert.equal(hook(root, JSON.stringify(ask("[policy] Push?"))).status, 0);
    assert.equal(hook(root, "not json").status, 0);
    assert.equal(hook(root, JSON.stringify(ask("Push?")), { REINS_ASK_GATE: "off" }).status, 0);
    assert.equal(hook(root, JSON.stringify(ask("Push?")), { WHIPPLETREE_ASK_GATE: "log" }).status, 0);
  });

  it("is off by default: no reins.json, or one without askTags", () => {
    assert.equal(hook(project(), JSON.stringify(ask("Push?"))).status, 0);
    assert.equal(hook(project({ protectedBranches: ["main"] }), JSON.stringify(ask("Push?"))).status, 0);
  });

  it("fails open on a config that doesn't load", () => {
    assert.equal(hook(project("{ not json"), JSON.stringify(ask("Push?"))).status, 0);
    assert.equal(hook(project({ askTags: { tags: [] } }), JSON.stringify(ask("Push?"))).status, 0);
  });

  it("writes the log askTags names, one line per question", () => {
    const root = project({ askTags: { tags: TAGS, log: "asks.jsonl" } });
    hook(root, JSON.stringify(ask("Push?", "[policy] Merge?")));
    const lines = readFileSync(join(root, "asks.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
    assert.deepEqual(lines.map(({ at, ...entry }) => {
      assert.ok(Number.isFinite(Date.parse(at)));
      return entry;
    }), [{ tag: null }, { tag: "policy" }]);
    assert.equal(statSync(join(root, "asks.jsonl")).mode & 0o077, 0);
  });

  it("leaves a broadly readable log or linked target unchanged", () => {
    const root = project({ askTags: { tags: TAGS, log: "asks.jsonl" } });
    const log = join(root, "asks.jsonl");
    writeFileSync(log, "existing", { mode: 0o644 });
    assert.equal(hook(root, JSON.stringify(ask("[policy] Merge?"))).status, 0);
    assert.equal(readFileSync(log, "utf8"), "existing");

    const other = project({ askTags: { tags: TAGS, log: "link/asks.jsonl" } });
    symlinkSync(root, join(other, "link"), "dir");
    assert.equal(hook(other, JSON.stringify(ask("[policy] Merge?"))).status, 0);
    assert.equal(readFileSync(log, "utf8"), "existing");
  });
});
