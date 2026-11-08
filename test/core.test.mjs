/*
  The guard core names no team's rule: each one is data in a bundled rule set (sets/).
  In the app: nothing at runtime; runs in `node --test test/*.test.mjs`.
  Used by: node:test (`node --test`), with node:assert; no install needed.
  Uses: src/guard.mjs (its text, and evaluate() and loadRules()); its rule sets, copied to a temp dir.

  The guard's code must hold only general rules and the evaluators; a team's names live in the
  rule sets. The term check reads the code outside comments, so a rule can't creep back in as a
  literal. The mutation checks empty each set (down to one stub row, since a set with nothing in it
  refuses every command) and show its rules go with it, so the set is what holds them, not a
  leftover in the code.
*/
import "./tmpdir.mjs";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { after, describe, it } from "node:test";

import { BUNDLED_SETS, evaluate, loadRules } from "../src/guard.mjs";

const GUARD = fileURLToPath(new URL("../src/guard.mjs", import.meta.url));
const SETS = fileURLToPath(new URL("../sets/", import.meta.url));

// The guard's code without its comments: whole-line `//` comments and inline `/** @type {…} */`
// annotations. Nothing else is cut, so no code can hide: a trailing `//` comment on a code line is
// kept (the code's regexes and globs hold `//` and `/*` too), and a term there fails the test.
// Also left out: the names in the list of bundled sets (BUNDLED_SETS), which names sets, not
// rules (`merge-conveyor`). Only the quoted names are cut, so other code on that line is still read.
const code = readFileSync(GUARD, "utf8")
  .replace(/\/\*\* @type \{.*?\} \*\//g, "")
  .split("\n")
  .filter((line) => !line.trim().startsWith("//"))
  .map((line) => line.replace(/^export const BUNDLED_SETS = Object\.freeze\(\[(?:"[a-z0-9-]+"(?:, )?)*\]\);/, "export const BUNDLED_SETS = [];"));

// One team's rules, by the words that name them, read from the shipped sets: each set's name, and
// the distinctive tokens in its `match` patterns (lowercase words joined by `-` or `:`, or UPPER_SNAKE names).
// Plain words ("rerun", "ready") are general and stay out. The off switch's name matches none.
const GENERIC = new Set(["dry-run"]);
const termsOf = (obj, out) => {
  if (Array.isArray(obj)) obj.forEach((v) => termsOf(v, out));
  else if (obj && typeof obj === "object") {
    for (const [k, v] of Object.entries(obj)) {
      if (k === "match" && typeof v === "string") {
        for (const t of v.match(/[A-Za-z][A-Za-z0-9_:-]{4,}/g) ?? []) {
          if ((/^[a-z]+(?:[-:][a-z]+)+$/.test(t) || /^[A-Z]+(?:_[A-Z]+)+$/.test(t)) && !GENERIC.has(t)) out.add(t);
        }
      } else termsOf(v, out);
    }
  }
};
const found = new Set();
for (const file of readdirSync(SETS).filter((f) => f.endsWith(".json"))) {
  found.add(file.replace(/\.json$/, ""));
  termsOf(JSON.parse(readFileSync(join(SETS, file), "utf8")), found);
}
const TERMS = [...found].map((t) => new RegExp(t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"));

describe("the guard's core names no team's rule", () => {
  it("reads a term list from the shipped sets", () => assert.ok(TERMS.length >= 4));
  for (const term of TERMS) {
    it(`no ${String(term)} in its code`, () => {
      const hits = code.filter((line) => term.test(line));
      assert.deepEqual(hits, [], `src/guard.mjs names ${String(term)} outside a comment`);
    });
  }
});

// A temp copy of the rule sets with `replaced`'s file replaced by `text`: the copy's paths, in load order.
const dirs = [];
after(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});
const NAMES = loadRules(mkdtempSync(join(tmpdir(), "guard-core-root-")), { sets: [...BUNDLED_SETS] }).loaded;
const setsWith = (text, replaced) => {
  const dir = mkdtempSync(join(tmpdir(), "guard-core-sets-"));
  dirs.push(dir);
  return NAMES.map((name) => {
    writeFileSync(join(dir, `${name}.json`), name === replaced ? text : readFileSync(join(SETS, `${name}.json`), "utf8"));
    return join(dir, `${name}.json`);
  });
};

// An emptied set: one row no command meets, since a set with nothing in it doesn't load.
const STUB = JSON.stringify({ ask: [{ match: "^guard-core-test-stub$", reason: "A stub row: this set's real rules are gone." }] });

describe("a set with nothing in it refuses every command, as a missing one does", () => {
  for (const text of ["{}", JSON.stringify({ $comment: "x", deny: [], ask: [], statusContexts: [] })]) {
    it(`draft-flow.json as ${text}`, () => {
      const rules = loadRules(mkdtempSync(join(tmpdir(), "guard-core-root-")), { sets: setsWith(text, "draft-flow") });
      assert.match(rules.error, /draft-flow\.json didn't load \(it holds no rows or knobs/);
      for (const command of ["ls", "git push -f origin dev"]) assert.deepEqual(evaluate(command, { branch: "feat", rules }), { decision: "deny", reason: rules.error });
    });
  }
});

describe("emptying each set turns its rows red", () => {
  const root = mkdtempSync(join(tmpdir(), "guard-core-root-"));
  dirs.push(root);
  const real = loadRules(root, { sets: [...BUNDLED_SETS] });
  // [set, command, expected decision with the set]: one row per kind of rule the set holds.
  /** @type {[string, string, string][]} */
  const rows = [
    ["merge-conveyor", "pnpm conveyor tick", "deny"],
    ["merge-conveyor", "sh scripts/conveyor-timer.sh", "deny"],
    ["merge-conveyor", "pnpm conveyor $verb", "ask"],
    ["merge-conveyor", "gh api repos/o/r/statuses/abc -f state=success -f context=conveyor/cleared", "deny"],
    ["merge-conveyor", "gh variable set CONVEYOR_ENABLED --body on", "ask"],
    ["draft-flow", "gh pr ready 5 --undo", "deny"],
    ["draft-flow", "gh pr ready 5", "ask"],
    ["ci-minutes", "gh run rerun 5", "deny"],
    ["ci-minutes", "gh workflow run ci.yml", "ask"],
    ["chute-boss", "pnpm lock run heavy --ignore-load -- pnpm check", "ask"],
    ["chute-boss", "pnpm lock waive heavy --as me --reason x", "ask"],
  ];
  const emptied = Object.fromEntries(NAMES.map((name) => [name, loadRules(root, { sets: setsWith(STUB, name) })]));

  it("every emptied copy loads", () => {
    for (const rules of Object.values(emptied)) assert.equal(rules.error, "");
  });

  for (const [set, command, expected] of rows) {
    it(`${set}: ${command}: ${expected} with the set, not without it`, () => {
      assert.equal(evaluate(command, { branch: "feat", rules: real })?.decision ?? null, expected);
      assert.notEqual(evaluate(command, { branch: "feat", rules: emptied[set] })?.decision ?? null, expected);
    });
  }
});
