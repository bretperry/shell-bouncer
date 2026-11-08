/*
  reins standalone: the core with no config on a bare repo, each knob's verdict from a fixture set,
  the config (reins.json) and the `files` option, and the loader's refusals.
  In the app: nothing at runtime; runs in `node --test test/*.test.mjs`.
  Used by: node:test (`node --test`), with node:assert; no install needed.
  Uses: src/guard.mjs, bin/reins.mjs, test/fixtures/team.json; temp git repos under the OS temp dir.

  A stranger's agent meets the defaults with no config, so the bare-repo rows are the ones that
  matter most: the general rules hold, and no team's rule (a bundled set's) fires unasked. Each knob
  row runs with the fixture set and without it, so the row proves the knob gives the verdict. Every
  loader refusal denies every command, since a misspelt name read as "nothing" would switch rules off.
*/
import "./tmpdir.mjs";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { BUNDLED_SETS, evaluate, loadRules, PACKAGE_NAME } from "../src/index.mjs";

const BIN = fileURLToPath(new URL("../bin/reins.mjs", import.meta.url));
const TEAM = fileURLToPath(new URL("./fixtures/team.json", import.meta.url));

// A temp folder holding `files` (an object is written as JSON), not a git repo.
const folder = (files = {}) => {
  const root = mkdtempSync(join(tmpdir(), "reins-root-"));
  for (const [path, value] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), typeof value === "string" ? value : JSON.stringify(value));
  }
  return root;
};

// A temp git repo on `branch`, with `files`, so the hook's own branch lookup runs.
const repoOn = (branch, files = {}) => {
  const root = folder(files);
  const git = (...args) => execFileSync("git", ["-c", "user.email=a@b", "-c", "user.name=a", "-c", "commit.gpgsign=false", ...args], { cwd: root, stdio: "pipe" });
  git("init", "-q", "-b", branch, ".");
  git("commit", "-q", "--allow-empty", "-m", "init");
  return root;
};

// The hook's decision, run as Claude Code runs it: `reins hook claude`, the project root in
// CLAUDE_PROJECT_DIR, the payload's cwd the repo. null when it answers nothing (no opinion).
const hook = (root, command) => {
  const env = { ...process.env, CLAUDE_PROJECT_DIR: root };
  for (const name of ["REINS", "WHIPPLETREE_GUARD", "DATABASE_URL"]) delete env[name];
  const result = spawnSync(process.execPath, [BIN, "hook", "claude"], { input: JSON.stringify({ tool_input: { command }, cwd: root }), env, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout === "" ? null : JSON.parse(result.stdout).hookSpecificOutput;
};
const decisionIn = (root, command) => hook(root, command)?.permissionDecision ?? null;

describe("the core alone: a bare repo with no reins.json", () => {
  const root = repoOn("feat");

  it("loads no rule sets", () => {
    const rules = loadRules(root);
    assert.equal(rules.error, "");
    assert.deepEqual(rules.loaded, []);
    assert.deepEqual([...rules.branches.protected], ["main", "master"]);
  });

  // [command, decision through the real hook]
  const rows = [
    ["ls", null],
    ["git status", null],
    ["git push origin feat", null],
    ["git push -f origin feat", null],
    // main and master are protected, and a push to either asks.
    ["git push -f origin main", "deny"],
    ["git push -f origin master", "deny"],
    ["git push --delete origin master", "deny"],
    ["git push origin main", "ask"],
    ["git push origin HEAD:master", "ask"],
    ["gh api -X PATCH repos/o/r/git/refs/heads/master -f sha=abc", "ask"],
    // dev is a team's branch, not the core's.
    ["git push -f origin dev", null],
    ["git push --no-verify", "deny"],
    ["gh pr merge 3", "ask"],
    ["pkill -f node", "deny"],
    ['psql -h db.example.com -c "DROP TABLE users"', "deny"],
    ["terraform destroy", "deny"],
    ["gh repo delete o/r --yes", "deny"],
    // A bundled set's rows don't fire unless a project turns the set on.
    ["gh pr ready 3", null],
    ["gh run rerun 9", null],
    ["pnpm conveyor tick", null],
    ["pnpm lock waive heavy --as me --reason x", null],
    // The guard's own files and package.
    ["rm reins.json", "ask"],
    ["echo '{}' > .claude/settings.json", "ask"],
    ["rm -rf node_modules/reins", "ask"],
    ["pnpm add -D reins@0.2.0", "ask"],
    ["npm uninstall reins", "ask"],
    ["pnpm add left-pad", null],
    ["pnpm install", null],
  ];
  for (const [command, expected] of rows) {
    it(`${command} → ${String(expected)}`, () => assert.equal(decisionIn(root, command), expected));
  }

  it("a refusal names the guard and says why", () => {
    const answer = hook(root, "git push -f origin main");
    assert.match(answer?.permissionDecisionReason ?? "", /^reins: Force-pushing main is never an agent's call/);
  });

  it("the package-manager rule names the package by its one constant", () => {
    assert.equal(PACKAGE_NAME, JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).name);
    assert.equal(evaluate(`npm i ${PACKAGE_NAME}`, { branch: "feat" })?.decision, "ask");
  });

  it("REINS=off and the old WHIPPLETREE_GUARD=off both turn the hook off; another value doesn't", () => {
    for (const [name, value, expected] of [["REINS", "off", ""], ["WHIPPLETREE_GUARD", "off", ""], ["REINS", "on", "deny"]]) {
      const result = spawnSync(process.execPath, [BIN, "hook", "claude"], { input: JSON.stringify({ tool_input: { command: "git push -f origin main" }, cwd: root }), env: { ...process.env, CLAUDE_PROJECT_DIR: root, REINS: "", WHIPPLETREE_GUARD: "", [name]: value }, encoding: "utf8" });
      assert.equal(result.stdout === "" ? "" : JSON.parse(result.stdout).hookSpecificOutput.permissionDecision, expected, `${name}=${value}`);
    }
  });
});

describe("reins.json: the config at the project root", () => {
  it("turns bundled sets on by name", () => {
    const root = repoOn("feat", { "reins.json": { sets: ["draft-flow", "ci-minutes"] } });
    assert.deepEqual(loadRules(root).loaded, ["draft-flow", "ci-minutes"]);
    assert.equal(decisionIn(root, "gh pr ready 3"), "ask");
    assert.equal(decisionIn(root, "gh pr ready 3 --undo"), "deny");
    assert.equal(decisionIn(root, "gh run rerun 9"), "deny");
    assert.equal(decisionIn(root, "pnpm conveyor tick"), null);
  });

  it("protectedBranches replaces the default, for pushes and the API alike", () => {
    const root = repoOn("feat", { "reins.json": { protectedBranches: ["main", "release"] } });
    assert.equal(decisionIn(root, "git push -f origin release"), "deny");
    assert.equal(decisionIn(root, "gh api -X DELETE repos/o/r/git/refs/heads/release"), "deny");
    // master is no longer protected, so a force-push isn't refused; it is still in askOnPush, so it asks.
    assert.equal(decisionIn(root, "git push -f origin master"), "ask");
  });

  it("askOnPush replaces the default; an empty list asks on no push", () => {
    const release = repoOn("feat", { "reins.json": { askOnPush: ["release"] } });
    assert.equal(decisionIn(release, "git push origin release"), "ask");
    assert.equal(decisionIn(release, "git push origin main"), null);
    assert.equal(decisionIn(release, "git push -f origin main"), "deny", "still protected");
    const none = repoOn("feat", { "reins.json": { askOnPush: [] } });
    assert.equal(decisionIn(none, "git push origin main"), null);
  });

  it("holds the project's own deny, ask, and allow", () => {
    const root = repoOn("feat", {
      "reins.json": {
        deny: [{ match: "^make\\s+deploy\\b", reason: "Deploys go through CI." }],
        ask: [{ match: "^npm\\s+publish\\b", reason: "Publishing is the user's call." }],
        allow: [{ command: "dropdb app_test", reason: "The throwaway test database." }],
      },
    });
    assert.equal(hook(root, "make deploy")?.permissionDecisionReason, "reins: Deploys go through CI. (reins.json)");
    assert.equal(decisionIn(root, "npm publish"), "ask");
    assert.equal(decisionIn(root, "dropdb app_test"), null);
    assert.equal(decisionIn(root, "dropdb app"), "deny");
  });

  it("ruleDir names a folder of pack files, which is then a guard file", () => {
    const root = repoOn("feat", { "reins.json": { ruleDir: ".reins" }, ".reins/iac.json": { deny: [{ match: "^pulumi\\s+up\\b", reason: "Applies go through CI." }] } });
    assert.equal(hook(root, "pulumi up")?.permissionDecisionReason, "reins: Applies go through CI. (.reins/iac.json)");
    assert.equal(decisionIn(root, "rm .reins/iac.json"), "ask");
    assert.equal(decisionIn(folder(), "rm .reins/iac.json"), null, "no ruleDir, no guard folder");
  });

  it("askTags is read and checked, for the ask gate", () => {
    assert.deepEqual(loadRules(folder({ "reins.json": { askTags: { tags: ["only-you"], tools: "AskUserQuestion" } } })).askTags, { tags: ["only-you"], refusal: undefined, tools: ["AskUserQuestion"], log: undefined });
    assert.equal(loadRules(folder()).askTags, null);
  });
});

describe("the files option: a caller keeps its own file names", () => {
  it("renames the config, adds a branch file and a rule folder", () => {
    const root = folder({
      "project-rules.json": { deny: [{ match: "^make\\s+deploy\\b", reason: "Deploys go through CI." }] },
      "tooling.json": { protectedBranches: ["main", "dev"], other: "its own tooling's key" },
      "rules.d/x.json": { ask: [{ match: "^pulumi\\s+up\\b", reason: "Applies ask." }] },
      "reins.json": { deny: [{ match: "^ls$", reason: "Not read: the config was renamed." }] },
    });
    const rules = loadRules(root, { files: { config: "project-rules.json", branches: "tooling.json", ruleDir: "rules.d" } });
    assert.equal(rules.error, "");
    assert.equal(evaluate("make deploy", { branch: "feat", rules })?.decision, "deny");
    assert.equal(evaluate("git push -f origin dev", { branch: "feat", rules })?.decision, "deny");
    assert.equal(evaluate("pulumi up", { branch: "feat", rules })?.decision, "ask");
    assert.equal(evaluate("ls", { branch: "feat", rules }), null);
    for (const path of ["project-rules.json", "tooling.json", "rules.d/x.json"]) assert.equal(evaluate(`rm ${path}`, { branch: "feat", rules })?.decision, "ask", path);
  });

  it("config: null reads no config at all", () => {
    const rules = loadRules(folder({ "reins.json": "{ broken" }), { files: { config: null } });
    assert.equal(rules.error, "");
  });
});

// Rules with the fixture set, and with the core alone, for one knob row.
const withTeam = loadRules(folder(), { sets: [TEAM] });
const coreOnly = loadRules(folder(), { sets: [] });
const decision = (rules, command, options = {}) => evaluate(command, { branch: "feat", rules, ...options })?.decision ?? null;

describe("each knob gives its verdict from a fixture set", () => {
  it("the fixture set loads", () => assert.equal(withTeam.error, ""));

  // [knob, command, expected with the set, options]
  /** @type {[string, string, string, Record<string, unknown>?][]} */
  const rows = [
    ["deny row, on: segment", "pnpm autopilot on 8", "deny"],
    ["deny row, on: segment (a marker named outright)", "echo x > .git/team-autopilot", "deny"],
    ["ask row, on: program", "node scripts/batch-merge.mjs 12", "ask"],
    ["protectedBranches", "git push -f origin dev", "deny"],
    ["workflowOnlyBranches", "git push origin HEAD:base", "deny"],
    ["statusContexts", "gh api repos/o/r/statuses/abc -f state=success -f context=review/lint", "deny"],
    ["statusContexts, unreadable", "gh api repos/o/r/statuses/abc -f context=$C", "ask"],
    ["repoVariables", "gh variable set RUNNER_POLICY --body force", "deny"],
    ["repoVariables, through gh api", "gh api -X DELETE repos/o/r/actions/variables/RUNNER_POLICY", "deny"],
    ["markerFiles", "echo 1 > .git/team-auto*", "ask"],
    ["freezeMarkers", "git push origin dev", "deny", { shipFreezeIn: () => "29" }],
    ["skipCi", "git commit -m '[skip ci] x'", "deny"],
    ["pushEnvDeny", "TEAM_SKIP_CHECKS=1 git push", "deny"],
    ["gitConfigAsk", "git config team.prepush fast", "ask"],
    ["guardFiles", "rm .team-rules/x.json", "ask"],
  ];
  for (const [knob, command, expected, options] of rows) {
    it(`${knob}: ${command} → ${expected} with the set, not without it`, () => {
      assert.equal(decision(withTeam, command, options), expected);
      assert.notEqual(decision(coreOnly, command, options), expected);
    });
  }

  it("freezeMarkers: {pr} in the reason is the marker's text", () => {
    assert.match(evaluate("git push origin dev", { branch: "feat", rules: withTeam, shipFreezeIn: () => "29" })?.reason ?? "", /release PR #29 is open/);
  });

  it("skipCi: allowed on its own branch; {branch} names the other", () => {
    assert.equal(decision(withTeam, "git commit -m '[skip ci] x'", { branch: "dev" }), null);
    assert.match(evaluate("git commit -m '[skip ci] x'", { branch: "feat", rules: withTeam })?.reason ?? "", /on 'feat'/);
  });

  it("a set's protectedBranches gives way to the config's", () => {
    const rules = loadRules(folder({ "reins.json": { protectedBranches: ["main"] } }), { sets: [TEAM] });
    assert.equal(decision(rules, "git push -f origin dev"), null);
  });
});

// The refusal every command gets from rules that didn't load.
const refusesAll = (rules, names) => {
  assert.match(rules.error, names);
  assert.match(rules.error, /so every shell command is refused/);
  for (const command of ["ls", "git status", ""]) assert.deepEqual(evaluate(command, { rules }), { decision: "deny", reason: rules.error });
};

describe("the loader refuses every command when what it was told to read doesn't load", () => {
  it("an unknown set name, from the config", () => refusesAll(loadRules(folder({ "reins.json": { sets: ["draft-flow", "draft-flwo"] } })), /sets\[1\] is not a bundled rule set/));

  it("an unknown set name, from the caller", () => refusesAll(loadRules(folder(), { sets: ["draft-flwo"] }), /"draft-flwo" is not a bundled rule set/));

  it("an absent named set", () => refusesAll(loadRules(folder(), { sets: [join(folder(), "gone.json")] }), /gone\.json didn't load \(it is missing/));

  it("an unknown files key", () => refusesAll(loadRules(folder(), { files: { projcet: "x.json" } }), /the files option has an unknown key "projcet"/));

  it("a files path outside the project", () => refusesAll(loadRules(folder(), { files: { config: "../x.json" } }), /files\.config must be a path inside the project/));

  it("a knob row without verdict", () => {
    const set = join(folder({ "set.json": { statusContexts: [{ match: "^x/", reason: "x" }] } }), "set.json");
    refusesAll(loadRules(folder(), { sets: [set] }), /statusContexts\[0\]\.verdict must be "deny" or "ask"/);
    const variable = join(folder({ "set.json": { repoVariables: [{ name: "X", reason: "x" }] } }), "set.json");
    refusesAll(loadRules(folder(), { sets: [variable] }), /repoVariables\[0\]\.verdict must be "deny" or "ask"/);
  });

  it("an allow meeting a set's row is a broken file", () => {
    for (const command of ["pnpm autopilot on 8", "git config team.prepush fast", "node scripts/batch-merge.mjs 12"]) {
      refusesAll(loadRules(folder({ "reins.json": { allow: [{ command, reason: "x" }] } }), { sets: [TEAM] }), /allow\[0\]\.command meets a built-in rule an exemption can't lift/);
    }
    refusesAll(loadRules(folder({ "reins.json": { sets: ["draft-flow"], allow: [{ command: "gh pr ready 3", reason: "x" }] } })), /allow\[0\]\.command meets a built-in rule an exemption can't lift/);
  });

  it("an unknown config key, or a knob of the wrong shape", () => {
    refusesAll(loadRules(folder({ "reins.json": { protectedBranchs: ["main"] } })), /^reins\.json didn't load \(the top level has an unknown key "protectedBranchs"/);
    refusesAll(loadRules(folder({ "reins.json": { askOnPush: "main" } })), /"askOnPush" must be a non-empty array of branch names/);
    refusesAll(loadRules(folder({ "reins.json": { askTags: { tags: [] } } })), /"askTags\.tags" must be a non-empty array/);
    refusesAll(loadRules(folder({ "reins.json": { ruleDir: "/etc" } })), /ruleDir must be a path inside the project/);
    refusesAll(loadRules(folder({ "reins.json": { sets: "draft-flow" } })), /"sets" must be an array/);
  });

  it("protectedBranches named in both the config and the branch file", () => {
    refusesAll(loadRules(folder({ "reins.json": { protectedBranches: ["main"] }, "b.json": { protectedBranches: ["dev"] } }), { files: { branches: "b.json" } }), /"protectedBranches" is also set in reins\.json/);
  });

  it("the off switch named in the refusal is the caller's first offEnv name", () => {
    assert.match(loadRules(folder({ "reins.json": "{" })).error, /set REINS=off/);
    assert.match(loadRules(folder({ "reins.json": "{" }), { offEnv: ["OTHER_GUARD"] }).error, /set OTHER_GUARD=off/);
  });

  it("every bundled set loads on its own", () => {
    for (const name of BUNDLED_SETS) assert.equal(loadRules(folder(), { sets: [name] }).error, "", name);
  });
});
