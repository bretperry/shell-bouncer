/*
  The `reins` command: explain, sets, help, an unknown command, and the package's shape.
  In the app: nothing at runtime; runs in `node --test test/*.test.mjs`.
  Used by: node:test (`node --test`), with node:assert; no install needed.
  Uses: bin/reins.mjs, package.json, src/index.mjs; temp folders under the OS temp dir.
*/
import "./tmpdir.mjs";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import * as reins from "../src/index.mjs";

const BIN = fileURLToPath(new URL("../bin/reins.mjs", import.meta.url));
const PKG = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const cli = (args, root = mkdtempSync(join(tmpdir(), "reins-cli-"))) => {
  const env = { ...process.env, CLAUDE_PROJECT_DIR: root };
  delete env.REINS;
  delete env.WHIPPLETREE_GUARD;
  return spawnSync(process.execPath, [BIN, ...args], { env, cwd: root, encoding: "utf8" });
};

describe("reins CLI", () => {
  it("explain prints the verdict and the rule's reason, and runs nothing", () => {
    const denied = cli(["explain", "git push -f origin main"]);
    assert.equal(denied.status, 0);
    assert.match(denied.stdout, /^verdict: deny$/m);
    assert.match(denied.stdout, /^reason: Force-pushing main/m);
    assert.match(cli(["explain", "ls"]).stdout, /^verdict: allow \(no rule fired\)$/m);
  });

  it("explain reads the project's reins.json, and says when it doesn't load", () => {
    const root = mkdtempSync(join(tmpdir(), "reins-cli-"));
    writeFileSync(join(root, "reins.json"), JSON.stringify({ sets: ["draft-flow"] }));
    const ready = cli(["explain", "gh", "pr", "ready", "3"], root);
    assert.match(ready.stdout, /^rule sets: draft-flow$/m);
    assert.match(ready.stdout, /^verdict: ask$/m);
    writeFileSync(join(root, "reins.json"), "{");
    const broken = cli(["explain", "ls"], root);
    assert.equal(broken.status, 1);
    assert.match(broken.stdout, /^verdict: deny$/m);
  });

  it("explain with no command prints its usage", () => assert.equal(cli(["explain"]).status, 1));

  it("sets lists every bundled set and what it holds", () => {
    const out = cli(["sets"]);
    assert.equal(out.status, 0);
    for (const name of reins.BUNDLED_SETS) assert.match(out.stdout, new RegExp(`^${name}: `, "m"));
    assert.match(out.stdout, /merge-conveyor: 5 deny rows, 2 ask rows, 1 status contexts, 1 repository variables/);
  });

  it("help, and an unknown command", () => {
    assert.equal(cli(["help"]).status, 0);
    assert.match(cli(["help"]).stdout, /reins explain/);
    const unknown = cli(["frobnicate"]);
    assert.equal(unknown.status, 1);
    assert.match(unknown.stderr, /unknown command "frobnicate"/);
  });

  it("hook with no host blocks", () => assert.equal(cli(["hook"]).status, 2));
});

describe("the package's shape", () => {
  it("names one bin, reins, and the exports resolve", () => {
    assert.deepEqual(PKG.bin, { reins: "bin/reins.mjs" });
    assert.equal(PKG.license, "FSL-1.1-MIT");
    assert.equal(PKG.engines.node, ">=22");
    assert.equal(PKG.dependencies, undefined);
    assert.equal(PKG.devDependencies, undefined);
    assert.equal(reins.PACKAGE_NAME, PKG.name);
    // The guard protects node_modules/.bin/<the package's name, unscoped>, so the bin must carry that name.
    assert.ok(Object.hasOwn(PKG.bin, reins.PACKAGE_NAME.replace(/^@[^/]+\//, "")));
  });

  it("exports the API's names", () => {
    for (const name of ["evaluate", "hookVerdict", "loadRules", "main", "parseLine", "words", "destroysSql", "dotenvValue", "targetOf", "shipFreeze"]) assert.equal(typeof reins[name], "function", name);
    assert.equal(typeof reins.LIMITS, "object");
    assert.equal(typeof reins.WATCHDOG_MS, "number");
    assert.equal(typeof reins.askGate.judge, "function");
  });

  it("ships every bundled set, and nothing else in sets/", () => {
    const shipped = readdirSync(fileURLToPath(new URL("../sets/", import.meta.url))).map((name) => name.replace(/\.json$/, ""));
    assert.deepEqual(shipped.toSorted(), [...reins.BUNDLED_SETS].toSorted());
  });
});
