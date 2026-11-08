/*
  Table test for command-guard's verdicts: what is refused, what asks the user, what runs.
  In the app: nothing at runtime; runs in `node --test test/*.test.mjs`.
  Used by: node:test (`node --test`), with node:assert; no install needed.
  Uses: src/guard.mjs → evaluate(), loadRules(), dotenvValue(); test/fixtures/team.json; temp repos under the OS temp dir.

  The allowed rows matter as much as the refused ones: a guard that blocks everyday commands
  gets switched off, and then it guards nothing. The project-rule tests lock the two ways a rule
  file could fail silently: a broken file read as "no rules", and an exemption that covers more
  than the one command it names. Rows are grouped by topic; strings only, nothing here runs a command.
*/
import "./tmpdir.mjs";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { availableParallelism, loadavg, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { after, describe, it } from "node:test";

import * as core from "../src/guard.mjs";

// The core's helpers, as the tests use them.
const { destroysSql, dotenvValue, LIMITS, targetOf, WATCHDOG_MS, words } = core;

// The machine's 1-minute load line for the timing tests: 3, or 1 per core when higher. Past it,
// even CPU time stretches, so a timing bar loosens.
const loadLine = () => Math.max(3, availableParallelism());

// What a project that turns everything on runs: every bundled set, plus a team's own set (the
// fixture, which exercises every knob), with a rule folder and a branch file named through `files`.
// A test that builds its own rules gets these sets and branches unless it names its own, so each
// row meets the team's rules the way a project's hook adapter would apply them.
const TEAM_SET = fileURLToPath(new URL("./fixtures/team.json", import.meta.url));
const TEST_SETS = ["draft-flow", TEAM_SET, "merge-conveyor", "ci-minutes", "chute-boss"];
const TEST_FILES = { ruleDir: ".reins", branches: "branches.json" };
const EMPTY_ROOT = mkdtempSync(join(tmpdir(), "guard-empty-root-"));
const loadRules = (root, options = {}) => core.loadRules(root, { files: TEST_FILES, sets: TEST_SETS, ...options });
const TEST_RULES = loadRules(EMPTY_ROOT);
if (TEST_RULES.error !== "") throw new Error(TEST_RULES.error);
const withSets = (rules) => (rules === undefined ? TEST_RULES : rules.sets === undefined ? { ...rules, sets: TEST_RULES.sets, branches: rules.branches ?? TEST_RULES.branches, guard: rules.guard ?? TEST_RULES.guard } : rules);
const evaluate = (command, options = {}) => core.evaluate(command, { ...options, rules: withSets(options.rules) });
const hookVerdict = (command, cwd, options = {}) => core.hookVerdict(command, cwd, { root: EMPTY_ROOT, files: TEST_FILES, sets: TEST_SETS, ...options });
const SHIP_FREEZE_FILE = "team-freeze";
const shipFreeze = (dir, file = SHIP_FREEZE_FILE) => core.shipFreeze(dir, file);

// Both budgets lifted, so a timing test measures one parser path rather than the gate in front of it.
const UNBOUNDED = { chars: Number.POSITIVE_INFINITY, ms: Number.POSITIVE_INFINITY, wallMs: Number.POSITIVE_INFINITY };

// A Prisma schema whose datasource is DATABASE_URL: a reset is judged loopback only once the guard
// has read a datasource like this one (positive evidence), so a loopback project carries one.
const SCHEMA = 'datasource db {\n  provider = "postgresql"\n  url      = env("DATABASE_URL")\n}\n';

// Branches of the directories a test command `cd`s or `git -C`s into.
const DIRS = { "../app": "dev", "~/src/app": "dev", "../feat-wt": "feat/x", "../x": "feat/x" };

// [command, branch checked out where the hook runs, expected decision or null]
const cases = [
  // Ready needs the user's OK; back to draft never happens.
  ["gh pr ready 12", "feat", "ask"],
  ["gh pr ready 12 --undo", "feat", "deny"],
  ["gh pr ready --undo 12", "feat", "deny"],
  ["gh pr create --draft --base dev", "feat", null],
  // Autopilot mode is the user's switch: an agent reads it, uses it, or turns it off, never on.
  ["pnpm autopilot on 8", "feat", "deny"],
  ["pnpm run autopilot on 8", "feat", "deny"],
  ["npm run autopilot on 8", "feat", "deny"],
  ["node scripts/autopilot.mjs on 8", "feat", "deny"],
  ["echo 2099-01-01 > .git/team-autopilot", "feat", "deny"],
  ["pnpm --dir . autopilot on 8", "feat", "deny"],
  ["pnpm autopilot -- on 8", "feat", "deny"],
  ["echo 'pnpm autopilot on 8' | sh", "feat", "deny"],
  ["timeout 5 pnpm autopilot on 8", "feat", "deny"],
  ["pnpm autopilot status", "feat", null],
  ["pnpm autopilot off", "feat", null],
  ["pnpm autopilot ready 12", "feat", null],
  ["pnpm autopilot merge 12", "feat", null],
  // The conveyor's timer and its clearance mark: `clear` is a review's, the rest are not an agent's.
  ["pnpm conveyor clear 12 abc1234", "feat", null],
  ["pnpm conveyor status", "feat", null],
  ["pnpm conveyor report --days 7", "feat", null],
  ["pnpm conveyor tick", "feat", "deny"],
  ["pnpm run conveyor tick", "feat", "deny"],
  ["pnpm --dir . conveyor tick", "feat", "deny"],
  ["node scripts/conveyor.mjs tick", "feat", "deny"],
  ["timeout 5 node scripts/conveyor.mjs tick", "feat", "deny"],
  ["sh scripts/conveyor-timer.sh", "feat", "deny"],
  // A dry run writes nothing, so it is anyone's; only that exact form.
  ["pnpm conveyor tick --dry-run", "feat", null],
  ["pnpm run conveyor tick --dry-run", "feat", null],
  ["node scripts/conveyor.mjs tick --dry-run", "feat", null],
  ["timeout 5 node scripts/conveyor.mjs tick --dry-run", "feat", null],
  ["pnpm conveyor -- tick --dry-run", "feat", null],
  ["pnpm conveyor tick --dry-run-not", "feat", "deny"],
  ["pnpm conveyor tick --dry-run extra", "feat", "deny"],
  ["pnpm conveyor tick --verbose --dry-run", "feat", "deny"],
  ["pnpm run conveyor tick --dry-run-not", "feat", "deny"],
  ["pnpm conveyor tick --dry-run; pnpm conveyor tick", "feat", "deny"],
  ["pnpm run conveyor tick --dry-run && pnpm run conveyor tick", "feat", "deny"],
  ["bash -c 'pnpm conveyor tick --dry-run; pnpm conveyor tick'", "feat", "deny"],
  // The conveyor's switch: starting it or removing it is the user's; stopping it is always safe.
  ["gh variable set CONVEYOR_ENABLED --body off", "feat", null],
  ["gh variable set CONVEYOR_ENABLED --body off --repo o/r", "feat", null],
  ["gh variable set CONVEYOR_ENABLED -b off", "feat", null],
  ["gh variable set CONVEYOR_ENABLED --body=off", "feat", null],
  ["gh variable set CONVEYOR_ENABLED --body on", "feat", "ask"],
  ["gh variable set CONVEYOR_ENABLED --body on --repo o/r", "feat", "ask"],
  ["gh variable set --repo o/r CONVEYOR_ENABLED --body on", "feat", "ask"],
  ["gh variable --repo o/r set CONVEYOR_ENABLED --body on", "feat", "ask"],
  ["gh variable set CONVEYOR_ENABLED -b on", "feat", "ask"],
  ["gh variable set CONVEYOR_ENABLED -bon", "feat", "ask"],
  ["gh variable set CONVEYOR_ENABLED --body=on", "feat", "ask"],
  ["gh variable set conveyor_enabled --body on", "feat", "ask"],
  ["gh variable set CONVEYOR_ENABLED --body yes", "feat", "ask"],
  ["gh variable set CONVEYOR_ENABLED --body OFF", "feat", "ask"],
  ["gh variable set CONVEYOR_ENABLED --body ''", "feat", "ask"],
  ["gh variable set CONVEYOR_ENABLED --body off --body on", "feat", "ask"],
  ["gh variable set CONVEYOR_ENABLED", "feat", "ask"],
  ["echo on | gh variable set CONVEYOR_ENABLED", "feat", "ask"],
  ["gh variable set CONVEYOR_ENABLED --body \"$VALUE\"", "feat", "ask"],
  ["gh variable set \"$NAME\" --body on", "feat", "ask"],
  ["gh variable set -f vars.env", "feat", "ask"],
  ["gh variable set OTHER --body on", "feat", null],
  ["gh variable delete CONVEYOR_ENABLED", "feat", "ask"],
  ["gh variable delete CONVEYOR_ENABLED --repo o/r", "feat", "ask"],
  ["gh variable delete OTHER", "feat", null],
  // The runner policy is the owner's: every value moves where CI bills, so no set or delete passes.
  ["gh variable set RUNNER_POLICY --body never", "feat", "deny"],
  ["gh variable set RUNNER_POLICY --body force --repo o/r", "feat", "deny"],
  ["gh variable set --repo o/r runner_policy -b ''", "feat", "deny"],
  ["gh variable set RUNNER_POLICY -f vars.env", "feat", "deny"],
  ["gh variable delete RUNNER_POLICY", "feat", "deny"],
  ["gh variable delete RUNNER_POLICY --repo o/r", "feat", "deny"],
  ["bash -c 'gh variable set RUNNER_POLICY --body force'", "feat", "deny"],
  ["gh api --method PATCH repos/o/r/actions/variables/RUNNER_POLICY -f value=force", "feat", "deny"],
  ["gh api --method DELETE repos/o/r/actions/variables/RUNNER_POLICY", "feat", "deny"],
  ["gh api --method POST repos/o/r/actions/variables -f name=RUNNER_POLICY -f value=never", "feat", "deny"],
  ["curl -X PATCH https://api.github.com/repos/o/r/actions/variables/RUNNER_POLICY -d '{\"value\":\"force\"}'", "feat", "deny"],
  ["verb=set; name=RUNNER_POLICY; gh variable \"$verb\" \"$name\" --body force", "feat", "deny"],
  ["name=RUNNER_POLICY; gh variable set \"$name\" --body force", "feat", "deny"],
  ["verb=delete; gh variable \"$verb\" RUNNER_POLICY", "feat", "deny"],
  ["gh variable set \"$NAME\" --body off", "feat", "ask"],
  ["gh variable set HOSTED_*", "feat", "ask"],
  ["gh variable \"$VERB\" \"$NAME\"", "feat", "ask"],
  ["gh api -X PATCH repos/o/r/environments/prod/variables/RUNNER_POLICY -f value=force", "feat", "deny"],
  ["gh api -X POST repos/o/r/environments/prod/variables -f name=RUNNER_POLICY -f value=never", "feat", "deny"],
  ["gh api repos/o/r/environments/prod/variables/RUNNER_POLICY", "feat", null],
  ["gh api -X POST repos/o/r/environments/prod/variables --input vars.json", "feat", "ask"],
  ["gh api -X POST repos/o/r/environments/prod/variables -F name=@f -f value=force", "feat", "ask"],
  ["gh api repos/o/r/environments/prod/variables", "feat", null],
  ["gh variable get RUNNER_POLICY", "feat", null],
  ["gh api repos/o/r/actions/variables/RUNNER_POLICY", "feat", null],
  ["grep -rn RUNNER_POLICY .github/workflows", "feat", null],
  ["gh variable get CONVEYOR_ENABLED", "feat", null],
  ["gh variable list", "feat", null],
  ["gh api --method PATCH repos/o/r/actions/variables/CONVEYOR_ENABLED -f value=on", "feat", "ask"],
  ["gh api -X PATCH /repos/o/r/actions/variables/conveyor_enabled -f value=on", "feat", "ask"],
  ["gh api repos/o/r/actions/variables/CONVEYOR_ENABLED -f value=on", "feat", "ask"],
  ["gh api --method DELETE repos/o/r/actions/variables/CONVEYOR_ENABLED", "feat", "ask"],
  ["gh api --method POST repos/o/r/actions/variables -f name=CONVEYOR_ENABLED -f value=on", "feat", "ask"],
  ["gh api --method POST repos/o/r/actions/variables --input body.json", "feat", "ask"],
  ["gh api --method PATCH repos/o/r/actions/variables/OTHER -f name=CONVEYOR_ENABLED", "feat", "ask"],
  ["gh api --method POST repos/o/r/actions/variables -f name=OTHER -f value=on", "feat", null],
  ["gh api repos/o/r/actions/variables/CONVEYOR_ENABLED", "feat", null],
  ["curl -X PATCH https://api.github.com/repos/o/r/actions/variables/CONVEYOR_ENABLED -d '{\"value\":\"on\"}'", "feat", "ask"],
  ["grep -n CONVEYOR_ENABLED scripts/conveyor.mjs", "feat", null],
  ["git commit -m 'Explain the conveyor tick'", "feat", null],
  ["grep -n 'conveyor tick' docs/guide/devices.md", "feat", null],
  ["gh api --method POST repos/o/r/statuses/abc -f state=success -f context=conveyor/cleared", "feat", "deny"],
  ["curl -X POST https://api.github.com/repos/o/r/statuses/abc -d '{\"context\":\"conveyor/cleared\"}'", "feat", "deny"],
  ["grep -rn conveyor/cleared scripts", "feat", null],
  // A review gate's status goes through `pnpm gate post`, which fingerprints the files.
  ["gh api --method POST repos/o/r/statuses/abc -f state=success -f context=review/lint", "feat", "deny"],
  ["curl -X POST https://api.github.com/repos/o/r/statuses/abc -d '{\"context\":\"review/lint\"}'", "feat", "deny"],
  ["pnpm gate post 12 lint passed", "feat", null],
  ["gh api repos/o/r/commits/abc/statuses --jq '.[] | select(.context==\"review/lint\")'", "feat", null],
  ["gh api repos/o/r/commits/abc/status", "feat", null],
  // The same status by a spelling the text rules can't read: a variable, a glob, or a body from a file or stdin.
  ["c=conveyor/cleared; gh api repos/o/r/statuses/abc -f state=success -f context=$c", "feat", "deny"],
  ["gh api repos/o/r/statuses/abc -f state=success -f context=conveyor/cl*", "feat", "ask"],
  ["gh api repos/o/r/statuses/abc -f state=success -F context=@ctx.txt", "feat", "ask"],
  ["gh api repos/o/r/statuses/abc --input status.json", "feat", "ask"],
  ["echo '{\"context\":\"conveyor/cleared\",\"state\":\"success\"}' | gh api repos/o/r/statuses/abc --input -", "feat", "ask"],
  ["gh api repos/o/r/statuses/abc -f state=success -f context=Conveyor/Cleared", "feat", "deny"],
  ["gh api repos/o/r/statuses/abc -f state=success -F context=review/lint", "feat", "deny"],
  ["gh api repos/o/r/statuses/abc -f state=success -f context=ci/lint", "feat", null],
  ["gh api repos/o/r/commits/abc/status --jq '.statuses[] | select(.context==\"conveyor/cleared\")'", "feat", null],
  // The tick by a package-manager spelling the parser reads as no program, or through a variable.
  ["pnpm run -s conveyor tick", "feat", "deny"],
  ["pnpm run --silent conveyor tick", "feat", "deny"],
  ["npm run -s conveyor tick", "feat", "deny"],
  ["pnpm run --dir . conveyor tick", "feat", "deny"],
  ["pnpm run conveyor -- tick", "feat", "deny"],
  ["npm run conveyor -- tick", "feat", "deny"],
  ["c=conveyor; pnpm $c tick", "feat", "deny"],
  ["c=tick; pnpm conveyor $c", "feat", "deny"],
  ["export c=conveyor; pnpm $c tick", "feat", "deny"],
  ["pnpm conveyor $(echo tick)", "feat", "ask"],
  ["pnpm conveyor $sub", "feat", "ask"],
  ["pnpm run -s conveyor tick --dry-run", "feat", null],
  ["pnpm run -s conveyor -- tick --dry-run", "feat", null],
  ["c=conveyor; pnpm $c tick --dry-run", "feat", null],
  ["pnpm run -s conveyor status", "feat", null],
  ["pnpm run -s conveyor clear 12 abc1234", "feat", null],
  ["pnpm conveyor clear 12 abc1234 --repo o/r", "feat", null],
  ["pnpm run lint; echo conveyor tick", "feat", null],
  ["pnpm run test -- --grep 'conveyor tick'", "feat", null],
  ["node --test scripts/conveyor*.test.mjs", "feat", null],
  // The autopilot marker named by a variable or a pattern rather than its plain name.
  ["f=team-autopilot; echo 2099-01-01 > .git/$f", "feat", "deny"],
  ["p=team; echo 2099-01-01 > .git/${p}-autopilot", "feat", "deny"],
  ["echo 2099-01-01 > .git/team-auto*", "feat", "ask"],
  ["echo 2099-01-01 > .git/team-autop?lot", "feat", "ask"],
  ["echo 2099-01-01 > .git/team-{autopilot,x}", "feat", "ask"],
  ["printf x | tee .git/team-autop[i]lot", "feat", "ask"],
  ["cp x .git/t*-autopilot", "feat", "ask"],
  ["echo 2099-01-01 > $(git rev-parse --git-common-dir)/team-a*", "feat", "ask"],
  ["echo 2099-01-01 > \"$(git rev-parse --git-common-dir)\"/team-$(echo autopilot)", "feat", "ask"],
  ["echo 2099-01-01 > .git/$unset", "feat", "ask"],
  ["X=autopilot; pnpm $X on 1", "feat", "deny"],
  ["X=autopilot; pnpm $X status", "feat", null],
  ["f=notes.txt; echo hi > .git/$f", "feat", null],
  ["echo hi > .git/info/exclude", "feat", null],
  ["echo hi > out*", "feat", null],
  ["echo hi > /tmp/w*", "feat", null],
  ["cp x $dest", "feat", null],
  // An approval is the user's yes: an agent reads it, never records it.
  ["pnpm approve 12 merge", "feat", "deny"],
  ["pnpm approve -- 12 hold:gate", "feat", "deny"],
  ["node scripts/approve.mjs 12 merge", "feat", "deny"],
  // The batch form (`approve <pr> <pr> …`) is the same act, so the same refusal.
  ["pnpm approve 1 2", "feat", "deny"],
  ["pnpm approve 12 13 14", "feat", "deny"],
  ["pnpm approve -- 1 2", "feat", "deny"],
  ["pnpm --silent approve 1 2", "feat", "deny"],
  ["pnpm run approve 1 2", "feat", "deny"],
  ["node scripts/approve.mjs 1 2", "feat", "deny"],
  ["node ./scripts/approve.mjs 1 2", "feat", "deny"],
  ["cd scripts && node approve.mjs 1 2", "feat", "deny"],
  ["pnpm approve '1' '2'", "feat", "deny"],
  ["sh -c 'pnpm approve 1 2'", "feat", "deny"],
  ["echo y | pnpm approve 1 2", "feat", "deny"],
  ["FOO=1 pnpm approve 1 2", "feat", "deny"],
  ["echo '{}' >> .git/team-approvals.log", "feat", "deny"],
  ["pnpm approve list", "feat", null],
  ["pnpm approve check 12 merge", "feat", null],
  // Merges and ships need the user in the loop.
  ["gh pr merge 12 --merge --match-head-commit abc", "dev", "ask"],
  ["git push origin main", "dev", "ask"],
  ["git push origin dev:main", "dev", "ask"],
  ["git push", "main", "ask"],
  ["git push origin", "main", "ask"],
  // Force on dev/main is refused; on your own branch it is normal after a rebase.
  ["git push --force origin dev", "feat", "deny"],
  ["git push -f", "main", "deny"],
  ["git push origin +main", "feat", "deny"],
  ["git push --force-with-lease origin feat/x", "feat/x", null],
  ["git push -u origin claude/fix-thing", "claude/fix-thing", null],
  // A chained command is judged per push, not by any word on the line.
  ["git push -u origin feat && git checkout main", "feat", null],
  ["git push origin feat/dev-tools", "feat/dev-tools", null],
  // Bypassing the pre-push hook is the user's call.
  ["git push --no-verify origin feat", "feat", "deny"],
  ["TEAM_SKIP_CHECKS=1 git push origin feat", "feat", "deny"],
  // [skip ci] only on dev.
  ['git commit -m "docs: tweak [skip ci]"', "dev", null],
  ['git commit -m "fix: thing [skip ci]"', "feat", "deny"],
  ["git commit -m \"$(cat <<'EOF'\ndocs; notes\n\n[skip ci]\nEOF\n)\"", "feat", "deny"],
  // CI reruns.
  ["gh run rerun 123", "feat", "deny"],
  ["gh run rerun 123 --failed", "feat", null],
  // A pattern kill reaches other agents' runs; a kill by PID doesn't.
  ["pkill -f vitest", "feat", "deny"],
  ["pkill -9f playwright", "feat", "deny"],
  ["pkill --full next-server", "feat", "deny"],
  ["pkill node", "feat", "deny"],
  ["killall node", "feat", "deny"],
  ["killall -9 Chrome", "feat", "deny"],
  ["killall 'Google Chrome'", "feat", "deny"],
  ["sudo pkill -f node", "feat", "deny"],
  ["kill 12345", "feat", null],
  ["pkill -u me myserver", "feat", null],
  ["killall nodemon-helper", "feat", null],
  ["gh workflow run ci.yml", "feat", "ask"],
  // Deleting data.
  ['psql "$PROD_URL" -c "DROP TABLE users"', "feat", "deny"],
  ["psql -h db.example.com <<SQL\nDELETE FROM users;\nSQL", "feat", "deny"],
  ['psql postgres://me@localhost:5432/app -c "TRUNCATE entries"', "feat", null],
  ["pnpm prisma migrate reset", "feat", "ask"],
  ["neonctl branches delete preview-12", "feat", "deny"],
  ["aws s3 rb s3://user-uploads --force", "feat", "deny"],
  ["terraform destroy", "feat", "deny"],
  // The branch is read where the commit or push runs, not where the hook runs.
  ['cd ~/src/app && git commit -m "docs: notes [skip ci]"', "feat/x", null],
  ['cd ../app && git add docs && git commit -m "docs: notes [skip ci]"', "feat/x", null],
  ['git -C ../x commit -m "fix: thing [skip ci]"', "dev", "deny"],
  ['cd ../nowhere && git commit -m "docs [skip ci]"', "dev", "ask"],
  ["cd ../app && git push --force", "feat/x", "deny"],
  // A bare remote doesn't hide the current branch; flag clusters and other spellings count.
  ["git push --force origin", "dev", "deny"],
  ["git push -f origin", "main", "deny"],
  ["git push origin HEAD", "main", "ask"],
  ["git push -uf origin dev", "feat", "deny"],
  ["git push -fu origin dev", "feat", "deny"],
  ['git push origin "main"', "feat", "ask"],
  ["git push --all --force", "feat", "deny"],
  ["git push --delete origin dev", "feat", "deny"],
  ["git push origin :dev", "feat", "deny"],
  ["sh -c 'git push -f origin main'", "feat", "deny"],
  ['bash -c "git push origin main"', "feat", "ask"],
  ["env FOO=1 bash -c 'git push -f origin main'", "feat", "deny"],
  ['bash -c "git push -f origin \\"main\\""', "feat", "deny"],
  ["sudo sh -c 'terraform destroy'", "feat", "deny"],
  ["git push --all", "feat", "ask"],
  ["git push origin --delete feat/old", "feat", null],
  // base is the template branch its workflow alone writes: no agent push, forced or not.
  ["git push origin HEAD:base", "feat", "deny"],
  ["git push --force origin HEAD:base", "feat", "deny"],
  ["git push origin --delete base", "feat", "deny"],
  ["git push origin refs/heads/base", "feat", "deny"],
  ["git push", "base", "deny"],
  ["gh api -X PATCH repos/o/r/git/refs/heads/base -f sha=abc", "feat", "deny"],
  ["gh api -X DELETE repos/o/r/git/refs/heads/base", "feat", "deny"],
  ["gh api repos/o/r/branches/base/rename -f new_name=old", "feat", "deny"],
  ["gh api repos/o/r/git/refs/heads/base", "feat", null],
  ["git push -u origin feat/base-fix", "feat/base-fix", null],
  ["git push origin HEAD:feat/base", "feat", null],
  ["git push --all", "feat", "ask"],
  // Other roads to a merge or a draft flip.
  ["node scripts/lib/batch-merge.mjs 165 166", "dev", "ask"],
  ["node scripts/lib/batch-merge.mjs 287 --ship", "dev", "ask"],
  ["node scripts/lib/batch-merge.mjs 165 --dry-run", "dev", null],
  ["node --no-warnings scripts/lib/batch-merge.mjs 1 2", "dev", "ask"],
  ["node --import ./x.mjs scripts/lib/batch-merge.mjs 1", "dev", "ask"],
  ["./scripts/lib/batch-merge.mjs 1 --ship", "dev", "ask"],
  // Projects made before the Node port still have the Python merge script.
  ["python3 scripts/lib/batch_merge.py 165 166", "dev", "ask"],
  ["python3 scripts/lib/batch_merge.py 287 --ship", "dev", "ask"],
  ["python3 scripts/lib/batch_merge.py 165 --dry-run", "dev", null],
  ["gh api -X PUT repos/o/r/pulls/12/merge", "feat", "ask"],
  ["gh api repos/o/r/pulls/12", "feat", null],
  ["gh api graphql -f query='mutation { convertPullRequestToDraft(input: {pullRequestId: \"x\"}) { clientMutationId } }'", "feat", "deny"],
  // A destructive word in a search, a file, or a message is not a delete.
  ['grep -rn "terraform destroy" docs', "feat", null],
  ["rg dropdb", "feat", null],
  ['git commit -m "docs: never run dropdb; use neonctl branches reset by hand"', "feat", null],
  ['git commit -m "docs: never terraform destroy" -m "ok"', "feat", null],
  ["cat <<EOF > notes.md\nrun terraform destroy only by hand\nEOF", "feat", null],
  ['echo "DROP TABLE users" | psql "$PROD_URL"', "feat", "deny"],
  ["pnpm exec prisma migrate reset", "feat", "ask"],
  ["sudo terraform destroy", "feat", "deny"],
  // The git, gh, and delete rules read the program behind a wrapper the guard reads.
  ["timeout 5 git push -f origin main", "feat", "deny"],
  ["nohup gh pr merge 12", "feat", "ask"],
  ["timeout 60 gh pr merge 20", "feat", "ask"],
  ["xargs git push -f origin main", "feat", "deny"],
  ["xargs -I{} gh run rerun {}", "feat", "deny"],
  ["sudo -u x gh pr merge 1", "feat", "ask"],
  ["doas git push --force origin dev", "feat", "deny"],
  ["nice -n 5 gh pr ready 3", "feat", "ask"],
  ["corepack pnpm@9 exec gh pr merge 3", "feat", "ask"],
  ["npx -y gh pr ready 3 --undo", "feat", "deny"],
  ["pnpm dlx gh workflow run ci.yml", "feat", "ask"],
  ["pnpm lock status", "feat", null],
  ["pnpm lock take port-3000 --as me", "feat", null],
  ["node scripts/stack.mjs list", "feat", null],
  ["nohup node scripts/lib/batch-merge.mjs 1 2", "dev", "ask"],
  ["ssh host git push -f origin main", "feat", "deny"],
  ["docker exec c git push -f origin main", "feat", "deny"],
  ["kubectl exec p -- dropdb x", "feat", "deny"],
  ["timeout 9 dropdb prod", "feat", "deny"],
  ["doppler run -- git push -f origin main", "feat", "deny"],
  ["eval 'gh pr merge 3'", "feat", "ask"],
  ["strace aws s3 rb s3://b", "feat", "ask"],
  // A shell fed a command on stdin runs it.
  ["echo 'git push -f origin main' | sh", "feat", "deny"],
  ["bash <<'EOF'\ngit push -f origin main\nEOF", "feat", "deny"],
  ["bash <<<'gh pr merge 3'", "feat", "ask"],
  // Exporting the skip switch sets it for the push too.
  ["export TEAM_SKIP_CHECKS=1; git push origin feat", "feat", "deny"],
  ["env TEAM_SKIP_CHECKS=1 git push origin feat", "feat", "deny"],
  // Case arms, function bodies, background jobs, and comments read as bash reads them.
  ["case x in x) git push -f origin main;; esac", "feat", "deny"],
  ["f() { git push -f origin main; }; f", "feat", "deny"],
  ["sleep 1 & git push -f origin main", "feat", "deny"],
  ["cd ../app & git push --force", "feat/x", null],
  ["echo hi # ; git push -f origin main", "feat", null],
  // Everyday commands pass untouched.
  ['grep -rn "DELETE FROM" src', "feat", null],
  ["pnpm test && pnpm lint", "feat", null],
  ["git status", "main", null],
];

describe("guard evaluate", () => {
  for (const [command, branch, expected] of cases) {
    it(`${String(command)} (on ${String(branch)}) → ${String(expected)}`, () => {
      assert.equal(evaluate(command, { branch, branchIn: (dir) => DIRS[dir] ?? "" })?.decision ?? null, expected);
    });
  }
});

// The evaluate() context for a hook that runs on `branch`.
const contextOf = (branch) => ({ branch, branchIn: (dir) => DIRS[dir] ?? "" });

// The filesystem here is case-insensitive, so `GIT` runs git: the program name folds, nothing else does.
describe("guard: program names match case-insensitively", () => {
  const featCtx = contextOf("feat");
  const rows = [
    // [lowercase command, mixed-case command, branch]
    ["git push -f origin main", "GIT push -f origin main", "feat"],
    ["git push origin HEAD", "GIT push origin HEAD", "main"],
    ["gh pr merge 1", "GH pr merge 1", "feat"],
    ['psql -c "DROP TABLE x" postgres://me@db.example.com/prod', 'PSQL -c "DROP TABLE x" postgres://me@db.example.com/prod', "feat"],
    ['git commit -m "[skip ci] x"', 'GIT commit -m "[skip ci] x"', "feat"],
    ["git push -f origin main", "Git push -f origin main", "feat"],
    ["git push -f origin main", "gIt push -f origin main", "feat"],
    ["git push -f origin main", "/usr/bin/GIT push -f origin main", "feat"],
    ["git push -f origin main", "./Git push -f origin main", "feat"],
    ["gh pr merge 1", "/usr/bin/GH pr merge 1", "feat"],
    ["git push -f origin main", "env GIT push -f origin main", "feat"],
    ["git push -f origin main", "sudo GIT push -f origin main", "feat"],
    ["gh pr merge 1", "COMMAND GH pr merge 1", "feat"],
    ["git push -f origin main", "SH -c 'git push -f origin main'", "feat"],
  ];
  for (const [lower, mixed, branch] of rows) {
    const context = contextOf(branch);
    it(`${mixed} → same verdict as ${lower}`, () => {
      const expected = evaluate(lower, context)?.decision ?? null;
      assert.notEqual(expected, null, `${lower} must be refused or asked`);
      assert.equal(evaluate(mixed, context)?.decision ?? null, expected);
    });
  }

  it("arguments stay case-sensitive: a branch called Main is not main", () => {
    assert.equal(evaluate("git push origin Main", featCtx)?.decision ?? null, null);
    assert.equal(evaluate("git push origin feat/MAIN", featCtx)?.decision ?? null, null);
    assert.equal(evaluate("GIT push origin Main", featCtx)?.decision ?? null, null);
    assert.equal(evaluate("GIT push origin feat/MAIN", featCtx)?.decision ?? null, null);
  });
});

// Temp repo roots, removed after the run.
const roots = [];
after(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true });
});

// A throwaway repo root holding `files` ({ path: object → JSON, or string → as is }).
const repoWith = (files) => {
  const root = mkdtempSync(join(tmpdir(), "command-guard-"));
  roots.push(root);
  for (const [path, contents] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), typeof contents === "string" ? contents : JSON.stringify(contents));
  }
  return root;
};

// main()'s readers over a temp tree at `root` (HOME is home/), with `env` as the agent's environment.
const readersIn = (root, env = {}) => {
  const where = (dir) => (dir === null ? root : dir.startsWith("~") ? join(root, "home", dir.slice(1)) : resolve(root, dir));
  // A file's text as main() reads it: a regular file up to 1 MB, else null.
  const file = (dir, path) => {
    try {
      const full = resolve(where(dir), path);
      const found = statSync(full);
      return found.isFile() && found.size <= 1_000_000 ? readFileSync(full, "utf8") : null;
    } catch {
      return null;
    }
  };
  return {
    branch: "feat",
    targetIn: (/** @type {string | null} */ dir, /** @type {string} */ name, /** @type {string | null} */ dotenv = ".env", useEnv = true) => {
      if (useEnv && env[name] !== undefined) return { value: env[name], from: "the environment" };
      const value = dotenv === null ? undefined : dotenvValue(file(dir, dotenv) ?? "", name);
      return value === undefined ? null : { value, from: dotenv };
    },
    scriptIn: (dir, name) => {
      try {
        return JSON.parse(file(dir, "package.json") ?? "").scripts?.[name] ?? "";
      } catch {
        return "";
      }
    },
    fileIn: file,
    // main()'s dirIn, without its entry cap (these trees are small).
    dirIn: (dir, path) => {
      try {
        const full = resolve(where(dir), path);
        if (!statSync(full).isDirectory()) return { dir: false };
        const entries = readdirSync(full, { withFileTypes: true });
        return { dir: true, files: entries.filter((each) => !each.isDirectory()).map((each) => each.name), dirs: entries.filter((each) => each.isDirectory()).map((each) => each.name), more: false };
      } catch {
        return null;
      }
    },
    dirExists: (dir) => {
      try {
        return statSync(where(dir)).isDirectory();
      } catch {
        return false;
      }
    },
  };
};

// The decision for `command` under `rules`, on a feature branch.
const decide = (command, rules) => evaluate(command, { branch: "feat", branchIn: (dir) => DIRS[dir] ?? "", rules })?.decision ?? null;

describe("freeze marker: no push to dev while a release PR is open", () => {
  // The marker as shipFreezeIn reads it: the hook's cwd (null) and ../app are frozen at PR 29, ../feat-wt is not.
  const FROZEN = new Map([[null, "29"], ["../app", "29"]]);
  const frozen = (command, branch = "feat") =>
    evaluate(command, { branch, branchIn: (dir) => DIRS[dir] ?? "", shipFreezeIn: (dir) => FROZEN.get(dir) ?? null }) ?? null;
  // [command, branch where the hook runs, expected decision or null]
  const rows = [
    ["git push", "dev", "deny"],
    ["git push origin dev", "feat", "deny"],
    ["git push origin HEAD:dev", "feat", "deny"],
    ["git push origin feat:refs/heads/dev", "feat", "deny"],
    ["git push -u origin @", "dev", "deny"],
    ["git -C ../app push", "feat", "deny"],
    ['git commit -m "docs: plan State [skip ci]" && git push origin dev', "dev", "deny"],
    ["git push origin feat", "feat", null],
    ["git push", "feat", null],
    // A worktree of another clone with no marker.
    ["cd ../feat-wt && git push origin dev", "feat", null],
  ];
  for (const [command, branch, expected] of rows) {
    it(`${command} (on ${branch}) → ${String(expected)}`, () => {
      assert.equal(frozen(command, branch)?.decision ?? null, expected);
    });
  }

  it("names the ship PR and says to push after the merge", () => {
    assert.match(frozen("git push origin dev")?.reason ?? "", /release PR #29 is open.*after the merge/);
  });

  it("lets a push to dev through with no marker", () => {
    assert.equal(evaluate("git push origin dev", { branch: "feat", shipFreezeIn: () => null }), null);
  });

  it("reads the marker from the clone's shared git dir, so every worktree sees it", () => {
    const root = mkdtempSync(join(tmpdir(), "ship-freeze-"));
    roots.push(root);
    const git = (...args) => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", ...args], { cwd: root, encoding: "utf8" });
    git("init", "-q", "-b", "dev");
    git("commit", "-q", "--allow-empty", "-m", "base");
    git("worktree", "add", "-q", "-b", "feat", join(root, "wt"));
    assert.equal(shipFreeze(join(root, "wt")), null);
    writeFileSync(join(root, ".git", SHIP_FREEZE_FILE), "29\n");
    assert.equal(shipFreeze(join(root, "wt")), "29");
    assert.equal(shipFreeze(root), "29");
  });
});

describe("project rules: an absent file", () => {
  const rules = loadRules(repoWith({}));

  it("loads as no rules", () => {
    assert.equal(rules.error, "");
  });

  for (const [command, branch, expected] of cases) {
    it(`${String(command)} (on ${String(branch)}) → ${String(expected)}, as without the file`, () => {
      assert.equal(evaluate(command, { branch, branchIn: (dir) => DIRS[dir] ?? "", rules })?.decision ?? null, expected);
    });
  }
});

describe("project rules: a file that is present but doesn't load refuses every command", () => {
  const PROJECT = "reins.json";
  const PACK = ".reins/infra.json";
  const rule = { match: "^make\\s+deploy\\b", reason: "Deploys go through CI." };
  // [what is wrong, files, the file and error the refusal must name]
  const broken = [
    ["malformed JSON", { [PROJECT]: '{ "deny": [ }' }, /^reins\.json didn't load \(.*JSON/],
    ["an empty file", { [PROJECT]: "" }, /^reins\.json didn't load \(.*JSON/],
    ["a regex that doesn't compile", { [PROJECT]: { deny: [{ ...rule, match: "^(make" }] } }, /deny\[0\]\.match: Invalid regular expression/],
    ["an `unless` that doesn't compile", { [PROJECT]: { ask: [{ ...rule, unless: "[" }] } }, /ask\[0\]\.unless: Invalid regular expression/],
    ["a misspelled kind", { [PROJECT]: { denny: [rule] } }, /unknown key "denny"/],
    ["a misspelled field", { [PROJECT]: { deny: [{ ...rule, resaon: "x" }] } }, /deny\[0\] has an unknown key "resaon"/],
    ["a missing reason", { [PROJECT]: { deny: [{ match: rule.match }] } }, /deny\[0\]\.reason must be a non-empty string/],
    ["a stateful regex flag", { [PROJECT]: { deny: [{ ...rule, flags: "g" }] } }, /deny\[0\]\.flags may only be "i"/],
    ["a kind that isn't a list", { [PROJECT]: { ask: rule } }, /"ask" must be an array/],
    ["a top level that isn't an object", { [PROJECT]: [] }, /the top level must be an object/],
    ["a kind given twice (JSON keeps only the last)", { [PROJECT]: '{ "deny": [], "deny": [] }' }, /"deny" appears twice in one object/],
    ["a field given twice in one rule", { [PROJECT]: '{ "deny": [{ "match": "^a", "match": "^b", "reason": "x" }] }' }, /"match" appears twice in one object/],
    ["an exemption that expands a variable", { [PROJECT]: { allow: [{ command: "dropdb $DB", reason: "x" }] } }, /allow\[0\]\.command must be one plain command/],
    ["an exemption that chains a second command", { [PROJECT]: { allow: [{ command: "dropdb a && dropdb b", reason: "x" }] } }, /allow\[0\]\.command must be one plain command/],
    ...["dropdb app_*", "dropdb app_?", "dropdb [ab]", "dropdb app_{a,b}", "dropdb ~/db"].map((command) => [`an exemption with a glob, brace, or ~: ${command}`, { [PROJECT]: { allow: [{ command, reason: "x" }] } }, /allow\[0\]\.command must be one plain command/]),
    // An exemption may lift only a data-delete deny; one that meets any other built-in rule is a broken file.
    ...[
      "git push --force origin main",
      "gh pr ready 5 --undo",
      "git push --no-verify",
      "TEAM_SKIP_CHECKS=1 git push",
      "bash -c 'git push --force origin main'",
      "git push --force",
      "gh pr ready 12",
      'psql -h db.example.com -c "DROP TABLE t"',
      "prisma migrate reset --force",
      "DATABASE_URL=postgres://db.example.com/app prisma migrate dev",
    ].map((command) => [`an exemption for a rule it can't lift: ${command}`, { [PROJECT]: { allow: [{ command, reason: "x" }] } }, /allow\[0\]\.command meets a built-in rule an exemption can't lift/]),
    ["a pack that exempts", { [PACK]: { allow: [{ command: "terraform destroy", reason: "x" }] } }, /^\.reins\/infra\.json didn't load \(.*unknown key "allow"/],
    ["a pack that doesn't parse", { [PACK]: "{" }, /^\.reins\/infra\.json didn't load/],
  ];

  for (const [label, files, names] of broken) {
    it(typeof label === "string" ? label : "broken rule file", () => {
      const rules = loadRules(repoWith(files));
      assert.match(rules.error, names);
      // The agent is sent to the user, not invited to edit its own guard rules.
      assert.match(rules.error, /Stop and tell the user/);
      for (const command of ["git status", "ls", "pnpm test", ""]) {
        assert.deepEqual(evaluate(command, { rules }), { decision: "deny", reason: rules.error });
      }
    });
  }

  it("a directory where the file should be", () => {
    const root = repoWith({});
    mkdirSync(join(root, PROJECT));
    assert.equal(decide("ls", loadRules(root)), "deny");
  });

  it("a symlink to a file that isn't there", () => {
    const root = repoWith({});
    symlinkSync(join(root, "gone.json"), join(root, PROJECT));
    assert.match(loadRules(root).error, /^reins\.json didn't load/);
  });

  it("files in the pack directory that aren't .json are ignored", () => {
    assert.equal(loadRules(repoWith({ ".reins/README.md": "# packs" })).error, "");
  });
});

describe("project rules: deny, ask, and exemptions", () => {
  const rules = loadRules(
    repoWith({
      "reins.json": {
        $comment: "Neutral examples: a deny, a deny with unless, an ask, and exemptions.",
        deny: [
          { match: "^make\\s+deploy\\b", reason: "Deploys go through CI." },
          { match: "^db-reseed\\b", unless: "DATABASE_URL=postgres://localhost(:\\d+)?/\\w+ ", reason: "Reseeds only a loopback database." },
          { match: "^dropdb\\s+app_keep\\b", reason: "Never this one." },
        ],
        ask: [{ match: "^npm\\s+publish\\b", reason: "Publishing is the user's call." }],
        allow: [
          { command: "dropdb app_test", reason: "The throwaway test database." },
          { command: 'dropdb "app test"', reason: "A quoted name with a space is one word." },
          { command: "dropdb app_keep", reason: "Lifts the built-in deny; the project's own deny still stands." },
          { command: "pulumi up --stack scratch", reason: "Lifts a pack deny." },
        ],
      },
      ".reins/iac.json": { deny: [{ match: "^pulumi\\s+up\\b", reason: "Applies go through CI." }] },
    }),
  );

  // [command, expected decision]
  const rows = [
    // A deny reads the command in command position.
    ["make deploy", "deny"],
    ["make test", null],
    ['grep -rn "make deploy" docs', null],
    // Chains, prefixes, quoting, and `bash -c` get no bypass.
    ["pnpm test && make deploy", "deny"],
    ["git status; make deploy", "deny"],
    ["make test || make deploy", "deny"],
    ["FOO=1 make deploy", "deny"],
    ["env FOO=1 make deploy", "deny"],
    ["sudo make deploy", "deny"],
    ['"make" deploy', "deny"],
    ["bash -c 'make deploy'", "deny"],
    ['sh -c "pnpm test && make deploy"', "deny"],
    ["env FOO=1 bash -c 'make deploy'", "deny"],
    // Ask, and deny beats ask.
    ["npm publish", "ask"],
    ["npm publish && make deploy", "deny"],
    // `unless` sees the inline assignment that `match` doesn't, and reads from the first word.
    ["db-reseed", "deny"],
    ["DATABASE_URL=postgres://localhost:5432/app db-reseed", null],
    ["DATABASE_URL=postgres://db.example.com/app db-reseed", "deny"],
    // The shell uses a variable's last assignment, and so does `unless`.
    ["DATABASE_URL=postgres://localhost:5432/app DATABASE_URL=postgres://db.example.com/app db-reseed", "deny"],
    ["DATABASE_URL=postgres://db.example.com/app DATABASE_URL=postgres://localhost:5432/app db-reseed", null],
    ["db-reseed --note DATABASE_URL=postgres://localhost/app now", "deny"],
    // An exemption lifts the built-in deny of exactly that command, quotes and spacing aside.
    ["dropdb app_test", null],
    ['dropdb "app_test"', null],
    ["dropdb  app_test", null],
    ["bash -c 'dropdb app_test'", null],
    ['dropdb "app test"', null],
    // Anything more or different stays refused: another name, an extra argument, a prefix that can retarget it.
    ["dropdb app_test2", "deny"],
    ["dropdb app_test other_db", "deny"],
    ["dropdb other", "deny"],
    ["PGHOST=db.example.com dropdb app_test", "deny"],
    ["sudo dropdb app_test", "deny"],
    ["dropdb app_test > /dev/null", "deny"],
    ["dropdb app_test && dropdb app", "deny"],
    ["dropdb app_test & dropdb app", "deny"],
    ["dropdb app test", "deny"],
    // The project's own deny beats its exemption.
    ["dropdb app_keep", "deny"],
    // Pack rules load from the pack directory, and an exemption can lift one.
    ["pulumi up", "deny"],
    ["pulumi up --stack scratch", null],
    ["pulumi preview", null],
  ];

  it("loads", () => {
    assert.equal(rules.error, "");
  });

  for (const [command, expected] of rows) {
    it(`${String(command)} → ${String(expected)}`, () => {
      assert.equal(decide(command, rules), expected);
    });
  }

  it("names the file a refusal came from", () => {
    assert.equal(evaluate("make deploy", { rules })?.reason, "Deploys go through CI. (reins.json)");
    assert.equal(evaluate("pulumi up", { rules })?.reason, "Applies go through CI. (.reins/iac.json)");
  });
});

// A temp repo with a copy of the package in pkg/ and a project's own hook entry, pkg/hook.mjs,
// which runs main() with the test's sets and files, the way a project's adapter would. Rule files
// are read from the repo root (the hook passes it), whatever the hook's cwd.
const PACKAGE = fileURLToPath(new URL("..", import.meta.url));
const HOOK_ENTRY = `import { fileURLToPath } from "node:url";
import { main } from "./src/guard.mjs";
const here = (path) => fileURLToPath(new URL(path, import.meta.url));
main({ root: here(".."), files: ${JSON.stringify(TEST_FILES)}, sets: ["draft-flow", here("team.json"), "merge-conveyor", "ci-minutes", "chute-boss"] });
`;
const guardIn = (files) => {
  const root = repoWith(files);
  for (const dir of ["src", "sets", "bin"]) copyDir(join(PACKAGE, dir), join(root, "pkg", dir));
  copyFileSync(TEAM_SET, join(root, "pkg", "team.json"));
  writeFileSync(join(root, "pkg", "hook.mjs"), HOOK_ENTRY);
  return root;
};
const copyDir = (from, to) => {
  mkdirSync(to, { recursive: true });
  for (const name of readdirSync(from)) copyFileSync(join(from, name), join(to, name));
};

// Runs the hook as a host would, from a cwd outside the repo (or `cwd`), with the off switch and database URLs unset.
const run = (root, host, command, cwd = tmpdir(), extraEnv = {}) => {
  const env = { ...process.env };
  for (const name of ["REINS", "WHIPPLETREE_GUARD", "DATABASE_URL", "GOOSE_DBSTRING", "PGHOSTADDR", "PGSERVICE", "PGHOST", "CDPATH", "CLAUDE_PROJECT_DIR"]) delete env[name];
  return execFileSync(process.execPath, [join(root, "pkg", "hook.mjs"), host], { input: JSON.stringify({ tool_input: { command }, command, cwd }), env: { ...env, ...extraEnv }, encoding: "utf8" });
};

// Rules exempting `command`, built by hand to skip loadRules' check; the key is the command's words, as the guard stores it.
const exempting = (command) => ({ deny: [], ask: [], allow: new Set([JSON.stringify(words(command))]), error: "" });

describe("project rules: an exemption that got past the schema still lifts only a data-delete deny", () => {
  // [command, exempted command, branch, expected]
  const rows = [
    ["git push --force origin main", "git push --force origin main", "feat", "deny"],
    ["gh pr ready 5 --undo", "gh pr ready 5 --undo", "feat", "deny"],
    ["git push --no-verify", "git push --no-verify", "feat", "deny"],
    ["TEAM_SKIP_CHECKS=1 git push", "TEAM_SKIP_CHECKS=1 git push", "feat", "deny"],
    ["bash -c 'git push --force origin main'", "git push --force origin main", "feat", "deny"],
    ["git push --force", "git push --force", "main", "deny"],
    ["gh pr ready 12", "gh pr ready 12", "feat", "ask"],
    ['psql -h db.example.com -c "DROP TABLE t"', 'psql -h db.example.com -c "DROP TABLE t"', "feat", "deny"],
    ["dropdb app_test", "dropdb app_test", "feat", null],
  ];

  for (const [command, exempted, branch, expected] of rows) {
    it(`${String(command)} (exempting ${String(exempted)}, on ${String(branch)}) → ${String(expected)}`, () => {
      assert.equal(evaluate(command, { branch, rules: exempting(exempted) })?.decision ?? null, expected);
    });
  }
});

// The rules that moved from the guard's code into its rule sets (.team-rules/) stay out
// of an exemption's reach: a set's row is never liftable, as the code's rules never were. Each row
// passes before the move too, so it tests the move, not new behavior.
describe("rule sets: an exemption can't lift a rule that moved into a set", () => {
  // [moved deny, command, whether an allow for it breaks reins.json, extra evaluate() options]
  /** @type {[string, string, boolean, Record<string, unknown>][]} */
  const rows = [
    ["autopilot on", "pnpm autopilot on 2", true, {}],
    ["approve", "pnpm approve 12 hooks", true, {}],
    ["conveyor tick", "pnpm conveyor tick", true, {}],
    ["a raw conveyor/cleared post", "gh api repos/o/r/statuses/abc -f state=success -f context=conveyor/cleared", true, {}],
    // The brackets are shell syntax, so the allow is refused before the rule is reached.
    ["[skip ci] on a feature branch", 'git commit -m "docs [skip ci]"', false, {}],
    // exemption() reads no freeze marker, so this allow loads; the verdict still stands.
    ["a push to dev with the freeze marker set", "git push origin dev", false, { shipFreezeIn: () => "29" }],
  ];
  for (const [label, command, breaksFile, extra] of rows) {
    it(`${label}: still denied when exempted`, () => {
      assert.equal(evaluate(command, { branch: "feat", rules: exempting(command), ...extra })?.decision, "deny");
    });
    if (breaksFile) {
      it(`${label}: an allow for it breaks reins.json`, () => {
        const rules = loadRules(repoWith({ "reins.json": { allow: [{ command, reason: "x" }] } }));
        assert.match(rules.error, /allow\[0\]\.command meets a built-in rule an exemption can't lift/);
      });
    }
  }
});

// Rules loaded from a repo whose branches.json holds `value` (none when undefined).
const withBranches = (value) => loadRules(repoWith(value === undefined ? {} : { "branches.json": value }));
// The decision for `command` under `rules`, on `branch`.
const on = (rules, command, branch = "feat") => evaluate(command, { branch, rules })?.decision ?? null;

describe("protected branches: branches.json's protectedBranches", () => {

  it("defaults to main, dev, and base, with only base's workflow writing it", () => {
    for (const rules of [withBranches(undefined), withBranches({ eject: {} })]) {
      assert.equal(rules.error, "");
      assert.deepEqual([...rules.branches.protected], ["main", "dev", "base"]);
      assert.equal(on(rules, "git push -f origin dev"), "deny");
      assert.equal(on(rules, "git push origin HEAD:base"), "deny");
      assert.equal(on(rules, "git push -f origin release"), null);
    }
  });

  it("a list replaces the defaults, for pushes and the API alike", () => {
    const rules = withBranches({ protectedBranches: ["main", "release"] });
    assert.equal(rules.error, "");
    assert.equal(on(rules, "git push -f origin release"), "deny");
    assert.equal(on(rules, "git push --delete origin release"), "deny");
    assert.equal(on(rules, "git push -f", "release"), "deny");
    assert.equal(on(rules, "git push origin main", "dev"), "ask");
    assert.equal(on(rules, "gh api repos/o/r/branches/release/rename -f new_name=old"), "deny");
    assert.equal(on(rules, "gh api -X DELETE repos/o/r/git/refs/heads/release"), "deny");
    // dev and base are ordinary branches here, base's workflow-only rule included.
    assert.equal(on(rules, "git push -f origin dev"), null);
    assert.equal(on(rules, "git push origin HEAD:base"), null);
    assert.equal(on(rules, "gh api repos/o/r/branches/dev/rename -f new_name=old"), null);
  });

  it("base listed keeps its workflow-only rule", () => {
    const rules = withBranches({ protectedBranches: ["main", "base"] });
    assert.equal(on(rules, "git push origin HEAD:base"), "deny");
    assert.equal(on(rules, "git push -f origin dev"), null);
  });

  it("a value that isn't a list of branch names refuses every command, naming the file", () => {
    for (const value of [{ protectedBranches: [] }, { protectedBranches: "main" }, { protectedBranches: ["main", 1] }, { protectedBranches: ["a b"] }, { protectedBranches: ["-x"] }, "{"]) {
      const rules = withBranches(value);
      assert.match(rules.error, /^branches\.json didn't load/, JSON.stringify(value));
      assert.deepEqual(evaluate("git status", { rules }), { decision: "deny", reason: rules.error });
    }
  });

  it("writing branches.json from the shell is the user's call", () => {
    assert.equal(on(withBranches(undefined), "echo '{}' > branches.json"), "ask");
  });
});

// The test's rule sets as loadRules() reads them here, and a temp copy of them, each set's text
// passed through `edit(name, data)` (return undefined to leave a set out): the copy's paths, in order.
// `name` is the bundled set's name, or "team" for the fixture.
const setName = (entry) => (entry === TEAM_SET ? "team" : entry);
const SET_NAMES = TEST_SETS.map(setName);
const setsCopy = (edit = (name, data) => data) => {
  const dir = repoWith({});
  const from = fileURLToPath(new URL("../sets/", import.meta.url));
  return TEST_SETS.map((entry) => {
    const name = setName(entry);
    const source = entry === TEAM_SET ? TEAM_SET : join(from, `${name}.json`);
    const data = edit(name, JSON.parse(readFileSync(source, "utf8")));
    if (data !== undefined) writeFileSync(join(dir, `${name}.json`), JSON.stringify(data));
    return join(dir, `${name}.json`);
  });
};

describe("rule sets: a team's rules load from the paths the caller names, and each set must load", () => {
  it("loads the bundled sets by name, and the team's by path", () => {
    assert.deepEqual(TEST_RULES.loaded, TEST_SETS);
    assert.equal(loadRules(repoWith({}), { sets: setsCopy() }).error, "");
  });

  it("dev and base are protected by the team's set: without its protectedBranches, a force-push to dev isn't refused", () => {
    const rules = loadRules(repoWith({}), { sets: setsCopy((name, data) => (name === "team" ? { ...data, protectedBranches: undefined } : data)) });
    assert.equal(rules.error, "");
    assert.notEqual(on(rules, "git push -f origin dev"), "deny");
    assert.equal(on(loadRules(repoWith({}), { sets: setsCopy() }), "git push -f origin dev"), "deny");
  });

  it("team.json absent: every command is refused, naming it", () => {
    const rules = loadRules(repoWith({}), { sets: setsCopy((name, data) => (name === "team" ? undefined : data)) });
    assert.match(rules.error, /team\.json didn't load/);
    assert.match(rules.error, /Stop and tell the user/);
    for (const command of ["ls", "git status", ""]) assert.deepEqual(evaluate(command, { rules }), { decision: "deny", reason: rules.error });
  });

  it("a set list naming draft-flow-typo: every command is refused, naming it", () => {
    const rules = loadRules(repoWith({}), { sets: TEST_SETS.map((name) => (name === "draft-flow" ? "draft-flow-typo" : name)) });
    assert.match(rules.error, /draft-flow-typo/);
    assert.deepEqual(evaluate("ls", { rules }), { decision: "deny", reason: rules.error });
  });

  it("a set that is present but broken refuses every command, naming it and the field", () => {
    for (const [edit, names] of [
      [(data) => ({ ...data, allow: [{ command: "ls", reason: "x" }] }), /unknown key "allow"/],
      [(data) => ({ ...data, statusContexts: [{ match: "^x/", reason: "x" }] }), /statusContexts\[0\]\.verdict must be "deny" or "ask"/],
      [(data) => ({ ...data, deny: [{ on: "argv", match: "^x", reason: "x" }] }), /deny\[0\]\.on must be "program" or "segment"/],
      [(data) => ({ ...data, protectedBranches: [] }), /"protectedBranches" must be a non-empty array of branch names/],
    ]) {
      const rules = loadRules(repoWith({}), { sets: setsCopy((name, data) => (name === "ci-minutes" ? edit(data) : data)) });
      assert.match(rules.error, /ci-minutes\.json didn't load/);
      assert.match(rules.error, names);
      assert.deepEqual(evaluate("ls", { rules }), { decision: "deny", reason: rules.error });
    }
  });

  it("a set with nothing in it ({}) refuses every command, naming it", () => {
    const rules = loadRules(repoWith({}), { sets: setsCopy((name, data) => (name === "ci-minutes" ? {} : data)) });
    assert.match(rules.error, /ci-minutes\.json didn't load \(it holds no rows or knobs/);
    assert.deepEqual(evaluate("ls", { rules }), { decision: "deny", reason: rules.error });
  });

  it("an unreadable status context or variable asks, built in, with any set that guards one (merge-conveyor alone)", () => {
    const alone = loadRules(repoWith({}), { sets: ["merge-conveyor"] });
    assert.equal(alone.error, "");
    for (const command of ["gh api repos/o/r/statuses/abc -f state=success -f context=$C", "gh api repos/o/r/statuses/abc --input body.json", "gh api repos/o/r/statuses/abc -f context=@ctx.txt"]) {
      assert.deepEqual(evaluate(command, { branch: "feat", rules: alone }), { decision: "ask", reason: "This posts a commit status whose context the guard can't read (a variable, a glob, `@file`, or an `--input` body), and a rule set guards some contexts: the user confirms." });
    }
    // The conveyor's row without its own unreadable texts: the built-in ones ask.
    const bare = loadRules(repoWith({}), { sets: setsCopy((name, data) => (name === "merge-conveyor" ? { ...data, repoVariables: data.repoVariables.map(({ unreadableBody: _body, unreadableName: _name, ...row }) => row) } : data)).filter((path) => path.endsWith("merge-conveyor.json")) });
    assert.equal(bare.error, "");
    assert.match(evaluate('gh variable set "$n" --body on', { branch: "feat", rules: bare })?.reason ?? "", /whose name the shell fills in/);
    assert.match(evaluate("gh variable set -f vars.env", { branch: "feat", rules: bare })?.reason ?? "", /a body the guard doesn't open/);
    assert.match(evaluate("gh api -X PATCH repos/o/r/actions/variables/X --input body.json", { branch: "feat", rules: bare })?.reason ?? "", /a body the guard doesn't open/);
    // With no set that guards a status context, a status post is the core's business only.
    assert.equal(on(loadRules(repoWith({}), { sets: ["draft-flow"] }), "gh api repos/o/r/statuses/abc -f context=$C"), null);
  });

  it("a project file in the hook's root can't stand in for a set", () => {
    const root = repoWith({ "team.json": {}, "sets/team.json": {} });
    assert.equal(on(loadRules(root), "git push -f origin dev"), "deny");
  });
});

describe("databases: migration tools and SQL clients, judged by where they point", () => {
  // What the disk holds where a command runs: `.env` database URLs, package.json scripts, SQL files.
  const LOCAL_URL = "postgresql://app:app@localhost:5432/app?schema=public";
  const REMOTE_URL = "postgresql://u:secret@ep-quiet-1.us-east-2.aws.neon.tech/app";
  const ENV_FILES = { local: { DATABASE_URL: LOCAL_URL }, prod: { DATABASE_URL: REMOTE_URL } };
  const SCRIPTS = { "db:reset": "prisma migrate reset --force", "db:migrate": "prisma migrate dev", "db:push": "prisma db push", "db:deploy": "prisma migrate deploy", nuke: "dropdb app", self: "pnpm self", test: "vitest run" };
  const FILES = { "drop.sql": "BEGIN;\nDROP TABLE users;\nCOMMIT;\n", "add.sql": "CREATE TABLE tag (id int);\n" };
  const options = {
    branch: "feat",
    targetIn: (dir, name) => {
      const value = ENV_FILES[dir ?? "."]?.[name];
      return value === undefined ? null : { value, from: ".env" };
    },
    scriptIn: (_dir, name) => SCRIPTS[name] ?? "",
    // local/ and prod/ hold a schema whose datasource names DATABASE_URL: a reset runs only once the guard has read one.
    fileIn: (dir, path) => (path === "prisma/schema.prisma" ? (dir !== null && dir in ENV_FILES ? SCHEMA : null) : (FILES[path] ?? null)),
  };

  // [command, expected decision]
  const rows = [
    // Each destructive migrate spelling is refused against a non-loopback database, however the URL arrives.
    ["DATABASE_URL=postgres://u:p@db.example.com/app pnpm prisma migrate reset", "deny"],
    ["cd prod && pnpm prisma migrate reset --force", "deny"],
    ["cd prod && pnpm db:reset", "deny"],
    ["cd prod && npm run db:reset", "deny"],
    ["cd prod && pnpm db:push --accept-data-loss", "deny"],
    ["DATABASE_URL=postgres://db.example.com/app npx prisma db push --force-reset", "deny"],
    ["export DATABASE_URL=postgres://db.example.com/app && prisma migrate reset", "deny"],
    ["DATABASE_URL=postgres://db.example.com/app; prisma migrate reset", "deny"],
    ['bash -c "cd prod && pnpm db:reset"', "deny"],
    ["cd prod && pnpm nuke", "deny"],
    ["sqlx database reset --database-url postgres://db.example.com/app", "deny"],
    ["sqlx migrate revert -D postgres://db.example.com/app", "deny"],
    ["DATABASE_URL=postgres://db.example.com/app sqlx database drop -y", "deny"],
    ["diesel database reset --database-url=postgres://db.example.com/app", "deny"],
    ['goose -dir db/migrations postgres "host=db.example.com dbname=app" down', "deny"],
    ['GOOSE_DBSTRING="host=db.example.com dbname=app" goose -dir db/migrations reset', "deny"],
    ['GOOSE_DBSTRING="host=localhost dbname=app host=db.example.com" goose -dir db/migrations reset', "deny"],
    ['GOOSE_DBSTRING="host=localhost dbname=app" goose -dir db/migrations reset', null],
    ["migrate -path db/migrations -database postgres://db.example.com/app drop -f", "deny"],
    ["DATABASE_URL=postgres://db.example.com/app alembic downgrade -1", "deny"],
    // A loopback-looking URL that isn't: a query host wins, a lookalike name, a multi-host list.
    ['DATABASE_URL="postgres://localhost/app?host=db.example.com" prisma migrate reset', "deny"],
    ["DATABASE_URL=postgres://localhost.example.com/app prisma migrate reset", "deny"],
    ["DATABASE_URL=postgres://localhost,db.example.com/app prisma migrate reset", "deny"],
    // The line's own setting wins over .env, as the shell and dotenv decide it.
    ["cd local && DATABASE_URL=postgres://db.example.com/app pnpm db:reset", "deny"],
    ["cd prod && DATABASE_URL=postgres://127.0.0.1/app pnpm db:reset", null],
    // On loopback (or a SQLite file, or a socket) they are the agent's to run.
    ["cd local && pnpm db:reset", null],
    ["cd local && DATABASE_URL=postgres://me@127.0.0.1:5432/app pnpm prisma migrate reset --force", null],
    ['cd prod && DATABASE_URL="postgres://u@%2Fvar%2Frun%2Fpostgresql/app" prisma migrate reset', null],
    ["sqlx database reset -D sqlite://dev.db -y", null],
    ['goose -dir db/migrations postgres "host=localhost dbname=app" down', null],
    ["migrate -path db/migrations -database postgres://[::1]:5432/app down 1", null],
    // Can't see where it points: the user confirms.
    ["prisma migrate reset", "ask"],
    ["DATABASE_URL=$PROD_URL prisma migrate reset", "ask"],
    ["cd local && doppler run -- prisma migrate reset", "ask"],
    ["cd local && dotenv -e .env.production -- pnpm prisma migrate reset", "ask"],
    ["cd local && source .env.production && prisma migrate reset", "ask"],
    ["alembic -c prod.ini downgrade base", "ask"],
    // `migrate dev` is refused only against a real database: it offers a reset when history differs.
    ["cd prod && pnpm db:migrate", "deny"],
    ["DATABASE_URL=postgres://db.example.com/app prisma migrate dev", "deny"],
    ["cd local && pnpm db:migrate", null],
    ["DATABASE_URL=postgresql://app:app@localhost:5432/app pnpm exec prisma migrate dev --name add_tag", null],
    ["DATABASE_URL=postgres://127.0.0.1:5432/app npx prisma migrate dev --create-only", null],
    ["pnpm prisma migrate dev", null],
    ["pnpm prisma migrate deploy", null],
    ["pnpm exec prisma migrate deploy", null],
    ["cd local && pnpm db:deploy", null],
    ["cd prod && pnpm prisma migrate status", null],
    ["cd local && pnpm db:push", null],
    ["pnpm test", null],
    ["pnpm self", null],
    // Applying to a real database is the user's or CI's: the user confirms.
    ["cd prod && pnpm db:deploy", "ask"],
    ["sqlx migrate run --database-url postgres://db.example.com/app", "ask"],
    // SQL clients: the host is parsed, not searched for, and a file they run is read.
    ['psql -h db.example.com -c "DROP TABLE users -- localhost"', "deny"],
    // A host the guard can't read (`$VAR`) with readable destructive SQL asks; a known remote host is refused.
    ['psql -h localhost "$PROD_URL" -c "DROP TABLE users"', "ask"],
    ['psql "postgresql://localhost/app?host=db.example.com" -c "DROP TABLE t"', "deny"],
    ['psql postgres://me@localhost.example.com/app -c "TRUNCATE t"', "deny"],
    ['psql "$PROD_URL" -f drop.sql', "ask"],
    ['psql "$PROD_URL" --file=drop.sql', "ask"],
    ['psql "$PROD_URL" < drop.sql', "ask"],
    ["prisma db execute --file drop.sql", "ask"],
    ["psql -h db.example.com -f drop.sql", "deny"],
    ['psql -h localhost -c "DROP TABLE users"', null],
    // The floor (the original whole-line rule) sees no loopback word in `-hlocalhost`, so it refuses.
    ['psql -hlocalhost -c "TRUNCATE t"', "deny"],
    ['psql -hlocalhost -c "SELECT 1"', null],
    ['psql -h 127.0.0.1 -c "DELETE FROM t WHERE id = $ID"', null],
    ["psql -h localhost -f drop.sql", null],
    ['psql "$PROD_URL" -f add.sql', null],
    // Words about these commands are not the commands.
    ['grep -rn "prisma migrate reset" docs', null],
    ['git commit -m "docs: never prisma migrate reset prod"', null],
  ];

  for (const [command, expected] of rows) {
    it(`${String(command)} → ${String(expected)}`, () => {
      assert.equal(evaluate(command, options)?.decision ?? null, expected);
    });
  }

  it("never echoes the URL, which can hold a password", () => {
    const reason = evaluate("cd prod && pnpm db:reset", options)?.reason ?? "";
    assert.match(reason, /non-loopback database \(DATABASE_URL from \.env\)/);
    assert.ok(!reason.includes("secret") && !reason.includes("neon.tech"), reason);
  });
});

// Each row was a bypass or a false positive.
describe("databases: what the resolver doesn't model asks, and never allows", () => {
  const REMOTE = "postgresql://u:secret@ep-quiet-1.us-east-2.aws.neon.tech/app";
  const LOCAL = "postgresql://u:p@localhost:5432/app";
  const R = "postgres://u@db.example.com/app";
  // A project tree read the way the hook reads it: cwd has a loopback .env; prod/ a remote one;
  // twice/ sets DATABASE_URL twice (the last wins); withprisma/ hides a remote URL in prisma/.env.
  const root = repoWith({
    ".env": `DATABASE_URL=${LOCAL}\nGOOSE_DBSTRING="host=localhost dbname=app"\n`,
    "prisma/schema.prisma": SCHEMA,
    "prod/.env": `DATABASE_URL=${REMOTE}\n`,
    "prod/prisma/schema.prisma": SCHEMA,
    "twice/.env": `DATABASE_URL=${LOCAL}\nDATABASE_URL=${REMOTE}\n`,
    "withprisma/.env": `DATABASE_URL=${LOCAL}\n`,
    "withprisma/prisma/.env": `DATABASE_URL=${REMOTE}\n`,
    "big.sql": `-- ${"x".repeat(1_000_001)}\nDROP TABLE users;\n`,
    "drop.sql": "DROP TABLE users;\n",
    "select.sql": "SELECT 1;\n",
    "package.json": { scripts: { "db:reset": "prisma migrate reset --force" } },
  });
  // The hook's readers (main()), over the temp tree and an empty environment.
  const at = (dir, path) => join(dir === null ? root : join(root, dir), path);
  const text = (dir, path) => {
    try {
      const full = at(dir, path);
      return statSync(full).size <= 1_000_000 ? readFileSync(full, "utf8") : null;
    } catch {
      return null;
    }
  };
  const options = {
    branch: "feat",
    targetIn: (/** @type {string | null} */ dir, /** @type {string} */ name, /** @type {string | null} */ file = ".env") => {
      const value = file === null ? undefined : dotenvValue(text(dir, file) ?? "", name);
      return value === undefined ? null : { value, from: file };
    },
    scriptIn: (dir, name) => {
      try {
        return JSON.parse(text(dir, "package.json") ?? "").scripts?.[name] ?? "";
      } catch {
        return "";
      }
    },
    fileIn: text,
  };

  // [command, expected decision]
  const rows = [
    // Target resolution. dotenv keeps the last of two; Prisma loads prisma/.env; --schema elsewhere is unseen.
    ["cd twice && prisma migrate reset --force", "deny"],
    [`DATABASE_URL=${LOCAL} DATABASE_URL=${R} prisma migrate reset --force`, "deny"],
    ["cd withprisma && prisma migrate dev", "deny"],
    ["cd withprisma && prisma migrate deploy", "ask"],
    ["prisma migrate reset --force --schema prod/schema.prisma", "ask"],
    ["prisma migrate dev --config ../other/prisma.config.ts", "ask"],
    ["prisma migrate dev --schema prisma/schema.prisma", null],
    ["pushd prod && prisma migrate reset --force", "deny"],
    ["pushd prod && popd && prisma migrate reset --force", null],
    ["(cd prod && prisma migrate reset --force)", "deny"],
    ["(cd prod && ls) && prisma migrate reset --force", null],
    ["cd $DIR && prisma migrate dev", "ask"],
    ['eval "$(cat .env.production)" && prisma migrate reset --force', "ask"],
    ['eval "$(cat .env.production)" && prisma migrate dev', "ask"],
    ["read -r DATABASE_URL < prod.url && prisma migrate reset --force", "ask"],
    ["export $(cat .env.production | xargs) && prisma migrate reset --force", "ask"],
    ["export $(cat .env.production | xargs) && prisma migrate deploy", "ask"],
    ["env $(cat .env.production) prisma migrate reset --force", "ask"],
    ["set -a && . ./.env.production && prisma migrate reset --force", "ask"],
    ["source .env.production && DATABASE_URL=postgres://127.0.0.1/app prisma migrate reset", null],
    ["export DATABASE_URL=postgres://127.0.0.1/app && source .env.production && prisma migrate reset", "ask"],
    // A wrapper or a path in front of the tool.
    [`cross-env DATABASE_URL=${R} prisma migrate reset --force`, "deny"],
    ["env-cmd -f .env.production prisma migrate reset --force", "ask"],
    ["railway run npx prisma migrate reset --force", "ask"],
    ['doppler run --command "prisma migrate reset --force"', "ask"],
    ["dotenv -e .env.production prisma migrate reset", "ask"],
    ["cd prod && pnpm --filter api prisma migrate reset --force", "deny"],
    ["pnpm --filter api prisma migrate reset --force", "ask"],
    ["pnpm -r db:reset", "ask"],
    ["pnpm -C prod exec prisma migrate reset --force", "deny"],
    ["pnpm --dir prod db:reset", "deny"],
    ["cd prod && npx --yes prisma migrate reset --force", "deny"],
    ["cd prod && npx prisma@6 migrate reset --force", "deny"],
    ["cd prod && pnpm dlx prisma migrate reset --force", "deny"],
    ["cd prod && ./node_modules/.bin/prisma migrate reset --force", "deny"],
    ["cd prod && node_modules/.bin/prisma migrate reset --force", "deny"],
    ["cd prod && timeout 600 prisma migrate reset --force", "deny"],
    ["cd prod && nohup prisma migrate reset --force", "deny"],
    ["cd prod && nice -n 5 prisma migrate reset --force", "deny"],
    ["cd prod && sudo -E prisma migrate reset --force", "deny"],
    ["cd prod && env -u FOO prisma migrate reset --force", "deny"],
    ["DATABASE_URL=$(cat prod.url) prisma migrate reset --force", "ask"],
    ["docker compose exec app prisma migrate reset --force", "ask"],
    ["./node_modules/.bin/prisma migrate reset --force", null],
    ["timeout 600 pnpm exec prisma migrate dev", null],
    // A secrets loader makes every effect ask, not only the destructive ones.
    ["dotenv -e .env.production -- prisma migrate dev", "ask"],
    ["dotenv -e .env.production -- prisma migrate deploy", "ask"],
    ["doppler run -- sqlx migrate run", "ask"],
    // Hosts.
    ['PGHOSTADDR=10.1.2.3 psql -h localhost -c "DROP TABLE users"', "deny"],
    ['PGHOSTADDR=127.0.0.1 psql -h localhost -c "DROP TABLE users"', null],
    ['PGSERVICE=prod psql -h localhost -c "DROP TABLE users"', "ask"],
    ['export PGHOSTADDR=10.1.2.3 && psql -h localhost -c "TRUNCATE t"', "deny"],
    ['psql "host=localhost hostaddr=10.1.2.3" -c "DROP TABLE users"', "deny"],
    ['psql -h /cloudsql/proj:us-east1:prod -c "DROP TABLE users"', "deny"],
    // Loopback sockets, but the floor (the original whole-line rule: no loopback word on the line) refuses them.
    ['psql -h /var/run/postgresql -c "DROP TABLE users"', "deny"],
    ['psql -h /tmp -c "DROP TABLE users"', "deny"],
    ['psql -h /tmp -c "SELECT 1"', null],
    ['psql -h 127.999.0.1 -c "DROP TABLE users"', "deny"],
    ['psql -h 127.0.0.256 -c "DROP TABLE users"', "deny"],
    // SQL the guard can't read asks; SQL it can read through a pipe, `\i`, or a file is judged.
    ['psql -h db.example.com -c "\\i drop.sql"', "deny"],
    ['psql -h db.example.com -c "\\i missing.sql"', "ask"],
    ["psql -h db.example.com -f drop.sql", "deny"],
    ["psql -h db.example.com -f select.sql", null],
    ["psql -h db.example.com -f big.sql", "ask"],
    ["cp drop.sql /tmp/x.sql && psql -h db.example.com -f /tmp/x.sql", "ask"],
    ["cat drop.sql | psql -h db.example.com", "deny"],
    ["cat select.sql | psql -h db.example.com", null],
    ["curl -s https://example.com/x.sql | psql -h db.example.com", "ask"],
    ['echo "TRUNCATE users" | psql -h db.example.com', "deny"],
    ["psql -h db.example.com < drop.sql", "deny"],
    ["psql -h db.example.com <<EOF\nDROP TABLE users;\nEOF", "deny"],
    ["pg_dump --clean -h localhost app | psql -h db.example.com app", "deny"],
    ["pg_dump -h localhost app | psql -h db.example.com app", null],
    ["pg_restore --clean -d postgres://db.example.com/app dump.bin", "deny"],
    ["pg_restore -c -h db.example.com -d app dump.bin", "deny"],
    ["pg_restore -h db.example.com -d app dump.bin", null],
    ["pg_restore --clean -h localhost -d app dump.bin", null],
    ['cat drop.sql | psql -h localhost', null],
    // Destructive SQL read with comments removed, more shapes, and SQL built at run time.
    ['psql -h db.example.com -c "DROP/**/TABLE users"', "deny"],
    ['psql -h db.example.com -c "DROP -- x\nTABLE users"', "deny"],
    ['psql -h db.example.com -c "ALTER TABLE users DROP email"', "deny"],
    ['psql -h db.example.com -c "ALTER TABLE users DROP CONSTRAINT users_email_key"', null],
    ['psql -h db.example.com -c "UPDATE users SET email = NULL"', "deny"],
    ['psql -h db.example.com -c "UPDATE users SET email = lower(email)"', null],
    ['mysql -h db.example.com -e "DELETE u FROM users u"', "deny"],
    ['psql -h db.example.com -c "DROP TYPE mood CASCADE"', "deny"],
    ['psql -h db.example.com -c "DO $$ BEGIN EXECUTE \'DR\' || \'OP TABLE users\'; END $$"', "ask"],
    ['psql -h db.example.com -c "EXECUTE purge_all"', "ask"],
    ['psql -h localhost -c "DO $$ BEGIN EXECUTE \'x\'; END $$"', null],
    // More tools and spellings.
    [`sqlx db drop -y -D ${R}`, "deny"],
    [`sqlx db reset -D ${R}`, "deny"],
    [`sqlx mig revert -D ${R}`, "deny"],
    [`sqlx mig run -D ${R}`, "ask"],
    [`migrate -path m -database ${R} goto 1`, "deny"],
    [`DATABASE_URL=${R} dbmate drop`, "deny"],
    [`DATABASE_URL=${R} dbmate rollback`, "deny"],
    [`dbmate -u ${R} down`, "deny"],
    ["dbmate --env-file .env.production rollback", "ask"],
    ["dbmate rollback", null],
    ["dbmate up", null],
    [`DATABASE_URL=${R} knex migrate:rollback --all`, "deny"],
    ["knex migrate:rollback", "ask"],
    [`DATABASE_URL=${R} drizzle-kit push --force`, "deny"],
    ["supabase db reset --linked", "deny"],
    [`supabase db reset --db-url ${R}`, "deny"],
    ["supabase db reset", null],
    [`DATABASE_URL=${R} alembic downgrade base`, "deny"],
    ["cd . && alembic downgrade base", "ask"],
    ["alembic upgrade head", null],
    ["goose -dir m create down sql", null],
    // SQL is judged per client, not against the whole line; the floor (the original whole-line rule)
    // still refuses a remote client on a line that says DROP TABLE anywhere.
    ['git commit -m "fix: DROP TABLE tmp" && psql -h db.example.com -c "select 1"', "deny"],
    ["psql -h db.example.com -c 'select 1' && psql -h localhost -c 'DROP TABLE t'", null],
    ["psql -h localhost -c 'DROP TABLE t' && psql -h db.example.com -c 'select 1'", null],
    // Words about these tools are not the tools.
    ['grep -rn "DROP TABLE" prisma/migrations', null],
    ["cat prisma/migrations/0001/migration.sql", null],
    ["which psql", null],
    ["git commit -F- <<EOF\nnever prisma migrate reset prod\nEOF", null],
    ["prisma migrate status", null],
    ["cd prod && prisma migrate status", null],
  ];

  for (const [command, expected] of rows) {
    it(`${JSON.stringify(command)} → ${String(expected)}`, () => {
      assert.equal(evaluate(command, options)?.decision ?? null, expected);
    });
  }

  it("dotenvValue keeps the last of two, as dotenv does", () => {
    assert.equal(dotenvValue("A=1\nexport A='2'\nB=3\n", "A"), "2");
    assert.equal(dotenvValue("B=3\n", "A"), undefined);
  });
});

// Each row was a bypass, a throw, or a false positive.
describe("databases: parsing the line, the SQL, and where it runs", () => {
  const LOCAL = "postgresql://u:p@localhost:5432/app";
  const R = "postgres://u@db.example.com/app";
  const D = "DROP TABLE users";
  // cwd has a loopback .env; prod/ a remote one; the rest each hide a remote URL a different way.
  const root = repoWith({
    ".env": `DATABASE_URL=${LOCAL}\n`,
    "prisma/schema.prisma": SCHEMA,
    "package.json": { scripts: { "db:reset": "prisma migrate reset --force" } },
    "prod/.env": `DATABASE_URL=${R}\n`,
    "prod/prisma/schema.prisma": SCHEMA,
    "colon/.env": `DATABASE_URL=${LOCAL}\nDATABASE_URL: ${R}\n`,
    "multi/.env": `DATABASE_URL=${R}\nNOTE="\nDATABASE_URL=${LOCAL}\n"\n`,
    "crlf/.env": `DATABASE_URL=${R}\r\nOTHER=1\r\n`,
    "cmt/.env": `DATABASE_URL=${R} # was localhost\n`,
    "pcfg/.env": `DATABASE_URL=${LOCAL}\n`,
    "pcfg/prisma.config.ts": `export default { datasource: { url: env("DATABASE_URL") } };\n`,
    "plit/.env": `DATABASE_URL=${LOCAL}\n`,
    "plit/prisma/schema.prisma": `datasource db {\n  provider = "postgresql"\n  url      = "${R}"\n}\n`,
    "pfine/.env": `DATABASE_URL=${LOCAL}\n`,
    "pfine/prisma/schema.prisma": 'datasource db {\n  provider = "postgresql"\n  url      = env("DATABASE_URL")\n}\n',
    "home/.env": `DATABASE_URL=${R}\n`,
    "drop.sql": `${D};\n`,
    "select.sql": "SELECT 1;\n",
    "stale.sql": "SELECT 1;\n",
    "sub/x.sql": `${D};\n`,
    "sub/inc.sql": "\\ir x.sql\n",
    "c1.sql": "\\i c2.sql\n",
    "c2.sql": "\\i c3.sql\n",
    "c3.sql": "\\i c4.sql\n",
    "c4.sql": "\\i c5.sql\n",
    "c5.sql": `${D};\n`,
    "cyc1.sql": "\\i cyc2.sql\n",
    "cyc2.sql": "\\i cyc1.sql\n",
    ...Object.fromEntries(Array.from({ length: 20 }, (_, index) => [`f${index + 1}.sql`, "SELECT 1;\n"])),
  });
  const decision = (command, env) => evaluate(command, readersIn(root, env))?.decision ?? null;

  // [command, expected decision, the agent's environment]
  /** @type {[string, string | null, Record<string, string>?][]} */
  const rows = [
    // A malformed `%` escape never throws (a throw skipped the guard for the whole line).
    [`git push --force origin main; psql postgres://%zz`, "deny"],
    [`psql -h db.example.com -c "${D}"; psql postgres://%zz`, "deny"],
    ["DATABASE_URL=postgres://%E0%A4%A/app prisma migrate reset --force", "ask"],
    // A heredoc fed through a pipe is the client's SQL.
    [`cat <<EOF | psql -h db.example.com\n${D};\nEOF`, "deny"],
    [`cat <<'SQL' | psql "$DATABASE_URL"\nTRUNCATE users;\nSQL`, "deny"],
    ["cat <<EOF | psql -h db.example.com\nSELECT 1;\nEOF", null],
    ["cat <<EOF | psql -h db.example.com\nSELECT $X;\nEOF", "ask"],
    [`cat <<EOF | psql -h localhost\n${D};\nEOF`, null],
    ["git commit -F - <<EOF\nfeat: drop legacy table\n\nRun prisma migrate reset --force locally.\nEOF", null],
    // Directory forms the guard can't follow lose track; the ones it can, it follows.
    ["cd && prisma migrate reset --force", "deny"],
    ["cd ~ && prisma migrate reset --force", "deny"],
    ["cd -P prod && prisma migrate dev", "deny"],
    ["cd -P prod && prisma migrate reset --force", "deny"],
    ["cd -- prod && prisma migrate reset --force", "deny"],
    ["{ cd prod; } && prisma migrate reset --force", "deny"],
    ["builtin cd prod && prisma migrate reset --force", "deny"],
    ["(cd prod && echo \\) && prisma migrate reset --force)", "deny"],
    ['(cd prod && echo ")" && prisma migrate reset --force)', "deny"],
    ["if true; then cd prod; fi; prisma migrate reset --force", "ask"],
    ["if true; then git push --force origin main; fi", "deny"],
    ["cd prod && cd - && prisma migrate reset --force", null],
    ["cd - && prisma migrate reset --force", "ask"],
    ["cd nowhere && prisma migrate reset --force", "ask"],
    ["cd app && prisma migrate dev", "ask", { CDPATH: join(root, "prod") }],
    ["cd ./prod && prisma migrate reset --force", "deny", { CDPATH: join(root, "home") }],
    ["X=$(cd prod && pwd) && prisma migrate reset --force", null],
    // A variable the line removes is read from the .env the tool then loads, not the environment.
    ["cd prod && unset DATABASE_URL && prisma migrate reset --force", "deny", { DATABASE_URL: LOCAL }],
    ["cd prod && env -u DATABASE_URL prisma migrate reset --force", "deny", { DATABASE_URL: LOCAL }],
    ["cd prod && env --unset=DATABASE_URL prisma migrate reset --force", "deny", { DATABASE_URL: LOCAL }],
    ["cd prod && env -i PATH=/usr/bin prisma migrate reset --force", "deny", { DATABASE_URL: LOCAL }],
    ["cd prod && prisma migrate reset --force", null, { DATABASE_URL: LOCAL }],
    [`DATABASE_URL=${LOCAL} prisma migrate reset --force`, null, { DATABASE_URL: R }],
    ["prisma migrate dev", "deny", { DATABASE_URL: R }],
    // `host=` inside the SQL is not where it connects.
    [`PGHOST=db.example.com psql -c "${D}; -- host=localhost"`, "deny"],
    [`psql -c "${D}; -- host=localhost"`, "deny", { PGHOST: "db.example.com" }],
    [`psql "service=prod" -c "SELECT 'host=localhost'; ${D}"`, "ask"],
    [`psql --command="${D} -- host=localhost"`, "ask"],
    // Quotes don't hide SQL, SQL the shell builds asks, and every include is followed.
    [`psql -h db.example.com -c "SELECT '--'; ${D}"`, "deny"],
    [`psql -h db.example.com -c "SELECT '/*'; ${D}; SELECT '*/'"`, "deny"],
    // The floor reads the whole line, so the SQL in the variable is refused.
    [`SQL="${D}" && psql -h db.example.com -c "$SQL"`, "deny"],
    ['psql -h db.example.com -c "$SQL"', "ask"],
    ['psql -h db.example.com -c "$(cat drop.sql)"', "ask"],
    // ANSI-C quoting is decoded, so the DROP is read.
    ["psql -h db.example.com -c $'\\x44ROP TABLE users'", "deny"],
    ['echo "$SQL" | psql -h db.example.com', "ask"],
    ["psql -h db.example.com -c \"SELECT format('DR%sOP TABLE %I', '', 'users') \\gexec\"", "ask"],
    ['mysql -h db.example.com -e "source drop.sql"', "deny"],
    ['mysql -h db.example.com -e "\\. drop.sql"', "deny"],
    ["cp drop.sql stale.sql && psql -h db.example.com -f stale.sql", "ask"],
    ["cat drop.sql > stale.sql; psql -h db.example.com -f stale.sql", "ask"],
    ["cat drop.sql | tee stale.sql && psql -h db.example.com -f stale.sql", "ask"],
    ["cp drop.sql sub && psql -h db.example.com -f sub/drop.sql", "ask"],
    // The heredoc body is on the line, so the floor refuses it.
    [`cat > stale.sql <<EOF\n${D};\nEOF\npsql -h db.example.com -f stale.sql`, "deny"],
    [`cat > stale.sql <<EOF\nSELECT 1;\nEOF\npsql -h db.example.com -f stale.sql`, "ask"],
    ["cp select.sql other.sql && psql -h db.example.com -f stale.sql", null],
    [`psql -h db.example.com ${Array.from({ length: 20 }, (_, index) => `-f f${index + 1}.sql`).join(" ")} -f drop.sql`, "ask"],
    [`psql -h db.example.com ${Array.from({ length: 20 }, (_, index) => `-f f${index + 1}.sql`).join(" ")}`, null],
    ["psql -h db.example.com -f c1.sql", "deny"],
    ["psql -h db.example.com -f sub/inc.sql", "deny"],
    ["psql -h db.example.com -f cyc1.sql", null],
    ["cat drop.sql | psql -h db.example.com -f /dev/stdin", "deny"],
    ["cat drop.sql | psql -h db.example.com -f -", "deny"],
    ["cat select.sql | psql -h db.example.com -f -", null],
    ["psql -h db.example.com -f /dev/stdin", "ask"],
    // A SQL client behind a remote shell or another wrapper is still judged.
    [`kubectl exec -it pg-0 -- psql -U postgres -c "${D}"`, "deny"],
    [`ssh prod-db psql -c "${D}"`, "deny"],
    [`ssh prod-db "psql -c '${D}'"`, "deny"],
    // In a container, no host or its localhost is the container's own database: the target is
    // unknown, so the user decides (the floor asks there too, rather than refusing).
    [`docker exec db psql -U postgres -c "${D}"`, "ask"],
    [`docker compose exec db psql -h localhost -c "${D}"`, "ask"],
    [`kubectl exec pg-0 -- sh -c "psql -c '${D}'"`, "deny"],
    [`su postgres -c "psql -c '${D}'"`, "deny"],
    [`watch psql -h db.example.com -c "${D}"`, "deny"],
    ["ssh prod-db psql -f drop.sql", "ask"],
    ['docker exec db psql -c "SELECT 1"', null],
    ['echo psql -c "DROP TABLE users"', null],
    // Dotenv's `KEY: value` form, multi-line quoted values, CRLF, and comments.
    ["cd colon && prisma migrate reset --force", "deny"],
    ["cd multi && prisma migrate reset --force", "deny"],
    ["cd crlf && prisma migrate reset --force", "deny"],
    ["cd cmt && prisma migrate reset --force", "deny"],
    // A Prisma config file means a loopback .env proves nothing; a URL written in the schema wins.
    ["cd pcfg && prisma migrate reset --force", "ask"],
    ["cd plit && prisma migrate reset --force", "deny"],
    ["cd plit && prisma migrate dev", "deny"],
    ["cd pfine && prisma migrate reset --force", null],
    // The tool through its own JS entry point.
    ["cd prod && node node_modules/prisma/build/index.js migrate reset --force", "deny"],
    ["cd prod && node ./node_modules/.pnpm/prisma@6.1.0/node_modules/prisma/build/index.js migrate reset --force", "deny"],
    ["node --env-file=.env.production node_modules/prisma/build/index.js migrate reset --force", "ask"],
    // Nesting, obfuscation, and false positives.
    ["printf 'DR%sP TABLE users' O | psql -h db.example.com", "ask"],
    ["printf 'DROP TABLE users;\\n' | psql -h db.example.com", "deny"],
    [`psql -h db.example.com -v t=TABLE -c "DROP :t users"`, "ask"],
    ['psql -h db.example.com -v ON_ERROR_STOP=1 -c "SELECT 1::int"', null],
    ['psql -h db.example.com -c "GRANT EXECUTE ON FUNCTION f() TO app"', null],
    ['psql -h db.example.com -c "EXECUTE purge_all"', "ask"],
    ["echo run prisma migrate reset --force to start over", null],
    ["grep -rn prisma migrate reset docs", null],
    [`${"eval ".repeat(20)}git status`, "ask"],
    [`${"eval ".repeat(3)}git push --force origin main`, "deny"],
  ];

  for (const [command, expected, env] of rows) {
    it(`${JSON.stringify(command)}${env ? ` with ${Object.keys(env).join(", ")} set` : ""} → ${String(expected)}`, () => {
      assert.equal(decision(command, env), expected);
    });
  }

  it("dotenvValue reads `KEY: value`, skips a key inside a quoted value, and keeps the last", () => {
    assert.equal(dotenvValue("A=1\nA: 2\n", "A"), "2");
    assert.equal(dotenvValue('A=1\nB="\nA=2\n"\n', "A"), "1");
    assert.equal(dotenvValue("export A='x y' # c\r\n", "A"), "x y");
    assert.equal(dotenvValue("A=x # c\n", "A"), "x");
    assert.equal(dotenvValue('A="never closed\n', "A"), '"never closed');
  });
});

// Timing: the hook times out at 10 s and a timed-out hook lets the command run, so every reader
// here must stay linear. Each input was over 10 s (or a hang) before it was fixed; the bounds leave CI headroom.
describe("databases: adversarial input stays far inside the hook's timeout", () => {
  const MB = 990_000;
  const fill = (unit) => unit.repeat(Math.floor(MB / unit.length));
  // [label, SQL file text a remote `psql -f big.sql` reads]
  const files = [
    ["no `;`, many `drop`", fill("drop x ")],
    ["no `;`, many `update … set`", fill("update the row set it to done\n")],
    ["no `;`, many `alter table`", fill("alter table t ")],
    ["unclosed block comments", fill("/* ")],
    ["unclosed quotes", fill("' ")],
    ["dollar tags", fill("$a$ ")],
    ["a long multi-table delete list", fill("delete a , ")],
    ["a million includes", fill("\\i ")],
    ["psql variables", fill(":a ")],
  ];
  for (const [label, text] of files) {
    it(`${label}: under 2 s`, () => {
      const started = Date.now();
      const verdict = evaluate("psql -h db.example.com -v x=1 -f big.sql", { fileIn: () => text });
      assert.ok(Date.now() - started < 2000, `${Date.now() - started} ms`);
      assert.equal(verdict?.decision, "ask");
    });
  }

  it("20,000 nested `eval`s ask, under 4 s", () => {
    const started = Date.now();
    assert.equal(evaluate(`${"eval ".repeat(20_000)}git push --force origin main`, {})?.decision, "ask");
    assert.ok(Date.now() - started < 4000, `${Date.now() - started} ms`);
  });

  it("a 1 MB .env of quotes and backslashes, under 1 s", () => {
    const started = Date.now();
    dotenvValue(fill("A='\\'"), "A");
    dotenvValue(fill('A="x\n'), "A");
    assert.ok(Date.now() - started < 1000, `${Date.now() - started} ms`);
  });
});

describe("hook entry point", () => {
  it("refuses everything when the project file is broken, for both hosts", () => {
    const root = guardIn({ "reins.json": "{ nope" });
    const output = JSON.parse(run(root, "claude", "ls")).hookSpecificOutput;
    assert.equal(output.permissionDecision, "deny");
    assert.ok(output.permissionDecisionReason.includes("reins.json didn't load"));
    assert.equal(JSON.parse(run(root, "cursor", "ls")).permission, "deny");
  });

  it("applies the project's rules", () => {
    const root = guardIn({ "reins.json": { deny: [{ match: "^make\\s+deploy\\b", reason: "Deploys go through CI." }] } });
    assert.equal(JSON.parse(run(root, "claude", "make deploy")).hookSpecificOutput.permissionDecision, "deny");
    assert.equal(run(root, "claude", "make test"), "");
  });

  it("without a project file, behaves as before", () => {
    const root = guardIn({});
    assert.equal(run(root, "claude", "ls"), "");
    assert.equal(JSON.parse(run(root, "cursor", "ls")).permission, "allow");
  });

  it("reads .env and package.json where the command runs", () => {
    const root = guardIn({});
    const project = repoWith({ "package.json": { scripts: { "db:reset": "prisma migrate reset --force" } }, "prisma/schema.prisma": SCHEMA, ".env": "# local\nDATABASE_URL=\"postgresql://u:p@db.example.com:5432/app\"\n" });
    assert.equal(JSON.parse(run(root, "claude", "pnpm db:reset", project)).hookSpecificOutput.permissionDecision, "deny");
    writeFileSync(join(project, ".env"), "export DATABASE_URL='postgresql://u:p@localhost:5432/app'\n");
    assert.equal(run(root, "claude", "pnpm db:reset", project), "");
    assert.equal(run(root, "claude", "pnpm exec prisma migrate dev", project), "");
  });

  it("reads .env as dotenv does (last wins), prisma/.env too, and SQL files it can't read ask", () => {
    const root = guardIn({});
    const decision = (command, cwd) => {
      const output = run(root, "claude", command, cwd);
      return output === "" ? null : JSON.parse(output).hookSpecificOutput.permissionDecision;
    };
    const twice = repoWith({ ".env": "DATABASE_URL=postgresql://localhost/app\nDATABASE_URL=postgresql://db.example.com/app\n" });
    assert.equal(decision("prisma migrate reset --force", twice), "deny");
    const nested = repoWith({ ".env": "DATABASE_URL=postgresql://localhost/app\n", "prisma/.env": "DATABASE_URL=postgresql://db.example.com/app\n" });
    assert.equal(decision("prisma migrate dev", nested), "deny");
    const files = repoWith({ "big.sql": `-- ${"x".repeat(1_000_001)}\nSELECT 1;\n`, "ok.sql": "SELECT 1;\n" });
    assert.equal(decision("psql -h db.example.com -f big.sql", files), "ask");
    assert.equal(decision("psql -h db.example.com -f missing.sql", files), "ask");
    assert.equal(decision("psql -h db.example.com -f ok.sql", files), null);
  });

  it("through the real readers: env, HOME, CDPATH, symlinks, /dev/stdin, no throws", () => {
    const root = guardIn({});
    const LOCAL = "postgresql://u:p@localhost:5432/app";
    const project = repoWith({
      ".env": `DATABASE_URL=${LOCAL}\n`,
      "prisma/schema.prisma": SCHEMA,
      "prod/.env": "DATABASE_URL=postgres://u@db.example.com/app\n",
      "home/.env": "DATABASE_URL=postgres://u@db.example.com/app\n",
      "cfg/.env": `DATABASE_URL=${LOCAL}\n`,
      "cfg/prisma.config.ts": 'export default { datasource: { url: env("DATABASE_URL") } };\n',
      "big.sql": `SELECT 1;\n-- ${"x".repeat(1_000_001)}\n`,
      "drop.sql": "DROP TABLE users;\n",
    });
    symlinkSync(join(project, "big.sql"), join(project, "link.sql"));
    const decision = (command, env = {}) => {
      const output = run(root, "claude", command, project, { HOME: join(project, "home"), ...env });
      return output === "" ? null : JSON.parse(output).hookSpecificOutput.permissionDecision;
    };
    // A bad `%` escape no longer throws (a throw skipped the whole line, the force-push too).
    assert.equal(decision("git push --force origin main; psql postgres://%zz"), "deny");
    // stat, not lstat: a link can't carry a file past the 1 MB cap; /dev/stdin is not a file.
    assert.equal(decision("psql -h db.example.com -f link.sql"), "ask");
    assert.equal(decision("psql -h db.example.com -f /dev/stdin"), "ask");
    assert.equal(decision("cat drop.sql | psql -h db.example.com -f /dev/stdin"), "deny");
    // A removed variable is read from the .env the tool loads, not the agent's environment.
    assert.equal(decision("cd prod && env -u DATABASE_URL prisma migrate reset --force", { DATABASE_URL: LOCAL }), "deny");
    assert.equal(decision("cd prod && unset DATABASE_URL && prisma migrate reset --force", { DATABASE_URL: LOCAL }), "deny");
    // Bare `cd` is HOME; a directory that isn't there, or CDPATH, loses track.
    assert.equal(decision("cd && prisma migrate reset --force"), "deny");
    assert.equal(decision("cd nowhere && prisma migrate reset --force"), "ask");
    assert.equal(decision("cd prod && prisma migrate reset --force", { CDPATH: join(project, "home") }), "ask");
    assert.equal(decision("cd cfg && prisma migrate reset --force"), "ask");
    assert.equal(decision("prisma migrate reset --force"), null);
  });

  it("through the real readers, the schema: package.json's prisma.schema and a multi-file schema folder", () => {
    const root = guardIn({});
    const LOCAL = "postgresql://u:p@localhost:5432/app";
    const R = "postgres://u@db.example.com/app";
    const remote = `datasource db {\n  provider = "postgresql"\n  url      = "${R}"\n}\n`;
    const project = repoWith({
      "pj/.env": `DATABASE_URL=${LOCAL}\nPROD_URL=${R}\n`,
      "pj/package.json": { prisma: { schema: "db/schema.prisma" } },
      "pj/db/schema.prisma": 'datasource db {\n  provider = "postgresql"\n  url      = env("PROD_URL")\n}\n',
      "multi/.env": `DATABASE_URL=${LOCAL}\n`,
      "multi/prisma/schema/db.prisma": remote,
      "multi/prisma/schema/models.prisma": "model A { id Int @id }\n",
      "nested/.env": `DATABASE_URL=${LOCAL}\n`,
      "nested/prisma/schema/db.prisma": SCHEMA,
      "nested/prisma/schema/more/x.prisma": remote,
      "loc/.env": `DATABASE_URL=${LOCAL}\n`,
      "loc/prisma/schema/db.prisma": SCHEMA,
      "loc/prisma/schema/models.prisma": "model A { id Int @id }\n",
      "none/.env": `DATABASE_URL=${LOCAL}\n`,
    });
    const decision = (command) => {
      const output = run(root, "claude", command, project);
      return output === "" ? null : JSON.parse(output).hookSpecificOutput.permissionDecision;
    };
    assert.equal(decision("cd pj && prisma migrate reset --force"), "deny");
    assert.equal(decision("cd multi && prisma migrate reset --force"), "deny");
    assert.equal(decision("cd multi && prisma migrate reset --force --schema prisma/schema"), "deny");
    assert.equal(decision("cd nested && prisma migrate reset --force"), "deny");
    assert.equal(decision("cd none && prisma migrate reset --force"), "ask");
    assert.equal(decision("cd loc && prisma migrate reset --force"), null);
  });

  it("an 840 KB SQL file with no `;` judges in under 5 s through the hook (it hung before)", () => {
    const root = guardIn({});
    const project = repoWith({ "slow.sql": "drop x ".repeat(120_000) });
    const started = Date.now();
    const output = run(root, "claude", "psql -h db.example.com -f slow.sql", project);
    assert.ok(Date.now() - started < 5000, `${Date.now() - started} ms`);
    assert.equal(JSON.parse(output).hookSpecificOutput.permissionDecision, "ask");
  });

  it("still runs when the repo is reached through a symlink", () => {
    const root = guardIn({});
    const link = join(repoWith({}), "linked");
    symlinkSync(root, link);
    assert.equal(JSON.parse(run(link, "claude", "terraform destroy")).hookSpecificOutput.permissionDecision, "deny");
  });
});

// ── Infrastructure: apply, destroy, state surgery, and cloud deletes, in every spelling ──
// [command, expected decision]. Each refused row is a spelling an agent could reach for: prefixes,
// full paths, -chdir, chains, `bash -c`, wrappers that run a command later in their arguments,
// substitutions, subshells, `eval`, and a shell fed on stdin.
const infraRefused = [
  ["terraform apply", "deny"],
  ["terraform apply -auto-approve", "deny"],
  ["terraform destroy", "deny"],
  ["tofu apply", "deny"],
  ["tofu destroy -auto-approve", "deny"],
  ["terraform -chdir=infra apply", "deny"],
  ["terraform -chdir infra apply", "deny"],
  ["/usr/local/bin/terraform apply", "deny"],
  ["./terraform destroy", "deny"],
  ["TF_LOG=debug terraform apply", "deny"],
  ["env AWS_PROFILE=prod terraform apply", "deny"],
  ["sudo -u deploy terraform apply", "deny"],
  ["cd infra && terraform apply", "deny"],
  ["terraform plan -out=p && terraform apply p", "deny"],
  ["terraform plan; terraform apply", "deny"],
  ["sh -c 'terraform apply'", "deny"],
  ["bash -lc \"cd infra && terraform destroy\"", "deny"],
  ["sudo -u bob bash -c 'terraform apply'", "deny"],
  ["timeout 600 terraform apply", "deny"],
  ["nohup terraform destroy &", "deny"],
  ["aws-vault exec prod -- terraform apply", "deny"],
  ["op run -- tofu apply", "deny"],
  ["echo infra | xargs -I{} terraform -chdir={} apply", "deny"],
  ["(terraform apply)", "deny"],
  ["{ terraform apply; }", "deny"],
  ["echo $(terraform apply)", "deny"],
  ["echo \"$(terraform destroy -auto-approve)\"", "deny"],
  ["x=`terraform apply`", "deny"],
  ["eval \"terraform apply\"", "deny"],
  ["eval terraform destroy", "deny"],
  ["echo \"terraform apply\" | sh", "deny"],
  ["cat <<EOF | bash\nterraform destroy\nEOF", "deny"],
  ["bash <<EOF\ncd infra\nterraform apply\nEOF", "deny"],
  ["ssh bastion 'terraform apply'", "deny"],
  ["if terraform apply; then echo ok; fi", "deny"],
  ["for d in a b; do terraform -chdir=$d destroy; done", "deny"],
  ["terraform apply -destroy", "deny"],
  ["terraform state rm aws_db_instance.main", "deny"],
  ["terraform state push old.tfstate", "deny"],
  ["terraform workspace delete staging", "deny"],
  ["terraform state mv a b", "ask"],
  ["terraform import aws_s3_bucket.x y", "ask"],
  ["terraform force-unlock 123", "ask"],
  ["terragrunt apply", "deny"],
  ["terragrunt run-all destroy", "deny"],
  ["terragrunt run --all -- apply", "deny"],
  ["terraform_1.9.8 apply", "deny"],
  ["tf apply", "deny"],
  ["pnpm exec terraform apply", "deny"],
  ["npx terraform destroy", "deny"],
  ["time terraform apply", "deny"],
  ["nice -n 10 terraform apply", "deny"],
  ["aws ec2 terminate-instances --instance-ids i-1", "deny"],
  ["aws rds delete-db-cluster --db-cluster-identifier prod", "deny"],
  ["aws s3 rm s3://bucket/key", "deny"],
  ["aws s3 sync . s3://bucket --delete", "deny"],
  ["aws --profile prod dynamodb delete-table --table-name users", "deny"],
  ["aws-vault exec prod -- aws s3 rb s3://b --force", "deny"],
  ["gcloud sql instances delete prod", "deny"],
  ["gcloud storage rm -r gs://b", "deny"],
  ["az group delete -n prod --yes", "deny"],
  ["gsutil rm gs://b/x", "deny"],
  ["\"terraform\" apply", "deny"],
  ["terraform \"apply\"", "deny"],
  ["terraform apply>log", "deny"],
];

// What an agent does with infrastructure every day, and text that only mentions a refused command.
const infraAllowed = [
  ["terraform plan", null],
  ["terraform plan -destroy", null],
  ["terraform plan -out=apply.tfplan", null],
  ["terraform fmt -check -recursive", null],
  ["terraform validate", null],
  ["terraform init -backend=false", null],
  ["terraform -chdir=infra init", null],
  ["terraform state list", null],
  ["terraform state show aws_s3_bucket.x", null],
  ["terraform output", null],
  ["terraform show plan.out", null],
  ["tflint --recursive", null],
  ["hadolint Dockerfile", null],
  ["aws sts get-caller-identity", null],
  ["aws s3 ls s3://bucket", null],
  ["aws s3 sync . s3://bucket", null],
  ["gcloud compute instances list", null],
  ["grep -rn \"terraform apply\" docs", null],
  ["grep -rn terraform docs", null],
  ["rg 'terraform destroy'", null],
  ["git commit -m \"docs: terraform apply is a human action\"", null],
  ["git commit -m \"$(cat <<'EOF'\nRefuse terraform apply in the guard\n\nterraform destroy too.\nEOF\n)\"", null],
  ["cat <<EOF > notes.md\nterraform apply only by hand\nEOF", null],
  ["echo \"run terraform apply by hand\"", null],
  ["docker build -t app .", null],
  ["ls terraform", null],
  ["timeout 60 terraform plan", null],
  ["aws-vault exec prod -- terraform plan", null],
  ["bash -c 'terraform fmt -check && terraform validate'", null],
  ["curl -fsSL https://example.com/install.sh | bash\n", null],
];

describe("guard: infrastructure", () => {
  for (const [command, expected] of [...infraRefused, ...infraAllowed]) {
    it(`${String(command)} → ${String(expected)}`, () => {
      assert.equal(evaluate(command, { branch: "feat" })?.decision ?? null, expected);
    });
  }

  it("an exemption lifts an apply of exactly that command and no other spelling", () => {
    const rules = exempting("terraform -chdir=sandbox apply");
    assert.equal(evaluate("terraform -chdir=sandbox apply", { branch: "feat", rules }), null);
    assert.equal(evaluate("terraform -chdir=prod apply", { branch: "feat", rules })?.decision, "deny");
    assert.equal(evaluate("timeout 5 terraform -chdir=sandbox apply", { branch: "feat", rules })?.decision, "deny");
  });

  it("a refusal says why and names the rule", () => {
    // Built in: the reason says what the rule protects and what to do instead, with no rule file to look up.
    for (const command of ["terraform destroy", "terraform state rm x", "terraform import a b", "terraform test", "aws s3 rb s3://b", "terraform $(echo apply)"]) {
      const reason = evaluate(command, { branch: "feat" })?.reason ?? "";
      assert.match(reason, /\b(human|user)\b/, command);
      assert.doesNotMatch(reason, /\.mdc\b/, command);
    }
  });

  it("an exemption doesn't lift the same apply run through a wrapper's command string", () => {
    const rules = exempting("terraform -chdir=sandbox apply");
    assert.equal(evaluate("bash -c 'terraform -chdir=sandbox apply'", { branch: "feat", rules })?.decision, "deny");
  });
});

// Line continuations, terraform test and init, quoting, wrappers, cloud deletes. [command, expected decision]
const infraQa = [
  // A line continuation joins lines; the apply after it is still in command position.
  ["terraform -chdir=infra/prod \\\n  apply \\\n  -var-file=prod.tfvars", "deny"],
  ["aws \\\n --profile prod \\\n s3 rb s3://b --force", "deny"],
  ["gcloud sql instances \\\n delete prod", "deny"],
  ["git push \\\n --force origin main", "deny"],
  // `terraform test` applies real resources (and destroys them): the user confirms.
  ["terraform test", "ask"],
  ["tofu test", "ask"],
  ["terraform -chdir=infra test", "ask"],
  ["terragrunt run-all test", "ask"],
  // Init that copies state over the destination backend's is state-push class.
  ["terraform init -migrate-state", "deny"],
  ["terraform init -force-copy", "deny"],
  ["terraform init -reconfigure -force-copy", "deny"],
  ["tofu -chdir=infra init -migrate-state -input=false", "deny"],
  ["terraform init -reconfigure", null],
  // Backticks the shell never runs: single quotes and quoted-terminator heredoc bodies.
  ["git commit -F - <<'EOF'\nfeat: refuse `terraform apply` in the guard\nEOF", null],
  ["git commit -m 'docs: never run `terraform destroy` yourself'", null],
  ["gh pr create --draft --body \"$(cat <<'EOF'\nThe guard refuses `terraform apply`; don't run it.\nEOF\n)\"", null],
  ["cat > docs/x.md <<'EOF'\nRun `tofu destroy` by hand only.\nEOF", null],
  // …and the ones it does run: an unquoted-terminator body and double quotes expand them.
  ["cat > notes.md <<EOF\nrun `terraform apply`\nEOF", "deny"],
  ["echo \"`terraform destroy`\"", "deny"],
  // Parentheses in a message are text, not a subshell.
  ["git commit -F - <<'EOF'\nfix(infra): explain terraform apply (and destroy)\nEOF", null],
  ["git commit -F - <<EOF\nfix(guard): terraform apply stays a human action\nEOF", null],
  ["git commit -m \"feat(infra): never terraform apply\"", null],
  // A wrapper runs its program word; its quoted arguments are data, unless it takes a command string.
  ["env LC_ALL=C grep -rn 'terraform apply' docs", null],
  ["sudo grep -rn 'terraform destroy' /etc", null],
  ["timeout 5 grep -rn 'terraform apply' docs", null],
  ["if grep -q 'terraform apply' docs/x.md; then echo found; fi", null],
  ["find . -exec grep -l 'terraform destroy' {} +", null],
  ["xargs grep -l 'terraform apply'", null],
  ["pnpm test -- -t 'terraform destroy'", null],
  ["time rg 'aws s3 rb' docs", null],
  ["sudo -iu deploy terraform apply", "deny"],
  ["env -S 'terraform apply'", "deny"],
  ["nix-shell --run 'terraform apply'", "deny"],
  ["terraform 2>/dev/null apply", "deny"],
  // A cloud delete is the operation, not any word that starts with delete.
  ["aws lambda invoke --function-name delete-user out.json", null],
  ["aws ssm get-parameter --name delete-me", null],
  ["gcloud compute instances describe delete-me", null],
  ["gcloud functions call delete-user", null],
  ["az vm show -n delete -g g", null],
  ["gsutil cp rm gs://b/", null],
  ["aws s3 sync . s3://b --exclude delete-me", null],
  ["terragrunt plan --terragrunt-working-dir apply", null],
  ["terragrunt --terragrunt-non-interactive apply", "deny"],
  // Deletes under other verbs.
  ["aws ecr batch-delete-image --repository-name r --image-ids imageTag=x", "deny"],
  ["aws sqs purge-queue --queue-url https://sqs/q", "deny"],
  ["aws ec2 deregister-image --image-id ami-1", "deny"],
  ["aws kms disable-key --key-id k", "deny"],
  ["aws --region us-east-1 kms schedule-key-deletion --key-id k", "deny"],
  ["gcloud kms keys versions destroy 1 --key k --keyring r --location l", "deny"],
  ["gcloud kms keys versions disable 1 --key k --keyring r --location l", "deny"],
  ["az keyvault purge --name v", "deny"],
  ["az keyvault key purge --vault-name v --name k", "deny"],
  ["gsutil rsync -d ./local gs://b", "deny"],
  ["gsutil -m rsync -r -d gs://a gs://b", "deny"],
  ["aws s3 mv s3://b/x ./x", "deny"],
  ["aws s3 mv --exclude '*.tmp' s3://a s3://b", "deny"],
  ["gsutil mv gs://b/x ./x", "deny"],
  ["bq rm -f -t proj:ds.table", "deny"],
  ["aws s3 mv ./x s3://b/x", null],
  ["gsutil mv ./x gs://b/x", null],
  ["gsutil rsync -r ./local gs://b", null],
  ["gcloud kms keys versions list --key k --keyring r --location l", null],
  ["gcloud services disable delete-api", null],
  ["bq ls", null],
  // Words joined from quoted and bare parts, with escapes, read as the shell reads them.
  ["terraform -chdir=\"my dir\" destroy -auto-approve", "deny"],
  ["terraform -chdir='prod infra' apply", "deny"],
  ["terraform ap'p'ly", "deny"],
  ["\"terra\"form apply", "deny"],
  ["terraform a\\pply", "deny"],
  ["terraform $'apply'", "deny"],
  ["terraform $'\\x61pply'", "deny"],
  // A program or verb that expands at run time, on a line about IaC: the user confirms.
  ["\"$TF\" apply", "ask"],
  ["${TERRAFORM_BIN} destroy", "ask"],
  ["$(which terraform) apply", "ask"],
  ["terraform $(echo apply)", "ask"],
  ["echo apply | xargs terraform", "ask"],
  ["\"$EDITOR\" notes.md", null],
  ["$HOME/bin/terraform apply", "deny"],
  // A shell fed on stdin, through every road.
  ["echo terraform apply|bash", "deny"],
  ["bash -s <<<'terraform apply'", "deny"],
  ["echo 'terraform apply' | sudo -u x bash", "deny"],
  ["bash <<'EOF'\nterraform destroy\nEOF", "deny"],
  ["echo hi | bash", null],
  // Help, a pipe inside quotes, case.
  ["terraform apply -help", null],
  ["terraform destroy --help", null],
  ["terraform help apply", null],
  ["aws ec2 terminate-instances help", null],
  ["gcloud help sql instances delete", null],
  ["az group delete -h", null],
  ["gsutil -h 'Cache-Control:no-cache' rm gs://b/x", "deny"],
  ["git commit -m \"docs: never echo terraform apply | sh\"", null],
  ["TERRAFORM apply", "deny"],
  ["Terraform.exe destroy", "deny"],
  ["AWS s3 rb s3://b", "deny"],
  ["tfenv exec plan", null],
];

describe("infrastructure: continuations, quoting, wrappers, and cloud deletes", () => {
  for (const [command, expected] of infraQa) {
    it(`${JSON.stringify(command)} → ${String(expected)}`, () => {
      assert.equal(evaluate(command, { branch: "feat" })?.decision ?? null, expected);
    });
  }

  it("asks, rather than crashing or recursing on, nesting deeper than it reads", () => {
    assert.equal(evaluate(`echo ${"$(echo ".repeat(40)}hi${")".repeat(40)}`, { branch: "feat" })?.decision, "ask");
    assert.equal(evaluate(`${"nohup ".repeat(100)}terraform plan`, { branch: "feat" })?.decision, "ask");
  });

  // A pattern that backtracks times the hook out, and a timed-out hook lets the command run.
  // Budgets lifted, so this times the parser itself, not the size gate in front of it; 1 s leaves
  // room for a machine running the suite in parallel, and a backtracking pattern takes far longer.
  // Best of three, so one GC pause or a busy neighbour (1261 ms once, under the full suite) can't fail it.
  it("evaluates a 200k-character heredoc, or line, in under 1 s with the budgets lifted", () => {
    const bodies = ["a".repeat(200_000), "|x".repeat(100_000), "/ |".repeat(66_667), "$(".repeat(100_000), '"a'.repeat(100_000), "`(".repeat(100_000), "<<x\n".repeat(50_000)];
    const lines = [...bodies.flatMap((body) => [`git commit -F - <<'EOF'\n${body}\nEOF`, `cat <<EOF | sh\n${body}\nEOF`]), `echo ${"x".repeat(200_000)}`, `echo ${"/x ".repeat(66_667)}`];
    for (const line of lines) {
      const took = best(line, UNBOUNDED);
      assert.ok(took < 1000, `${JSON.stringify(line.slice(0, 40))}… took ${Math.round(took)} ms (best of 3)`);
    }
  });
});

// Functions, heredoc terminators, spans, stdin shells, placeholders, more clouds. [command, expected decision]
const infraQa2 = [
  // A function body is a command; `function` names it, it doesn't hide it.
  ["function f { terraform apply; }; f", "deny"],
  ["function f { terraform destroy -auto-approve; }", "deny"],
  ["function f() { terraform apply; }; f", "deny"],
  ["f() { terraform apply; }; f", "deny"],
  ["coproc terraform apply", "deny"],
  ["coproc tf { terraform apply; }", "deny"],
  // Heredoc terminators: bash matches the whole line exactly, after quote removal of the whole word.
  ["cat <<EOF\nEOF \n: <<'X'\nEOF\nterraform apply\nX", "deny"],
  ["cat <<EOF\n  EOF\n: <<'X'\nEOF\nterraform apply\nX", "deny"],
  ["cat <<E\\OF\nEOF\nterraform apply", "deny"],
  ['cat <<"E"OF\nx\nEOF\nterraform apply\nE', "deny"],
  ["cat <<'E'OF\nx\nEOF\nterraform apply\nE", "deny"],
  ["cat <<EOF\nEOF \n: <<'X'\nEOF\ngit push --force origin main\nX", "deny"],
  ["cat <<E\\OF\nEOF\ngit push --force origin main", "deny"],
  ['cat <<"E"OF\nx\nEOF\ngit push --force origin main\nE', "deny"],
  ["cat <<'E'OF\nx\nEOF\ngit push --force origin main\nE", "deny"],
  ["cat <<EOF && git push --force origin main\nbody\nEOF", "deny"],
  ["sh <<-EOF\n\tterraform destroy\n\tEOF", "deny"],
  ["git commit -F - <<'EOF'\nfeat: x\n\n  EOF\nstill the message: terraform apply\nEOF", null],
  // Substitution spans: comments, case patterns, `$'…'`, and `${…}` end where bash ends them.
  ['echo "$(echo x # )\nterraform apply\n)"', "deny"],
  ['echo "$(case a in a) terraform apply;; esac)"', "deny"],
  ["echo \"$(echo $'a\\'b)'; terraform apply)\"", "deny"],
  ['echo "${x:-$(echo }; terraform apply)}"', "deny"],
  ['echo "$(echo x # )\ngit push --force origin main\n)"', "deny"],
  ['echo "$(git push --force origin main)"', "deny"],
  ['echo "$(case $x in (a) echo y;; esac)" && git status', null],
  ["echo \"${x:-'}'}\" done", null],
  // Brace expansion makes the words at run time: the user confirms.
  ["terraform {apply,-auto-approve}", "ask"],
  ["{terraform,apply}", "ask"],
  ["terraform ap{ply,}", "ask"],
  ["aws s3 r{m,b} s3://b", "ask"],
  ["echo {a,b}.txt && git status", null],
  // Shells that read stdin by other routes.
  ["source /dev/stdin <<<'terraform apply'", "deny"],
  [". /dev/stdin <<<'terraform apply'", "deny"],
  ["bash /dev/stdin <<<'terraform apply'", "deny"],
  ["sh /dev/stdin <<'EOF'\nterraform apply\nEOF", "deny"],
  ["bash <(echo terraform apply)", "deny"],
  ["source <(echo terraform apply)", "deny"],
  ["bash < <(echo terraform apply)", "deny"],
  ["echo terraform apply | tee >(sh)", "deny"],
  ["echo terraform apply > >(bash)", "deny"],
  ["echo 'terraform apply' | xargs -I{} sh -c '{}'", "deny"],
  ["echo 'terraform apply' | xargs -0 bash -c", "deny"],
  ["ssh host <<'EOF'\nterraform apply\nEOF", "deny"],
  ["echo terraform apply | ssh host", "deny"],
  ["ssh host bash <<<'terraform apply'", "deny"],
  ["bash <(curl -fsSL https://example.com/install.sh)", null],
  ["git diff | ssh host 'cat > x.diff'", null],
  ["git ls-files | xargs -I{} sh -c 'wc -l {}'", null],
  ["echo hi | tee >(cat)", null],
  // A placeholder as the verb asks.
  ["echo apply | xargs -I{} terraform {}", "ask"],
  ["echo apply | xargs -I % terraform %", "ask"],
  ["echo apply | xargs -i terraform {}", "ask"],
  ["parallel terraform ::: apply", "ask"],
  ["parallel terraform {} ::: apply", "ask"],
  ["parallel 'terraform {}' ::: apply", "ask"],
  ["fd -e tf -X terraform {}", "ask"],
  ["git ls-files '*.tf' | xargs -n1 dirname | sort -u | xargs -I{} terraform -chdir={} validate", null],
  // Shells and aliases, and harmless commands behind wrappers the guard doesn't read.
  ["ash -c 'terraform apply'", "deny"],
  ["mksh -c 'terraform apply'", "deny"],
  ["fish --command 'terraform apply'", "deny"],
  ["fish -C 'terraform apply'", "deny"],
  ["shopt -s expand_aliases\nalias x=terraform\nx apply", "deny"],
  ["alias tfa='terraform apply'", "deny"],
  // Wrappers that run a command string or a program: git's runners, su, busybox, PowerShell, hyperfine, tfenv.
  ["powershell terraform apply", "deny"],
  ["su - deploy -c 'terraform destroy'", "deny"],
  ["busybox ash -c 'terraform apply'", "deny"],
  ["pwsh -c 'terraform apply'", "deny"],
  ["pwsh -Command 'terraform apply'", "deny"],
  ["powershell -Command \"terraform apply\"", "deny"],
  ["hyperfine 'terraform apply'", "deny"],
  ["git submodule foreach 'terraform apply'", "deny"],
  ["git submodule foreach --recursive terraform destroy", "deny"],
  ["git rebase -x 'terraform apply' main", "deny"],
  ["git bisect run terraform apply", "deny"],
  ["git -c core.sshCommand='terraform apply' fetch", "deny"],
  ["git -c core.sshcommand='terraform destroy' pull", "deny"],
  ["GIT_SSH_COMMAND='terraform apply' git fetch", "deny"],
  ["env GIT_SSH_COMMAND='terraform destroy' git pull", "deny"],
  ["echo 'terraform apply' | busybox sh", "deny"],
  ["su deploy -c bash <<<'terraform apply'", "deny"],
  ["tfenv exec apply", "deny"],
  ["tofuenv exec destroy -auto-approve", "deny"],
  ["hyperfine --prepare='terraform apply' 'ls'", "deny"],
  ["pwsh -EncodedCommand dABlAHIAcgBhAGYAbwByAG0A", "ask"],
  ["alias tfa='terraform apply'\ntfa", "deny"],
  ["alias ll='ls -l'\nll", null],
  ["chrt -p 1234", null],
  ["git submodule foreach git pull", null],
  ["trap - EXIT", null],
  ["hyperfine 'pnpm test' 'pnpm lint'", null],
  // Cloud deletes that got through.
  ["gcloud deploy delivery-pipelines delete p --region r", "deny"],
  ["gcloud storage mv gs://b/x ./x", "deny"],
  ["gcloud storage rsync ./d gs://b --delete-unmatched-destination-objects", "deny"],
  ["az storage remove -c c --recursive", "deny"],
  ["az storage blob sync -c c -s d --delete-destination true", "deny"],
  ["az storage blob sync -c c -s d", "ask"],
  ["az storage blob sync -c c -s d --delete-destination false", null],
  ["bq --service_account x@y rm -f ds.t", "deny"],
  ["bq query 'DROP TABLE ds.t'", "deny"],
  ["bq query --nouse_legacy_sql 'DELETE FROM ds.t WHERE true'", "deny"],
  ["gcloud spanner databases execute-sql db --sql='DROP TABLE t'", "deny"],
  ["aws rds-data execute-statement --sql 'DROP TABLE t' --resource-arn a", "deny"],
  ["cdktf deploy", "deny"],
  ["cdktf destroy", "deny"],
  ["npx cdk deploy --all", "deny"],
  ["cdk bootstrap", "ask"],
  ["gcloud deploy releases list --delivery-pipeline p", null],
  ["gcloud storage mv ./x gs://b/x", null],
  ["gcloud storage rsync ./d gs://b", null],
  ["bq query 'SELECT 1'", null],
  ["cdk diff", null],
  ["cdktf synth", null],
  ["terramate run terraform plan", null],
  // Help, variables the line sets, and env's spellings.
  ["git apply fix.patch && $HOME/bin/check", null],
  ["\"$(git rev-parse --show-toplevel)\"/scripts/check.sh && git commit -m 'apply review'", null],
  ["TF=terraform; V=apply; $TF $V", "ask"],
  ["aws s3 rb help", null],
  ["aws s3 rm help", null],
  ["env -vS 'terraform apply'", "deny"],
  ['env -S"terraform apply"', "deny"],
  ["env -iS 'terraform apply'", "deny"],
  ["env - terraform apply", "deny"],
  ["env -u HOME terraform apply", "deny"],
];

describe("infrastructure: functions, heredocs, spans, stdin shells, and placeholders", () => {
  for (const [command, expected] of infraQa2) {
    it(`${JSON.stringify(command)} → ${String(expected)}`, () => {
      assert.equal(evaluate(command, { branch: "feat" })?.decision ?? null, expected);
    });
  }

  it("an exemption doesn't lift after a cd, pushd, or popd on the same line", () => {
    const rules = exempting("terraform -chdir=sandbox apply");
    for (const command of ["cd ../prod && terraform -chdir=sandbox apply", "pushd ../prod; terraform -chdir=sandbox apply", "popd; terraform -chdir=sandbox apply"]) {
      assert.equal(evaluate(command, { branch: "feat", rules })?.decision, "deny", command);
    }
    const dropRules = exempting("dropdb app_test");
    assert.equal(evaluate("dropdb app_test", { branch: "feat", rules: dropRules }), null);
    assert.equal(evaluate("cd /srv/prod && dropdb app_test", { branch: "feat", rules: dropRules })?.decision, "deny");
  });
});

// A line wrapped in `wrap` eight times (the guard's nesting depth), starting from `seed`.
const nest = (wrap, seed) => {
  let line = seed;
  for (let k = 0; k < 8; k += 1) line = wrap(line);
  return line;
};

// The biggest `shape(n)`, n a power of two, that fits the default size budget.
const fill = (shape) => {
  let n = 1;
  while (shape(n * 2).length <= LIMITS.chars) n *= 2;
  return shape(n);
};

// Best of three timings of one evaluate().
const best = (line, limits) =>
  Math.min(
    ...[1, 2, 3].map(() => {
      const started = performance.now();
      evaluate(line, { branch: "feat", limits });
      return performance.now() - started;
    }),
  );

// Milliseconds of CPU time the calling thread has used, read as the guard reads it for its own budget (cpuNow() in command-guard.mjs).
const cpuNow = () => {
  const { user, system } = typeof process.threadCpuUsage === "function" ? process.threadCpuUsage() : process.cpuUsage();
  return (user + system) / 1000;
};

// Wall-clock bound for one evaluate() with the default limits: the 250 ms budget plus headroom for a
// loaded CI runner (the worst shape measured 255 ms on an idle one). The old quadratics took
// 2–15 s, so this still catches them, and the hook's watchdog stays well above it.
const BOUND_MS = 1500;

// A branch lookup that blocks for 300 ms without using CPU.
const blockingBranchIn = () => {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 300);
  return "dev";
};

describe("guard: budgets and failures fail closed to ask", () => {
  it("asks, without parsing, for a line over the size budget", () => {
    // "Without parsing" is proven by the reason (the size gate answers before the parser runs),
    // not by the wall clock: a 50 ms bound flaked on loaded CI runners. BOUND_MS still catches a
    // gate that parses first.
    const line = `git commit -F - <<'EOF'\n${"a".repeat(LIMITS.chars)}\nEOF`;
    const started = performance.now();
    const verdict = evaluate(line, { branch: "feat" });
    const took = performance.now() - started;
    assert.ok(took < BOUND_MS, `took ${Math.round(took)} ms`);
    assert.equal(verdict?.decision, "ask");
    assert.match(verdict?.reason ?? "", /character budget/);
  });

  it("reads a line just under the size budget", () => {
    assert.equal(evaluate(`git commit -F - <<'EOF'\n${"a ".repeat(LIMITS.chars / 2 - 30)}\nEOF`, { branch: "feat" }), null);
  });

  it("asks when the time budget is spent, and the next call has a fresh budget", () => {
    const verdict = evaluate(`${"true;".repeat(20_000)}git status`, { branch: "feat", limits: { chars: Number.POSITIVE_INFINITY, ms: 0 } });
    assert.equal(verdict?.decision, "ask");
    assert.match(verdict?.reason ?? "", /0 ms budget/);
    assert.equal(evaluate("terraform apply", { branch: "feat" })?.decision, "deny");
  });

  // The CPU budget counts the guard's own work, so a process the scheduler leaves waiting (a loaded
  // machine) is not spent: here the wall clock moves 400 ms past the 250 ms budget inside a branch
  // lookup that uses no CPU, and the verdict is still the normal one.
  it("keeps the normal verdict when only wall-clock time passes (a descheduled guard)", () => {
    let calls = 0;
    const branchIn = () => {
      calls += 1;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 400);
      return "feat/x";
    };
    const started = performance.now();
    const verdict = evaluate('cd ../a && git commit -m "x"', { branch: "feat", branchIn });
    assert.ok(performance.now() - started >= 350, "the lookup should have stalled the wall clock");
    assert.equal(verdict, null);
    assert.equal(calls, 1);
  });

  it("keeps the normal verdict when an injected wall clock jumps past the CPU budget", () => {
    let reads = 0;
    const now = () => {
      reads += 1;
      return reads === 1 ? 0 : 1000;
    };
    // A frozen CPU clock, so a slow runner's real parse time can't trip the budget this test holds still.
    const verdict = evaluate(`${"true;".repeat(5000)}git status`, { branch: "feat", limits: { ...LIMITS, now, cpu: () => 0 } });
    assert.ok(reads > 1, "the line should have read the clock after it started");
    assert.equal(verdict, null);
  });

  it("asks, naming CPU time, when the guard's own work spends the budget (an injected CPU clock)", () => {
    let reads = 0;
    const cpu = () => {
      reads += 1;
      return reads * 100;
    };
    const verdict = evaluate(`${"true;".repeat(20_000)}git status`, { branch: "feat", limits: { ...LIMITS, chars: Number.POSITIVE_INFINITY, cpu } });
    assert.equal(verdict?.decision, "ask");
    assert.match(verdict?.reason ?? "", /250 ms budget of CPU time/);
  });

  it("asks, naming the wall-clock backstop, when a read blocks without using CPU", () => {
    const verdict = evaluate('cd ../a && git commit -m "x [skip ci]"; cd ../b && git commit -m "y [skip ci]"', { branch: "feat", branchIn: blockingBranchIn, limits: { ...LIMITS, wallMs: 100 } });
    assert.equal(verdict?.decision, "ask");
    assert.match(verdict?.reason ?? "", /100 ms of wall-clock time/);
    assert.equal(evaluate("terraform apply", { branch: "feat" })?.decision, "deny");
  });

  it("asks, naming the error, when evaluating throws", () => {
    // A rule whose matcher throws stands in for any parser bug.
    const throwing = { deny: [{ match: { test: () => { throw new Error("boom in a rule"); } }, unless: null, reason: "x", file: "f.json", project: true }], ask: [], allow: new Set(), error: "" };
    const verdict = evaluate("ls", { branch: "feat", rules: throwing });
    assert.equal(verdict?.decision, "ask");
    assert.match(verdict?.reason ?? "", /boom in a rule/);
  });

  it("the hook asks, for both hosts, when its input can't be read", () => {
    const root = guardIn({});
    const env = { ...process.env };
    delete env["WHIPPLETREE_GUARD"];
    delete env["REINS"];
    const raw = (host) => execFileSync(process.execPath, [join(root, "pkg", "hook.mjs"), host], { input: "{ not json", env, encoding: "utf8", stdio: ["pipe", "pipe", "ignore"] });
    assert.equal(JSON.parse(raw("claude")).hookSpecificOutput.permissionDecision, "ask");
    assert.equal(JSON.parse(raw("cursor")).permission, "ask");
  });

  // The old quadratics, each at a size that took 2–15 s (shape(n) builds the line): ask or deny
  // in under BOUND_MS with the default limits, under the watchdog the hook relies on. With the budgets
  // lifted, the parser itself must be linear: under 1 s at n (each quadratic took 1.8 s or more
  // there), or else 4× the input in under 8× the time (a quadratic takes 16×), best of three, so a
  // busy machine running the suite in parallel can't flake it.
  const shapes = [
    { label: "a pipeline of shells (printed words built once)", size: 6000, shape: (n) => `echo hi${"|sh".repeat(n)};terraform apply` },
    { label: "assignments (asAssigned)", size: 50_000, shape: (n) => `${"A=1 ".repeat(n)}terraform apply` },
    { label: "assignments behind env", size: 70_000, shape: (n) => `env ${"A=1 ".repeat(n)}terraform apply` },
    { label: "dynamic programs (the line read once)", size: 50_000, shape: (n) => `${"$x;".repeat(n)}terraform apply` },
    { label: "xargs with no verb", size: 10_000, shape: (n) => `${"echo x|xargs terraform;".repeat(n)}terraform apply` },
  ];
  for (const { label, size, shape } of shapes) {
    it(`${label}, n=${String(size)}: ask or deny in under ${String(BOUND_MS)} ms with the default limits`, () => {
      const started = performance.now();
      const verdict = evaluate(shape(size), { branch: "feat" });
      const took = performance.now() - started;
      assert.ok(took < BOUND_MS, `${label} took ${Math.round(took)} ms`);
      assert.ok(["ask", "deny"].includes(verdict?.decision ?? ""), `${label} → ${String(verdict?.decision)}`);
    });
    it(`${label}: linear with the budgets lifted`, () => {
      const small = best(shape(size / 4), UNBOUNDED);
      const large = best(shape(size), UNBOUNDED);
      assert.equal(evaluate(shape(size), { branch: "feat", limits: UNBOUNDED })?.decision, "deny");
      assert.ok(large < 1000 || large < small * 12, `${label}: ${Math.round(small)} ms at n/4, ${Math.round(large)} ms at n`);
    });
  }

  // Shapes that are linear but heavy (nested substitutions read at each level): at the size budget
  // the default limits hold them under the hook's timeout by a wide margin.
  it(`the worst shapes at the size budget finish in under ${String(BOUND_MS)} ms with the default limits`, () => {
    const lines = [
      fill((n) => `echo hi${"|sh".repeat(n)};terraform apply`),
      fill((n) => nest((s) => `sh -c "$(${s})"`, `echo ${"y ".repeat(n)}`)),
      fill((n) => nest((s) => `bash <<<"$(${s})"`, `echo ${"y ".repeat(n)}`)),
      fill((n) => `echo terraform apply${"|tee >(sh)".repeat(n)}`),
      fill((n) => `echo $(${"case a in a) ".repeat(n)})`),
    ];
    for (const line of lines) {
      const started = performance.now();
      evaluate(line, { branch: "feat" });
      const took = performance.now() - started;
      assert.ok(took < BOUND_MS, `${JSON.stringify(line.slice(0, 30))}… took ${Math.round(took)} ms`);
    }
  });
});

// ── Bounded branch lookups, the hook's watchdog, wrappers, and the fallback ──

// Spins for `ms` on this thread, the way a git blocked on a FIFO holds up a synchronous lookup.
const busy = (ms) => {
  const end = performance.now() + ms;
  while (performance.now() < end);
};

// Makes a FIFO with the system's mkfifo (Node has no API for it), with no shell in between.
const fifoAt = (path) => {
  mkdirSync(dirname(path), { recursive: true });
  execFileSync("mkfifo", [path]);
  return path;
};

// Runs the hook as Claude Code would, killed after 3× the watchdog so a hang fails the test
// instead of the suite. Returns Claude's hookSpecificOutput (null for silence) and the wall time.
const hookTimed = (root, command) => {
  const env = { ...process.env };
  delete env["WHIPPLETREE_GUARD"];
    delete env["REINS"];
  const started = performance.now();
  const output = execFileSync(process.execPath, [join(root, "pkg", "hook.mjs"), "claude"], { input: JSON.stringify({ tool_input: { command }, cwd: tmpdir() }), env, encoding: "utf8", timeout: WATCHDOG_MS * 3, stdio: ["pipe", "pipe", "ignore"] });
  return { output: output === "" ? null : JSON.parse(output).hookSpecificOutput, ms: performance.now() - started };
};

describe("guard: branch lookups are bounded", () => {
  it("looks each directory up once, however many commits and pushes run there", () => {
    const seen = [];
    const branchIn = (dir) => {
      seen.push(dir);
      return "feat/x";
    };
    const verdict = evaluate('cd ../x && git commit -m "a [skip ci]" && git commit -m "b [skip ci]"; git push --force; git -C ../x push', { branch: "feat", branchIn });
    assert.equal(verdict?.decision, "deny");
    assert.deepEqual(seen, ["../x"]);
  });

  it("looks nothing up for a line of plain commands after a cd (5000 of them)", () => {
    // Counts the work (lookups), not the time: with the default 250 ms budget a loaded CI runner
    // spent the budget on 5000 commands and the verdict became "ask", so lift the budgets here.
    let calls = 0;
    const branchIn = () => {
      calls += 1;
      return "feat";
    };
    assert.equal(evaluate(`cd .;${"true;".repeat(5000)}git status`, { branch: "feat", branchIn, limits: UNBOUNDED }), null);
    assert.equal(calls, 0);
  });

  it("asks once a slow lookup spends the time budget, without a second lookup", () => {
    // Each lookup blocks for 2 s; on "dev" the commits would pass, so only the clock read after
    // the first lookup turns this into an ask (without it: two lookups, 4 s, and no verdict).
    let calls = 0;
    const branchIn = () => {
      calls += 1;
      busy(2000);
      return "dev";
    };
    const verdict = evaluate('cd ../a && git commit -m "x [skip ci]"; cd ../b && git commit -m "y [skip ci]"', { branch: "feat", branchIn });
    assert.equal(verdict?.decision, "ask");
    assert.match(verdict?.reason ?? "", /250 ms budget/);
    assert.equal(calls, 1);
  });

  it("the hook asks, within the watchdog, for a push in a repo whose .git/HEAD is a FIFO", () => {
    // git blocks opening the FIFO forever; the lookup's own timeout kills it. Without that, the
    // hook sits in a blocked child process the watchdog can't stop, and never answers.
    const repo = repoWith({ ".git/objects/.keep": "", ".git/refs/.keep": "" });
    fifoAt(join(repo, ".git", "HEAD"));
    const { output, ms } = hookTimed(guardIn({}), `git -C ${repo} push --force`);
    assert.equal(output?.permissionDecision, "ask");
    assert.ok(ms < WATCHDOG_MS, `took ${Math.round(ms)} ms`);
  });
});

describe("guard: the hook's watchdog", () => {
  it("asks, naming the watchdog, when evaluation never finishes (a rule pattern that backtracks)", () => {
    // `^(a+)+$` against 40 a's and a `!` takes far longer than any hook timeout, and a regex never
    // calls tick(); only the watchdog stopping the evaluation gets an answer out.
    const root = guardIn({ "reins.json": { deny: [{ match: "^(a+)+$", reason: "Backtracks." }] } });
    const { output, ms } = hookTimed(root, `${"a".repeat(40)}!`);
    assert.equal(output?.permissionDecision, "ask");
    assert.match(output?.permissionDecisionReason ?? "", new RegExp(`${String(WATCHDOG_MS)} ms watchdog`));
    assert.ok(ms < WATCHDOG_MS * 2, `took ${Math.round(ms)} ms`);
  });

  it("refuses everything, quickly, when a rule file is a FIFO (a read that would block the hook)", () => {
    const root = guardIn({});
    fifoAt(join(root, "reins.json"));
    const { output, ms } = hookTimed(root, "ls");
    assert.equal(output?.permissionDecision, "deny");
    assert.match(output?.permissionDecisionReason ?? "", /not a regular file/);
    assert.ok(ms < WATCHDOG_MS, `took ${Math.round(ms)} ms`);
  });

  it("answers an everyday command with silence, as before", () => {
    assert.equal(hookTimed(guardIn({}), "git status").output, null);
  });
});

describe("guard: evaluate() forwards every option", () => {
  it("an option evaluate() doesn't name reaches the line evaluator, nested lines too", () => {
    // branchIn is called as a method of the options the line evaluator holds, so `this` shows
    // what reached it: a rule added later (targetIn) relies on the same forwarding.
    const reached = [];
    const options = {
      branch: "feat",
      branchIn(dir) {
        reached.push([dir, this.probe]);
        return "feat";
      },
      probe: "forwarded",
    };
    evaluate("git -C ../top push origin HEAD; bash -c 'git -C ../nested push origin HEAD'; echo $(git -C ../sub push origin HEAD)", options);
    assert.deepEqual(reached, [
      ["../top", "forwarded"],
      ["../nested", "forwarded"],
      ["../sub", "forwarded"],
    ]);
  });
});

describe("guard: span scanners cap their nesting", () => {
  it("asks by design, naming the depth, rather than overflowing the stack", () => {
    const verdict = evaluate(`echo ${"${x:-$(".repeat(5000)}`, { branch: "feat" });
    assert.equal(verdict?.decision, "ask");
    assert.match(verdict?.reason ?? "", /more than \d+ levels deep/);
  });

  it("still reads ordinary nesting", () => {
    assert.equal(evaluate('echo "${x:-$(echo "${y:-$(terraform apply)}")}"', { branch: "feat" })?.decision, "deny");
  });
});

// Wrappers that run `terraform apply`, the fallback for unknown runners, and
// the cheap object-storage and PaaS deletes. [command, expected decision]
const infraQa3 = [
  // Containers and pods: the program after the container, service, or `--`.
  ["docker exec c terraform apply", "deny"],
  ["docker exec -it -e TF_LOG=1 -w /infra c terraform apply", "deny"],
  ["docker compose exec infra terraform apply", "deny"],
  ["docker compose -f ops.yml run --rm infra terraform destroy", "deny"],
  ["docker-compose run --rm infra tofu apply", "deny"],
  ["podman exec c terraform destroy", "deny"],
  ["kubectl exec pod -- terraform apply", "deny"],
  ["kubectl exec -it pod -c box -- tofu destroy", "deny"],
  ["docker exec c terraform plan", null],
  ["docker compose run --rm app pnpm test", null],
  ["kubectl exec pod -- ls", null],
  ["kubectl get pods", null],
  ["docker build -t app .", null],
  // Package runners, secret and environment wrappers.
  ["bunx terraform apply", "deny"],
  ["dotenvx run -- terraform apply", "deny"],
  ["envchain prod terraform apply", "deny"],
  ["sops exec-env secrets.yaml 'terraform apply'", "deny"],
  ["sops exec-env secrets.yaml 'terraform plan'", null],
  ["sops -d secrets.yaml", null],
  // A watcher the guard doesn't read leaves a harmless command alone.
  ["entr -r pnpm test <<<x.ts", null],
  ["fd -e tf -x terraform fmt", null],
  // An ssh command for git is an everyday setting.
  ["GIT_SSH_COMMAND='ssh -i ~/.ssh/deploy' git fetch", null],
  ["git -c core.sshCommand='ssh -i key' fetch", null],
  // Fallback: an unknown program given an IaC CLI word and a destructive verb asks.
  ["unshare -r terraform apply", "ask"],
  ["systemd-run --user terraform apply", "ask"],
  ["docker run --rm hashicorp/terraform apply", "ask"],
  ["make terraform destroy", "ask"],
  ["unshare -r terraform state rm x", "ask"],
  ["docker run --rm hashicorp/terraform plan", null],
  ["grep -rn terraform apply.log", null],
  ["rg terraform apply", null],
  ["git log --grep terraform apply", null],
  ["ls terraform apply", null],
  // Object storage: deletes, syncs that delete, moves from a remote.
  ["rclone purge r:bucket", "deny"],
  ["rclone delete r:bucket/x", "deny"],
  ["rclone sync . r:bucket", "deny"],
  ["rclone --config c.conf sync . r:bucket", "deny"],
  ["rclone move r:bucket/x ./local", "deny"],
  ["rclone copy . r:bucket", null],
  ["rclone move ./x r:bucket", null],
  ["rclone ls r:bucket", null],
  ["s5cmd rm 's3://b/*'", "deny"],
  ["s5cmd --endpoint-url http://x rb s3://b", "deny"],
  ["s5cmd sync --delete . s3://b", "deny"],
  ["s5cmd cp x s3://b/", null],
  ["s5cmd sync . s3://b", null],
  ["mc rb --force local/b", "deny"],
  ["mc rm --recursive local/b/x", "deny"],
  ["mc mirror --remove ./site local/b", "deny"],
  ["mc ls local", null],
  ["mc mirror ./site local/b", null],
  ["s3cmd del --recursive s3://b", "deny"],
  ["s3cmd sync --delete-removed . s3://b", "deny"],
  ["s3cmd ls s3://b", null],
  ["azcopy rm https://a.blob.core.windows.net/c --recursive", "deny"],
  ["azcopy sync . https://a/c --delete-destination=true", "deny"],
  ["azcopy sync . https://a/c --delete-destination prompt", "deny"],
  ["azcopy sync . https://a/c", null],
  ["azcopy copy x https://a/c", null],
  // A raw DELETE through az, and PaaS destroys.
  ["az rest --method delete --url https://management.azure.com/x", "deny"],
  ["az rest -m DELETE --url https://management.azure.com/x", "deny"],
  ["az rest --method=delete --url u", "deny"],
  ["az rest --method get --url https://management.azure.com/x", null],
  ["doctl databases delete id", "deny"],
  ["doctl compute droplet rm web-1", "deny"],
  ["doctl compute droplet list", null],
  ["flyctl apps destroy app", "deny"],
  ["fly destroy app", "deny"],
  ["fly volumes delete vol_1", "deny"],
  ["fly deploy", null],
  ["fly status", null],
  ["heroku apps:destroy app --confirm app", "deny"],
  ["heroku pg:reset DATABASE", "deny"],
  ["heroku logs --tail", null],
  ["rclone help sync", null],
];

describe("infrastructure: containers, loaders, the fallback, object storage, and PaaS", () => {
  for (const [command, expected] of infraQa3) {
    it(`${JSON.stringify(command)} → ${String(expected)}`, () => {
      assert.equal(evaluate(command, { branch: "feat" })?.decision ?? null, expected);
    });
  }
});

// Wrappers the guard no longer reads, each a deny while the guard read it: the unknown-program
// fallback asks instead. [command, expected decision]
const unreadWrappers = [
  // An unknown program, then an IaC CLI word and an apply or destroy: the fallback asks.
  ["chrt -f 10 terraform apply", "ask"], // was deny
  ["chrt 10 terraform apply", "ask"], // was deny
  ["taskset -c 0 terraform apply", "ask"], // was deny
  ["taskset 0x1 terraform apply", "ask"], // was deny
  ["pkexec terraform apply", "ask"], // was deny
  ["setpriv --reuid=1000 terraform apply", "ask"], // was deny
  ["gosu deploy terraform apply", "ask"], // was deny
  ["fakeroot terraform apply", "ask"], // was deny
  ["nsenter -t 1 -m terraform apply", "ask"], // was deny
  ["runuser -u deploy -- terraform apply", "ask"], // was deny
  ["strace -f terraform apply", "ask"], // was deny
  ["strace -f -o trace.log terraform apply", "ask"], // was deny
  ["firejail terraform apply", "ask"], // was deny
  ["firejail --noprofile terraform destroy", "ask"], // was deny
  ["proxychains terraform apply", "ask"], // was deny
  ["proxychains4 -q -f p.conf terraform apply", "ask"], // was deny
  ["torsocks terraform apply", "ask"], // was deny
  ["watchexec -- terraform apply", "ask"], // was deny
  ["watchexec -e tf -c terraform apply", "ask"], // was deny
  ["entr -r terraform apply <<<main.tf", "ask"], // was deny
  ["fd -e tf -x terraform apply", "ask"], // was deny
  ["gdb -batch -ex run --args terraform apply", "ask"], // was deny
  ["watch -n 5 terraform apply", "ask"], // was deny
  ["parallel terraform -chdir={} apply ::: a b", "ask"], // was deny
  ["find . -name main.tf -execdir terraform destroy \\;", "ask"], // was deny
  ["terramate run terraform apply", "ask"], // was deny
  ["terramate run -- terraform destroy", "ask"], // was deny
  // A quoted string an unknown program may run: the fallback reads it as a command line and asks.
  ["runuser deploy -c 'terraform apply'", "ask"], // was deny
  ["sg docker -c 'terraform apply'", "ask"], // was deny
  ["trap 'terraform apply' EXIT", "ask"], // was deny
  ["entr -s 'terraform apply' <<<main.tf", "ask"], // was deny
  ["parallel ::: 'terraform apply'", "ask"], // was deny
  // CDK behind the same wrappers asks too.
  ["strace cdk destroy --force", "ask"], // was deny
  ["watch -n 60 cdk deploy --all", "ask"], // was deny
  ["parallel cdk destroy ::: a", "ask"], // was deny
  ["firejail npx cdk destroy", "ask"], // was deny
  ["runuser -u ci -- cdk destroy", "ask"], // was deny
  ["trap 'cdk destroy --force' EXIT", "ask"], // was deny
  ["strace -f sh -c 'cdk destroy'", "ask"], // was deny
  ["find . -name cdk.json -execdir cdk destroy --force \\;", "ask"], // was deny
  ["fd -x cdktf destroy", "ask"], // was deny
  ["strace cdk synth", null],
];

describe("infrastructure: wrappers the guard no longer reads", () => {
  for (const [command, expected] of unreadWrappers) {
    it(`${JSON.stringify(command)} → ${expected}`, () => {
      assert.equal(evaluate(command, { branch: "feat" })?.decision ?? null, expected);
    });
  }
});

// Image references with a tag or digest, opentofu's image, and compose services
// named for their image. Each must ask or deny. [command]
const infraQa4 = [
  "docker run --rm hashicorp/terraform:1.9 apply",
  "docker run --rm hashicorp/terraform:latest destroy",
  "docker run --rm hashicorp/terraform@sha256:abc apply",
  "podman run --rm docker.io/hashicorp/terraform:1.9 apply",
  "docker run --rm ghcr.io/opentofu/opentofu:1.8 apply",
  "docker compose run --rm terraform apply",
  "docker-compose run terraform destroy",
  "docker compose run --rm tf apply",
];

describe("infrastructure: image references and compose services", () => {
  for (const command of infraQa4) {
    it(`${JSON.stringify(command)} → ask or deny`, () => {
      assert.ok(["ask", "deny"].includes(evaluate(command, { branch: "feat" })?.decision ?? ""), command);
    });
  }

  it("the hook still answers when its stderr is closed (EPIPE on the failure note)", async () => {
    const root = guardIn({});
    const env = { ...process.env };
    delete env["WHIPPLETREE_GUARD"];
    delete env["REINS"];
    const child = spawn(process.execPath, [join(root, "pkg", "hook.mjs"), "claude"], { env, stdio: ["pipe", "pipe", "pipe"] });
    // Close our end of its stderr before it reads input, so its stderr write fails with EPIPE.
    await new Promise((done) => {
      child.stderr.once("close", done);
      child.stderr.destroy();
    });
    let out = "";
    child.stdout.on("data", (chunk) => {
      out += String(chunk);
    });
    const exited = new Promise((done) => child.once("close", (code) => done(code)));
    // Unparseable input sends the hook down failed(), which writes the answer and the stderr note.
    child.stdin.end("{ not json");
    assert.equal(await exited, 0);
    assert.equal(JSON.parse(out).hookSpecificOutput.permissionDecision, "ask");
  });
});

// Everyday commands an agent runs: the fallback and the wrappers must
// leave every one alone, because a guard that blocks these gets switched off.
const longBody = Array.from({ length: 400 }, (_, i) => `- item ${String(i)}: guard refuses \`terraform apply\` and \`aws s3 rm\`; run \`terraform plan\`; destroy old cache; drop table notes`).join("\n");
const everyday = [
  "git status",
  'git add -A && git commit -m "apply review feedback; destroy old cache"',
  "git commit -m 'terraform apply is a human action'",
  "git log --oneline -5",
  "git push -u origin feat/x",
  "git push --force-with-lease origin feat/x",
  "git rebase origin/dev",
  "git apply x.patch",
  "git stash push -u -m tag",
  "git fetch origin dev && git worktree add -b b ../p origin/dev",
  "git diff origin/dev...HEAD --stat",
  "git apply fix.patch && $HOME/bin/check",
  "\"$(git rev-parse --show-toplevel)\"/scripts/check.sh && git commit -m 'apply review'",
  "pnpm check",
  "pnpm test -- --run",
  "pnpm install --frozen-lockfile",
  "pnpm exec tsc --noEmit",
  "pnpm dlx prettier --check .",
  "pnpm infra:validate",
  "pnpm --filter web build",
  "npx tsc -p .",
  "node --test scripts/command-guard.test.mjs",
  "gh pr view 20 --json title,body",
  "gh pr checks 20",
  "gh run view 123 --log-failed",
  "gh run rerun 123 --failed",
  "gh api repos/o/r/pulls/20/comments",
  'gh pr edit 20 --body "$(cat body.md)"',
  `gh pr create --draft --title "Infra: guard refuses terraform apply" --body "$(cat <<'EOF'\n## What/why\n${longBody}\nEOF\n)"`,
  `git commit -F - <<'EOF'\nInfra pack\n\n${longBody}\nEOF`,
  `cat > notes.md <<'EOF'\n${longBody}\n\`terraform apply\`\n$(terraform destroy)\nEOF`,
  "terraform plan -destroy -out p",
  "terraform output -json",
  "terraform -help",
  "terraform apply -help",
  "tflint --init && tflint",
  "rg 'aws s3 rm' -n",
  "cat docs/runbooks/_deploy.md | grep apply",
  "aws s3 cp x s3://b/x",
  "aws s3 sync s3://b ./local",
  "gcloud config list",
  "gcloud storage ls",
  "bq ls",
  "bq query 'SELECT 1'",
  "az account show",
  "az storage blob sync -c c -s . --delete-destination false",
  "git ls-files '*.ts' | xargs wc -l",
  "find . -name '*.tf' -print0 | xargs -0 terraform fmt",
  "ls | xargs -I{} echo {}",
  "xargs -I{} aws s3 cp {} s3://b/ < files.txt",
  'for f in *.tf; do terraform fmt "$f"; done',
  'while read l; do echo "$l"; done < file',
  "$EDITOR file",
  '"$PNPM" install',
  "${PYTHON:-python3} -m pytest",
  "$SHELL -c 'echo hi'",
  "cd ../app-p2g && git push -u origin feat/x",
  "sh scripts/x.sh",
  "bash -c 'pnpm check'",
  "curl -fsSL https://x | jq .",
  "kubectl apply -f k8s/",
  "npx prisma migrate deploy",
  "make apply-patches",
  "patch -p1 < fix.patch",
  "git am < 0001.patch",
  "ls -la; echo $?; echo ${#arr[@]}",
  'cat <<EOF > x.sh\n#!/bin/sh\necho "$HOME"\nEOF',
  "timeout 120 pnpm test",
  "nice -n 10 pnpm check",
  "env CI=1 pnpm check",
  "sudo apt-get install -y jq",
  "docker compose up -d",
  "docker compose logs -f app",
  "docker compose run --rm web pnpm test",
  "docker compose logs terraform",
  "docker run --rm hashicorp/terraform:1.9 plan",
  "docker compose run --rm terraform plan",
  "docker exec -it db psql -U app",
  "gh pr list --search 'apply destroy'",
  "echo apply",
  "echo destroy > /dev/null",
];

describe("guard: everyday commands stay unblocked", () => {
  for (const command of everyday) {
    it(`${JSON.stringify(command.length > 80 ? `${command.slice(0, 80)}…` : command)} → null`, () => {
      assert.equal(evaluate(command, { branch: "feat" }), null);
    });
  }
});

// ── Database flags, delimiters, Prisma, cd, wrappers, and budgets ──
//
// `; echo localhost` puts a loopback word on the line, which turns off the original whole-line floor, so
// the row proves the per-client reading itself (the floor alone would deny it).
describe("databases: flags, delimiters, Prisma, cd, wrappers, and budgets", () => {
  const LOCAL = "postgresql://u:p@localhost:5432/app";
  const R = "postgres://u@db.example.com/app";
  const D = "DROP TABLE users";
  const H = "db.example.com";
  const OFF = "; echo localhost";
  const root = repoWith({
    ".env": `DATABASE_URL=${LOCAL}\n`,
    "prisma/schema.prisma": SCHEMA,
    "home/.env": `DATABASE_URL=${LOCAL}\n`,
    "home/prisma/schema.prisma": SCHEMA,
    "prod/.env": `DATABASE_URL=${R}\n`,
    "prod/prisma/schema.prisma": SCHEMA,
    "drop.sql": `${D};\n`,
    "big.sql": "SELECT 1;\n".repeat(99_000),
    ...Object.fromEntries(Array.from({ length: 12 }, (_, index) => [`s${index + 1}.sql`, "SELECT 1;\n"])),
    // Prisma's datasource names its variable, or names two.
    "pvar/.env": `DATABASE_URL=${LOCAL}\nPROD_URL=${R}\n`,
    "pvar/prisma/schema.prisma": 'datasource db {\n  provider = "postgresql"\n  url      = env("PROD_URL")\n}\n',
    "pvercel/.env": `POSTGRES_PRISMA_URL=${R}\n`,
    "pvercel/prisma/schema.prisma": 'datasource db {\n  provider = "postgresql"\n  url      = env("POSTGRES_PRISMA_URL")\n}\n',
    "pdirect/.env": `DATABASE_URL=${LOCAL}\nDIRECT_URL=${R}\n`,
    "pdirect/prisma/schema.prisma": 'datasource db {\n  provider  = "postgresql"\n  url       = env("DATABASE_URL")\n  directUrl = env("DIRECT_URL")\n}\n',
    "pcomment/.env": `DATABASE_URL=${LOCAL}\n`,
    "pcomment/prisma/schema.prisma": `datasource db {\n  provider = "postgresql"\n  // url   = "${R}"\n  url      = env("DATABASE_URL")\n}\n`,
    "pconfig/.env": `DATABASE_URL=${LOCAL}\nPROD_URL=${R}\n`,
    "pconfig/prisma.config.ts": "export default { datasource: { url: process.env.PROD_URL } };\n",
    // A .env saved with a byte-order mark.
    "bom/.env": `﻿DATABASE_URL=${R}\n`,
    // The schema somewhere the guard didn't look (package.json's prisma.schema, a folder).
    "schema-pj/.env": `DATABASE_URL=${LOCAL}\nPROD_URL=${R}\n`,
    "schema-pj/package.json": { prisma: { schema: "db/schema.prisma" } },
    "schema-pj/db/schema.prisma": 'datasource db {\n  provider = "postgresql"\n  url      = env("PROD_URL")\n}\n',
    "schema-lit/.env": `DATABASE_URL=${LOCAL}\n`,
    "schema-lit/package.json": { prisma: { schema: "db/schema.prisma" } },
    "schema-lit/db/schema.prisma": `datasource db {\n  provider = "postgresql"\n  url      = "${R}"\n}\n`,
    "schema-multi/.env": `DATABASE_URL=${LOCAL}\n`,
    "schema-multi/prisma/schema/db.prisma": `datasource db {\n  provider = "postgresql"\n  url      = "${R}"\n}\n`,
    "schema-multi/prisma/schema/models.prisma": "model A { id Int @id }\n",
    "schema-loc/.env": `DATABASE_URL=${LOCAL}\n`,
    "schema-loc/package.json": { prisma: { schema: "db/schema.prisma" } },
    "schema-loc/db/schema.prisma": SCHEMA,
    "schema-loc/prisma/schema/db.prisma": SCHEMA,
    "schema-none/.env": `DATABASE_URL=${LOCAL}\n`,
  });
  const readers = readersIn(root);
  const file = readers.fileIn;
  const decision = (command) => evaluate(command, readers)?.decision ?? null;
  const twelve = Array.from({ length: 12 }, (_, index) => `-f s${String(index + 1)}.sql`).join(" ");

  // [label, command, expected decision]
  /** @type {[string, string, string | null][]} */
  const rows = [
    // Getopt clusters, glued values, and a glued here-string, per client.
    ["psql -tAc", `psql -h ${H} -tAc "${D}"${OFF}`, "deny"],
    ["psql -Xqc", `psql -h ${H} -Xqc "${D}"${OFF}`, "deny"],
    ["psql -c glued", `psql -h ${H} -c"${D}"${OFF}`, "deny"],
    ["psql -qf", `psql -h ${H} -qf drop.sql${OFF}`, "deny"],
    ["psql -h glued", `psql -h${H} -c "${D}"${OFF}`, "deny"],
    ["mysql -e glued", `mysql -h ${H} -e"${D}"${OFF}`, "deny"],
    ["mysql -Be", `mysql -h ${H} -Be "${D}"${OFF}`, "deny"],
    ["mysql -ppass keeps its value glued", `mysql -h ${H} -ppass -e "${D}"${OFF}`, "deny"],
    ["here-string glued to its quote", `psql -h ${H} <<<"${D}"${OFF}`, "deny"],
    ["here-string before the host", `psql <<<"${D}" -h ${H}${OFF}`, "deny"],
    ["here-string glued to the host word", `psql -h ${H}<<<"${D}"${OFF}`, "deny"],
    ["pg_restore -Fc is a format, not --clean", `pg_restore -h ${H} -Fc -d app dump.bin`, null],
    ["pg_restore -c cleans", `pg_restore -h ${H} -c -d app dump.bin`, "deny"],
    // Fail closed: a remote client whose SQL comes from somewhere unread asks.
    ["remote client, stdin unread", `psql -h ${H}`, "ask"],
    ["remote client, unknown cluster", `psql -h ${H} -tAZ "${D}"${OFF}`, "ask"],
    ["listing databases reads no SQL", `psql -h ${H} -l`, null],
    ["stdin provably empty", `psql -h ${H} < /dev/null`, null],
    ["an interactive container shell stays allowed", "docker exec -it db psql -U app", null],
    // The heredoc reader, delimiters as bash reads them.
    ["'END-SQL'", `psql -h ${H} <<'END-SQL'\n${D};\nEND-SQL\necho localhost`, "deny"],
    ["\\EOF", `psql -h ${H} <<\\EOF\n${D};\nEOF\necho localhost`, "deny"],
    ["\"E.O.F\"", `psql -h ${H} <<"E.O.F"\n${D};\nE.O.F\necho localhost`, "deny"],
    ["a terminator with a trailing space doesn't end the body", `psql -h ${H} <<EOF\nSELECT 1;\nEOF \n${D};\nEOF\necho localhost`, "deny"],
    // Prisma's datasource variables, comments stripped, worst of url and directUrl.
    ["url = env(PROD_URL)", "cd pvar && prisma migrate reset --force", "deny"],
    ["url = env(POSTGRES_PRISMA_URL)", "cd pvercel && prisma migrate reset --force", "deny"],
    ["a remote directUrl", "cd pdirect && prisma migrate reset --force", "deny"],
    ["a commented-out remote literal is not the URL", "cd pcomment && prisma migrate reset --force", null],
    ["process.env.PROD_URL in prisma.config.ts", "cd pconfig && prisma migrate reset --force", "deny"],
    // Cd forms the guard can't follow lose track (home/ and . are loopback, so a miss allows).
    ["cd inside f()", "f() { cd prod; }; f; prisma migrate reset --force", "ask"],
    ["cd inside function", "function g { cd prod; }; g && prisma migrate reset --force", "ask"],
    ["cd in a case arm", "case x in x) cd prod;; esac; prisma migrate reset --force", "ask"],
    ["HOME= before cd", "HOME=prod cd && prisma migrate reset --force", "ask"],
    ["export HOME= before cd ~", "export HOME=prod; cd ~ && prisma migrate reset --force", "ask"],
    ["plain cd ~ still follows HOME", "cd ~ && prisma migrate reset --force", null],
    // Sudo resets the environment unless told to keep it.
    ["sudo drops an inline loopback URL", `cd prod && DATABASE_URL=${LOCAL} sudo prisma migrate reset --force`, "deny"],
    ["sudo -u drops it too", `cd prod && DATABASE_URL=${LOCAL} sudo -u app prisma migrate reset --force`, "deny"],
    ["sudo -E keeps it", `cd prod && DATABASE_URL=${LOCAL} sudo -E prisma migrate reset --force`, null],
    ["--preserve-env=NAME keeps that name", `cd prod && DATABASE_URL=${LOCAL} sudo --preserve-env=DATABASE_URL prisma migrate reset --force`, null],
    ["--preserve-env=OTHER drops the URL", `cd prod && DATABASE_URL=${LOCAL} sudo --preserve-env=PGHOST prisma migrate reset --force`, "deny"],
    ["--preserve-env= of the agent's own value asks", "sudo --preserve-env=DATABASE_URL prisma migrate reset --force", "ask"],
    // A shell option cluster holding `c` runs its next word.
    ["bash -lc", `bash -lc "psql -h ${H} -c '${D}'"${OFF}`, "deny"],
    ["sh -ec", `sh -ec "psql -h ${H} -c '${D}'"${OFF}`, "deny"],
    // The file budget is per line, shared by every client and every nested line.
    ["one client, 12 files", `psql -h ${H} ${twelve}`, null],
    ["two clients share one budget", `psql -h ${H} ${twelve}; psql -h ${H} ${twelve}`, "ask"],
    ["nested lines share it too (nested runs through evaluateLine)", `bash -c "psql -h ${H} ${twelve}"; bash -c "psql -h ${H} ${twelve}"`, "ask"],
    // Parens with a space before the second close are a subshell in a subshell.
    ["((cmd) )", `((psql -h ${H} -c "${D}") )${OFF}`, "deny"],
    // The lint's clearing forms, ported.
    ["MERGE … THEN DELETE", `psql -h ${H} -c "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE"`, "deny"],
    ["SET (a, b) = (NULL, NULL)", `psql -h ${H} -c "UPDATE users SET (email, name) = (NULL, NULL)"`, "deny"],
    ["T-SQL DELETE without FROM", `sqlcmd -S ${H} -Q "DELETE users WHERE id = 1"`, "deny"],
    ["aws rds-data reads SQL through destroysSql", "aws rds-data execute-statement --resource-arn arn:x --secret-arn arn:y --sql \"MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE\"", "deny"],
    // Heredoc ownership across a pipe, both directions.
    ["cat <<EOF | bash runs the body", "cat <<EOF | bash\nterraform destroy\nEOF", "deny"],
    ["cat <<EOF | psql reads the body", `cat <<EOF | psql -h ${H}\n${D};\nEOF\necho localhost`, "deny"],
    // A BOM, a backslashed program, and env -S.
    [".env with a BOM", "cd bom && prisma migrate dev", "deny"],
    ["\\prisma is prisma", "cd prod && \\prisma migrate reset --force", "deny"],
    ["env -S reads its string as a line", `env -S "psql -h ${H} -c '${D}'"${OFF}`, "deny"],
    ["env --split-string= too", `env --split-string="psql -h ${H} -c '${D}'"${OFF}`, "deny"],
    // A reset runs on loopback only once a datasource is read, every URL in it loopback.
    ["package.json prisma.schema → env(PROD_URL), remote in the root .env", "cd schema-pj && prisma migrate reset --force", "deny"],
    ["package.json prisma.schema → a literal remote URL", "cd schema-lit && prisma migrate reset --force", "deny"],
    ["multi-file prisma/schema/ folder, literal remote", "cd schema-multi && prisma migrate reset --force", "deny"],
    ["--schema prisma/schema (a folder), literal remote", "cd schema-multi && prisma migrate reset --force --schema prisma/schema", "deny"],
    ["no datasource read: a loopback .env alone asks", "cd schema-none && prisma migrate reset --force", "ask"],
    ["no datasource read: db push --force-reset asks too", "cd schema-none && prisma db push --force-reset", "ask"],
    ["no datasource read: a remote DATABASE_URL still refuses", "cd schema-none && DATABASE_URL=postgres://u@db.example.com/app prisma migrate reset --force", "deny"],
    ["no datasource read: migrate dev is unchanged", "cd schema-none && prisma migrate dev", null],
    ["control: package.json schema and a folder, all loopback, runs", "cd schema-loc && prisma migrate reset --force", null],
    // MySQL's ?socket= is judged by its directory, like postgres ?host=/dir.
    ["mysql ?socket=/cloudsql/… is not this machine", "DATABASE_URL=mysql://root@localhost/app?socket=/cloudsql/p:r:i prisma migrate reset --force", "deny"],
    // A local container's own database with no host asks, rather than being refused.
    ["docker compose exec psql DROP with no host asks", `docker compose exec db psql -U postgres -c "${D}"`, "ask"],
    ["docker compose exec psql DROP on a remote host still refuses", `docker compose exec db psql -h ${H} -c "${D}"`, "deny"],
    ["kubectl exec psql DROP with no host still refuses", `kubectl exec pg-0 -- psql -U postgres -c "${D}"`, "deny"],
  ];
  for (const [label, command, want] of rows) {
    it(`${label} → ${String(want)}`, () => {
      assert.equal(decision(command), want, command);
    });
  }

  // The reviewer's shape: 350 clients each reading a ~1 MB file. Per client, each read fit its own
  // cap, so the line read 350 MB; per line, the second read is over the byte budget and asks.
  it("350 clients × a 1 MB -f file asks after at most 20 reads, fast", () => {
    let sqlReads = 0;
    const big = "select 1 from t where a = 'x';\n".repeat(31_000);
    const started = performance.now();
    const verdict = evaluate(`psql -h ${H} -f a.sql; `.repeat(350), {
      branch: "feat",
      targetIn: () => null,
      fileIn: () => {
        sqlReads += 1;
        return big;
      },
    });
    const took = performance.now() - started;
    assert.equal(verdict?.decision, "ask");
    assert.ok(sqlReads <= 20, `${String(sqlReads)} reads`);
    assert.ok(took < BOUND_MS, `${Math.round(took)} ms`);
  });

  it("destroysSql is exported for the cloud rules", () => {
    assert.equal(destroysSql("MERGE INTO t USING s ON true WHEN MATCHED THEN DELETE"), true);
    assert.equal(destroysSql("UPDATE t SET (a, b) = (NULL, NULL)"), true);
    assert.equal(destroysSql("SELECT 1"), false);
  });

  it("evaluate() with no file reader treats a SQL file as unreadable (ask)", () => {
    assert.equal(evaluate(`psql -h ${H} -f drop.sql`, { branch: "feat" })?.decision, "ask");
  });

  it("MySQL's ?socket= is judged by its directory (a Cloud SQL socket is not this machine)", () => {
    assert.equal(targetOf("mysql://root@localhost/app?socket=/cloudsql/p:r:i"), "remote");
    assert.equal(targetOf("mysql://root@localhost/app?socket=/srv/sockets/mysqld.sock"), "remote");
    assert.equal(targetOf("mysql://root@localhost/app?socket=/tmp/mysql.sock"), "loopback");
    assert.equal(targetOf("mysql://root@localhost/app?socket=/var/run/mysqld/mysqld.sock"), "loopback");
    assert.equal(targetOf("mysql://root@localhost/app"), "loopback");
  });

  it("a multi-file schema folder past the guard's bounds asks", () => {
    const many = { dir: true, files: Array.from({ length: 70 }, (_, index) => `m${String(index)}.prisma`), dirs: [], more: false };
    // 70 loopback `.prisma` files in prisma/schema/ and no prisma/schema.prisma: past 64, it asks.
    const listed = { ...readers, dirIn: (_dir, path) => (path === "prisma/schema" ? many : null), fileIn: (dir, path) => (path === "prisma/schema.prisma" ? null : path.endsWith(".prisma") ? SCHEMA : file(dir, path)) };
    assert.equal(evaluate("prisma migrate reset --force", listed)?.decision, "ask");
    assert.equal(evaluate("prisma migrate reset --force", { ...listed, dirIn: (_dir, path) => (path === "prisma/schema" ? { ...many, files: many.files.slice(0, 10) } : null) })?.decision ?? null, null);
    const more = { ...readers, dirIn: (_dir, path) => (path === "prisma/schema" ? { dir: true, files: [], dirs: [], more: true } : null) };
    assert.equal(evaluate("prisma migrate reset --force", more)?.decision, "ask");
    // Written earlier on the line: what the reset reads is not what is on disk now.
    assert.equal(decision("cp other.prisma prisma/schema/db.prisma && prisma migrate reset --force"), "ask");
  });

  it("dotenvValue skips a byte-order mark", () => {
    assert.equal(dotenvValue("﻿DATABASE_URL=x\n", "DATABASE_URL"), "x");
  });

  // 64k-character single-segment lines: inside BOUND_MS with the default limits, and every one
  // asks once the time budget is gone (each loop checks the clock).
  /** @type {[string, (n: number) => string][]} */
  const single = [
    ["`cat <<A` openers", (n) => `cat ${"<<A ".repeat(n)}\nA`],
    ["`x` words", (n) => `psql -h ${H} ${"x ".repeat(n)}`],
    ["`cp a b;` chain", (n) => `${"cp a b;".repeat(n)}psql -h ${H}`],
    ["`ssh h psql` words", (n) => `ssh h ${"psql ".repeat(n)}-c "${D}"`],
    ["inline assignments", (n) => `${"A=1 ".repeat(n)}psql -h ${H}`],
    ["a .env-free prefix of env -u", (n) => `env ${"-u A ".repeat(n)}psql -h ${H}`],
  ];
  for (const [label, shape] of single) {
    it(`${label}: under ${String(BOUND_MS)} ms, and asks on a spent clock`, () => {
      const line = fill(shape);
      const started = performance.now();
      evaluate(line, readers);
      const took = performance.now() - started;
      assert.ok(took < BOUND_MS, `${Math.round(took)} ms`);
      assert.equal(evaluate(line, { ...readers, limits: { chars: LIMITS.chars, ms: 0 } })?.decision, "ask");
    });
  }
});

// A Prisma schema whose datasource url is `url` (a quoted literal or `env("NAME")`).
const ds = (url) => `datasource db {\n  provider = "postgresql"\n  url      = ${url}\n}\n`;

// ── Databases on a real tree: the reviewers' corpora, read through main()'s readers ──
// Each row: [command, expected decision, label, the agent's environment].
describe("databases: a project tree read the way the hook reads it", () => {
  const R = "postgres://u@db.example.com/app";
  const LOCAL = "postgresql://u:p@localhost:5432/app";
  const D = "DROP TABLE users";
  const H = "db.example.com";
  const root = mkdtempSync(join(tmpdir(), "guard-tree-"));
  roots.push(root);
  const put = (path, text) => {
    mkdirSync(join(root, path, ".."), { recursive: true });
    writeFileSync(join(root, path), text);
  };
  // cwd has a loopback .env and no schema, so a reset there asks; the rest each point somewhere else.
  put(".env", `DATABASE_URL=${LOCAL}\n`);
  put("package.json", JSON.stringify({ scripts: { "db:reset": "prisma migrate reset --force", test: "vitest run" } }));
  put("prod/.env", `DATABASE_URL=${R}\n`);
  put("home/.env", `DATABASE_URL=${LOCAL}\n`);
  put("empty/.env", "");
  put("exp/.env", `export DATABASE_URL='${R}' # prod\r\n`);
  put("both/.env", `DATABASE_URL=${R}\n`);
  put("both/.env.local", `DATABASE_URL=${LOCAL}\n`);
  put("pe/.env", `DATABASE_URL=${LOCAL}\n`);
  put("pe/prisma/.env", `DATABASE_URL=${R}\n`);
  put("bom/.env", `﻿DATABASE_URL=${R}\n`);
  put("cmtschema/.env", `DATABASE_URL=${R}\n`);
  put("cmtschema/prisma/schema.prisma", `datasource db {\n  provider = "postgresql"\n  // url = "${LOCAL}"\n  url      = env("DATABASE_URL")\n}\n`);
  put("othervar/.env", `DATABASE_URL=${LOCAL}\nPROD_URL=${R}\n`);
  put("othervar/prisma/schema.prisma", ds('env("PROD_URL")'));
  put("direct/.env", `DATABASE_URL=${LOCAL}\nDIRECT_URL=${R}\n`);
  put("direct/prisma/schema.prisma", `datasource db {\n  provider = "postgresql"\n  url       = env("DATABASE_URL")\n  directUrl = env("DIRECT_URL")\n}\n`);
  put("shadowlit/.env", `DATABASE_URL=${R}\n`);
  put("shadowlit/prisma/schema.prisma", `datasource db {\n  provider = "postgresql"\n  url = env("DATABASE_URL")\n  shadowDatabaseUrl = "${LOCAL}"\n}\n`);
  put("pj/.env", `DATABASE_URL=${LOCAL}\nPROD_URL=${R}\n`);
  put("pj/package.json", JSON.stringify({ prisma: { schema: "db/schema.prisma" } }));
  put("pj/db/schema.prisma", ds('env("PROD_URL")'));
  put("pjlit/.env", `DATABASE_URL=${LOCAL}\n`);
  put("pjlit/package.json", JSON.stringify({ prisma: { schema: "db/schema.prisma" } }));
  put("pjlit/db/schema.prisma", ds(`"${R}"`));
  put("multi/.env", `DATABASE_URL=${LOCAL}\n`);
  put("multi/prisma/schema/db.prisma", ds(`"${R}"`));
  put("multi/prisma/schema/models.prisma", "model A { id Int @id }\n");
  put("mysock/.env", "DATABASE_URL=mysql://root@localhost/app?socket=/cloudsql/p:r:i\n");
  // The controls: every datasource read, every URL loopback.
  put("loc/.env", `DATABASE_URL=${LOCAL}\n`);
  put("loc/prisma/schema.prisma", ds('env("DATABASE_URL")'));
  put("loc/package.json", JSON.stringify({ scripts: { "db:reset": "prisma migrate reset --force" } }));
  put("pjloc/.env", `DATABASE_URL=${LOCAL}\n`);
  put("pjloc/package.json", JSON.stringify({ prisma: { schema: "db/schema.prisma" } }));
  put("pjloc/db/schema.prisma", ds('env("DATABASE_URL")'));
  put("multiloc/.env", `DATABASE_URL=${LOCAL}\n`);
  put("multiloc/prisma/schema/db.prisma", ds('env("DATABASE_URL")'));
  put("multiloc/prisma/schema/models/a.prisma", "model A { id Int @id }\n");
  put("drop.sql", `${D};\n`);
  put("bin.sql", Buffer.from([0, 255, 254, 0x44, 0x52, 0, 13, 10, 0xc3, 0x28]));
  put("slow.sql", "drop x ".repeat(120_000));
  put("big1m.sql", `${"select 1 from t where a = 'x'; ".repeat(31_000)}\n`);
  put("bigq.sql", `select '${"a".repeat(999_000)}';\n`);
  symlinkSync("loop.sql", join(root, "loop.sql"));

  /** @type {[string, string | null, string, Record<string, string>?][]} */
  const rows = [
    // Input that once threw or hung: a throw skipped the guard for the whole line.
    ["prisma migrate dev --name postgres://%ff", "ask", "a URL-shaped --name reads as an unparsable target"],
    [`${Array(20_000).fill("eval").join(" ")} git push --force origin main`, "ask", "eval nested past MAX_NESTING"],
    [`${"(".repeat(5000)}git push --force origin main${")".repeat(5000)}`, "deny", "deep subshell parens"],
    [`psql -h ${H} -f bin.sql`, null, "a binary -f file"],
    [`psql -h ${H} -f loop.sql`, "ask", "a symlink loop as the -f file"],
    [`psql -h ${H} -f slow.sql`, "ask", "840 KB of 'drop x' with no ';'"],
    ["cd empty && prisma migrate reset --force", "ask", "an empty .env"],
    // .env parsing.
    ["cd exp && prisma migrate reset --force", "deny", "export, quotes, a comment, and CRLF"],
    ["cd both && prisma migrate reset --force", "deny", ".env remote, .env.local loopback"],
    ["cd pe && prisma migrate reset --force", "deny", "prisma/.env remote"],
    ["cd pe && prisma migrate dev", "deny", "prisma/.env remote, migrate dev"],
    ["cd bom && prisma migrate reset --force", "deny", "a .env with a BOM, reset"],
    // Hosts.
    [`PGHOSTADDR=10.0.0.5 PGHOST=localhost psql -c "${D}"`, "deny", "inline PGHOSTADDR after PGHOST"],
    [`export PGHOSTADDR=10.0.0.5 && psql -h localhost -c "${D}"`, "deny", "an exported PGHOSTADDR"],
    [`PGSERVICEFILE=prod.conf psql -h localhost -c "${D}"`, null, "PGSERVICEFILE without PGSERVICE, loopback"],
    [`psql -c "${D}"`, "deny", "PGHOST remote in the environment, no -h", { PGHOST: H }],
    [`psql "postgresql://localhost/app?host=localhost&host=${H}" -c "${D}"`, "deny", "URI host= twice"],
    [`psql "postgresql://localhost/app?hostaddr=10.0.0.5" -c "${D}"`, "deny", "URI hostaddr"],
    [`psql "postgresql://localhost/app?sslmode=require&application_name=x" -c "${D}"`, null, "other URI params, loopback"],
    [`psql "postgresql://localhost:5432@${H}/app" -c "${D}"`, "deny", "localhost:5432@ a remote host"],
    [`psql "postgresql://[fe80::1%25eth0]/app" -c "${D}"`, "deny", "an IPv6 zone id"],
    [`psql -h 0.0.0.0 -c "${D}"`, "deny", "0.0.0.0"],
    [`psql "postgresql://127.1/app" -c "${D}"`, "deny", "127.1 isn't read as loopback"],
    [`psql "postgresql://2130706433/app" -c "${D}"`, "deny", "a decimal IP isn't read as loopback"],
    [`psql "postgresql://localhost./app" -c "${D}"`, "deny", "localhost. isn't read as loopback"],
    [`psql -h /tmp/../cloudsql/p:r:prod -c "${D}"`, "deny", "/tmp/.. to a Cloud SQL socket"],
    [`psql -h localhost "postgresql:///app?host=${H}" -c "${D}"`, "deny", "-h localhost and a URI query host"],
    [`psql -h ${H} -f /tmp/missing-x.sql`, "ask", "a missing -f file"],
    // Client flag shapes.
    [`psql -h ${H} -c"${D}"`, "deny", 'glued -c"…"'],
    [`psql -h ${H} -tAc "${D}"`, "deny", "bundled -tAc"],
    [`psql -h ${H} -Xqc "${D}"`, "deny", "bundled -Xqc"],
    [`psql -h ${H} -qf drop.sql`, "deny", "bundled -qf file"],
    [`mysql -h ${H} -e"${D}"`, "deny", "mysql glued -e"],
    [`mysql -h ${H} -Be "${D}"`, "deny", "mysql bundled -Be"],
    [`psql -h ${H} <<<"${D}"`, "deny", "glued here-string"],
    [`psql -h ${H} <<< "${D}"`, "deny", "spaced here-string"],
    [`psql -h ${H} --command "${D}"`, "deny", "--command spaced"],
    [`psql --host ${H} -c "${D}"`, "deny", "--host spaced"],
    [`psql -h ${H} -c "${D}" -c "SELECT 1"`, "deny", "two -c"],
    [`psql -h ${H} -c "${D}" --single-transaction`, "deny", "a trailing flag"],
    [`psql --host=${H} --command="${D}"`, "deny", "--host= --command="],
    [`psql -d "host=${H} dbname=app" -c "${D}"`, "deny", "-d conninfo"],
    [`psql "host=localhost host=${H}" -c "${D}"`, "deny", "two host= in a conninfo"],
    [`psql "postgres://localhost,${H}/app" -c "${D}"`, "deny", "a multi-host URI"],
    [`psql -h localhost,${H} -c "${D}"`, "deny", "a multi-host -h"],
    // Heredoc delimiters.
    [`cat <<'END-SQL' | psql -h ${H}\n${D};\nEND-SQL`, "deny", "cat <<'END-SQL' (a dash in the delimiter)"],
    [`cat <<\\EOF | psql -h ${H}\n${D};\nEOF`, "deny", "cat <<\\EOF"],
    [`psql -h ${H} <<'END-SQL'\n${D};\nEND-SQL`, "deny", "psql <<'END-SQL'"],
    [`psql -h ${H} <<\\EOF\n${D};\nEOF`, "deny", "psql <<\\EOF"],
    [`psql -h ${H} <<"E.O.F"\n${D};\nE.O.F`, "deny", 'psql <<"E.O.F"'],
    [`psql -h ${H} <<-EOF\n\t${D};\n\tEOF`, "deny", "psql <<-EOF with tabs"],
    // cd: forms the guard follows, and forms that lose track.
    ["f() { cd prod; }; f && prisma migrate reset --force", "ask", "a function body's cd, called"],
    ["function f { cd prod; }; f; prisma migrate reset --force", "ask", "the function keyword"],
    ["cd prod & prisma migrate reset --force", "ask", "a cd in the background"],
    ["cd prod\nprisma migrate reset --force", "deny", "a newline after cd"],
    ["cd prod || exit 1; prisma migrate reset --force", "deny", "cd || exit"],
    ["pushd prod >/dev/null && prisma migrate reset --force", "ask", "pushd with a redirect"],
    ["cd prod 2>/dev/null && prisma migrate reset --force", "ask", "cd with a redirect"],
    ["[ -d prod ] && cd prod && prisma migrate reset --force", "deny", "test && cd"],
    ["for d in prod; do cd $d; done; prisma migrate reset --force", "ask", "cd to a loop variable"],
    ["while false; do :; done; cd prod && prisma migrate reset --force", "deny", "cd after a loop"],
    [`export HOME=${join(root, "prod")} && cd ~ && prisma migrate reset --force`, "ask", "export HOME, then cd ~"],
    [`HOME=${join(root, "prod")}; cd && prisma migrate reset --force`, "ask", "HOME=, then a bare cd"],
    // The environment, and wrappers in front of the tool.
    ["cd prod && sudo prisma migrate reset --force", "deny", "sudo resets the environment", { DATABASE_URL: LOCAL }],
    ["cd prod && sudo -u postgres prisma migrate reset --force", "deny", "sudo -u resets it too", { DATABASE_URL: LOCAL }],
    ["cd prod && su app -c 'prisma migrate reset --force'", "ask", "su -c", { DATABASE_URL: LOCAL }],
    ["cd prod && env - PATH=/usr/bin prisma migrate reset --force", "deny", "env - clears it", { DATABASE_URL: LOCAL }],
    ["cd prod && env --ignore-environment prisma migrate reset --force", "deny", "env --ignore-environment", { DATABASE_URL: LOCAL }],
    ["cd prod && env -iPATH=/x prisma migrate reset --force", "deny", "env -i glued to a value", { DATABASE_URL: LOCAL }],
    ["cd prod && env -S 'prisma migrate reset --force'", "ask", "env -S string", { DATABASE_URL: LOCAL }],
    ["cd prod && nohup prisma migrate reset --force &", "deny", "nohup … &"],
    ["cd prod && timeout -s KILL 60 prisma migrate reset --force", "deny", "timeout -s KILL 60"],
    ["cd prod && nice -n 10 npx --yes prisma@6 migrate reset --force", "deny", "nice, then npx with a version"],
    ["cd prod && npx -p prisma prisma migrate reset --force", "deny", "npx -p"],
    ["cd prod && pnpm exec prisma migrate reset --force", "deny", "pnpm exec"],
    ["cd prod && yarn prisma migrate reset --force", "deny", "yarn prisma"],
    ["cd prod && bunx prisma migrate reset --force", "deny", "bunx"],
    ["cd prod && npm exec -- prisma migrate reset --force", "deny", "npm exec --"],
    ["cd prod && node ./node_modules/.bin/prisma migrate reset --force", "deny", "node .bin/prisma"],
    ["cd prod && command prisma migrate reset --force", "deny", "command"],
    ["cd prod && exec prisma migrate reset --force", "deny", "exec"],
    ["cd prod && 'prisma' migrate reset --force", "deny", "a quoted program"],
    ["cd prod && pri''sma migrate reset --force", "deny", "a split-quoted program"],
    ["cd prod && prisma migrate 'reset' --force", "deny", "a quoted subcommand"],
    ["cd prod && prisma migrate re''set --force", "deny", "a split-quoted subcommand"],
    ["cd prod && prisma  migrate   reset --force", "deny", "extra spaces"],
    ["cd prod && prisma\tmigrate\treset --force", "deny", "tabs"],
    ["cd prod && prisma migrate reset -f", "deny", "-f"],
    ["cd prod && PRISMA_X=1 prisma migrate reset --force", "deny", "an unrelated inline variable"],
    ["cd prod && DATABASE_URL= prisma migrate reset --force", "ask", "an empty inline DATABASE_URL"],
    ["cd prod && prisma migrate reset --force --schema prisma/schema.prisma", "deny", "--schema in the directory"],
    ["cd prod && prisma migrate reset --force --schema=./schema.prisma", "deny", "--schema=./"],
    ["npm --prefix prod run db:reset", "deny", "npm --prefix, no script there"],
    [`bash -lc 'psql -h ${H} -c "${D}"'`, "deny", "bash -lc"],
    [`sh -ec 'psql -h ${H} -c "${D}"'`, "deny", "sh -ec"],
    ["bash -c 'cd prod && prisma migrate reset --force'", "deny", "bash -c, cd, reset"],
    [`echo users | xargs -I{} psql -h ${H} -c "DROP TABLE {}"`, "deny", "xargs psql"],
    [`find . -name '*.sql' -exec psql -h ${H} -f {} \\;`, "ask", "find -exec psql -f {}"],
    [`watch -n 5 psql -h ${H} -c "${D}"`, "deny", "watch psql"],
    [`time psql -h ${H} -c "${D}"`, "deny", "time psql"],
    [`PGPASSWORD=x psql -h ${H} -c "${D}"`, "deny", "a PGPASSWORD prefix"],
    [`sudo -u postgres psql -h ${H} -c "${D}"`, "deny", "sudo -u postgres psql"],
    // Prisma's schema and config, wherever they are.
    ["cd cmtschema && prisma migrate reset --force", "deny", "a commented-out loopback url; the real one is remote"],
    ["cd othervar && prisma migrate reset --force", "deny", 'url = env("PROD_URL"), not DATABASE_URL'],
    ["cd direct && prisma migrate reset --force", "deny", "a remote directUrl"],
    ["cd shadowlit && prisma migrate reset --force", "deny", "a loopback shadowDatabaseUrl, a remote url"],
    ["cd pj && prisma migrate reset --force", "deny", "package.json's prisma.schema → env(PROD_URL)"],
    ["cd pjlit && prisma migrate reset --force", "deny", "package.json's prisma.schema → a literal remote url"],
    ["cd multi && prisma migrate reset --force --schema prisma/schema", "deny", "--schema prisma/schema (a folder), a literal remote url"],
    ["cd mysock && prisma migrate reset --force", "deny", "mysql ?socket=/cloudsql"],
    ["cd loc && prisma migrate reset --force", null, "control: a loopback schema and .env"],
    ["cd loc && pnpm db:reset", null, "control: a pnpm script, loopback schema"],
    ["cd pjloc && prisma migrate reset --force", null, "control: package.json's prisma.schema, loopback"],
    ["cd multiloc && prisma migrate reset --force", null, "control: a multi-file folder, loopback"],
    // SQL: shapes, comments, and size.
    [`psql -h ${H} -c "MERGE INTO users u USING x ON true WHEN MATCHED THEN DELETE"`, "deny", "MERGE … THEN DELETE"],
    [`psql -h ${H} -c "UPDATE users SET (a, b) = (NULL, NULL)"`, "deny", "a tuple UPDATE to NULL"],
    [`sqlcmd -S ${H} -Q "DELETE users"`, "deny", "T-SQL DELETE without FROM"],
    [`psql -h ${H} -c "SELECT lo_unlink(oid) FROM pg_largeobject_metadata"`, null, "lo_unlink"],
    [`psql -h ${H} -c "CREATE FUNCTION w() RETURNS void AS 'DELETE FROM users' LANGUAGE sql; SELECT w()"`, "deny", "a function body that deletes"],
    [`mysql -h ${H} -e "${D}" # comment`, "deny", "mysql with a shell comment"],
    [`mysql -h ${H} -e "SELECT 1 # ; ${D}"`, "deny", "mysql # comment before the DROP (refused anyway)"],
    [`mysql -h ${H} -e "SELECT 1; # x\n${D}"`, "deny", "mysql # comment, then a DROP on the next line"],
    [`prisma db execute --url ${R} --stdin <<EOF\n${D};\nEOF`, "deny", "prisma db execute --stdin, heredoc"],
    [`prisma db execute --url ${R} --file drop.sql`, "deny", "prisma db execute --file"],
    [`echo "${D}" | prisma db execute --url ${R} --stdin`, "deny", "echo | prisma db execute --stdin"],
    [`psql -h ${H} -f big1m.sql`, null, "a ~1 MB benign file"],
    [`psql -h ${H} -f bigq.sql`, "ask", "a 1 MB single statement"],
    // Everyday commands stay allowed.
    ["grep -rn DROP prisma/migrations", null, "grep DROP"],
    ['rg "TRUNCATE|DELETE FROM" migrations/', null, "rg"],
    ["cat prisma/migrations/0001_init/migration.sql", null, "cat a migration"],
    ["cat drop.sql | grep DROP", null, "cat | grep"],
    ['git log -S "DROP TABLE"', null, "git log -S"],
    ['git commit -m "drop table users in migration"', null, "a commit message"],
    ["git add prisma/migrations && git commit -m wip", null, "git add migrations"],
    ["git fetch origin dev && git rebase origin/dev", null, "git rebase"],
    ["prisma generate", null, "prisma generate"],
    ["prisma migrate dev --name add_users", null, "a local migrate dev"],
    ["prisma migrate dev --name init", null, "a local migrate dev, init"],
    ["pnpm prisma migrate dev --name add_users", null, "pnpm prisma migrate dev"],
    ["npx prisma migrate dev --create-only", null, "npx migrate dev --create-only"],
    ["pnpm db:reset", "ask", "a package script reset, no schema in the tree"],
    ["npx prisma studio", null, "prisma studio"],
    [`psql ${LOCAL} -f drop.sql`, null, "a loopback -f"],
    [`psql -h localhost -U postgres -c "${D}"`, null, "psql localhost DROP"],
    [`psql -h 127.0.0.1 -p 5433 -d app -tAc "${D}"`, null, "psql loopback -tAc"],
    ["psql postgres://postgres@localhost:5432/test -f drop.sql", null, "a loopback URL -f"],
    ['psql -c "SELECT 1"', null, "no host, SELECT"],
    [`psql -c "${D}"`, "deny", "no host, DROP: the floor refuses it"],
    ['docker compose exec db psql -U postgres -c "SELECT 1"', null, "docker compose exec, SELECT"],
    ["git diff -- prisma/migrations | psql -h localhost", null, "a pipe into a local psql"],
    ["pg_dump -h db.example.com app > backup.sql", null, "pg_dump to a file"],
    ["goose -dir db/migrations create add_users sql", null, "goose create"],
    ["ls db/migrate", null, "ls db/migrate"],
    ["bin/rails db:migrate", null, "rails migrate"],
    ["make db-reset", null, "make (not modelled)"],
    ["pnpm install", null, "pnpm install"],
    ["pnpm -C packages/api test", null, "pnpm -C test"],
    ["pnpm --filter api build", null, "pnpm --filter build"],
    ["gh pr view 21 --json title", null, "gh pr view"],
    ["gh pr create --draft --title 'drop table cleanup' --body 'DROP TABLE x'", null, "gh pr create mentioning DROP"],
    ["gh api repos/o/r/pulls/21/comments", null, "gh api read"],
    ["echo 'DROP TABLE users' > notes.txt", null, "echo into a file"],
    ["cat drop.sql", null, "cat sql"],
    ["ssh build-box 'ls /var/log'", null, "ssh, harmless"],
    ["docker ps", null, "docker ps"],
  ];
  for (const [command, want, label, env] of rows) {
    // The ~1 MB file's verdict is read with the time budget lifted; the test after it holds the budget.
    const readers = label === "a ~1 MB benign file" ? { ...readersIn(root, env), limits: { ...LIMITS, ms: Number.POSITIVE_INFINITY, wallMs: Number.POSITIVE_INFINITY } } : readersIn(root, env);
    it(`${label} → ${String(want)}`, () => {
      assert.equal(evaluate(command, readers)?.decision ?? null, want, command.slice(0, 200));
    });
  }

  // The ~1 MB benign file within the budget. The guard spends its budget in CPU time of its own thread (cpuNow() in command-guard.mjs), so this
  // measures the same thing: wall time stretched past 250 ms when two CI jobs shared four cores (fastest of five: 260 ms), CPU time barely moves.
  // The fastest of up to ATTEMPTS reads, stopping at the first that fits, so a spike on a busy machine costs some reads, not the test. On a machine
  // past its load line (lock.mjs → loadLine()) even CPU time stretches (shared caches, a sibling hyperthread), so the bar is the loose BOUND_MS
  // there: the old quadratics took 2 to 15 s, and the row above this one already proves the verdict. Otherwise the bar is the budget itself.
  it(`a ~1 MB benign -f file reads inside the ${String(LIMITS.ms)} ms budget`, () => {
    const ATTEMPTS = 10;
    const loaded = loadavg()[0] > loadLine();
    const bar = loaded ? BOUND_MS : LIMITS.ms;
    let fastest = Number.POSITIVE_INFINITY;
    for (let attempt = 0; attempt < ATTEMPTS && fastest >= bar; attempt += 1) {
      const started = cpuNow();
      evaluate(`psql -h ${H} -f big1m.sql`, readersIn(root));
      fastest = Math.min(fastest, cpuNow() - started);
    }
    assert.ok(fastest < bar, `fastest of ${ATTEMPTS}: ${Math.round(fastest)} ms of CPU time, bar ${bar} ms${loaded ? ` (the 1-minute load ${loadavg()[0].toFixed(1)} is over the line ${loadLine()})` : ""}`);
  });
});

// ── Paths, gh flags, abbreviations, refspecs, the API, and data stores: bypasses that each returned
// allow, and a control per rule. [label, command, branch where the hook runs, expected decision] ──
const pathsAndApi = [
  // A full path to the program is that program, as the infra and SQL rules already read it.
  ["/usr/bin/git force-push dev", "/usr/bin/git push -f origin dev", "feat", "deny"],
  ["/usr/bin/git delete main", "/usr/bin/git push --delete origin main", "feat", "deny"],
  ["/usr/local/bin/git +main", "/usr/local/bin/git push origin +main", "feat", "deny"],
  ["/usr/bin/gh ready --undo", "/usr/bin/gh pr ready 1 --undo", "feat", "deny"],
  ["/usr/local/bin/gh merge", "/usr/local/bin/gh pr merge 1", "feat", "ask"],
  ["/usr/bin/dropdb", "/usr/bin/dropdb -h prod app", "feat", "deny"],
  ["/usr/bin/env git force-push main", "/usr/bin/env git push -f origin main", "feat", "deny"],
  ["git.exe force-push dev", "git.exe push -f origin dev", "feat", "deny"],
  ["control: /usr/bin/git feature push", "/usr/bin/git push -u origin feat/x", "feat/x", null],
  // Gh's repo flag in front of the subcommand.
  ["gh -R merge", "gh -R o/r pr merge 1", "feat", "ask"],
  ["gh --repo merge", "gh --repo o/r pr merge 1", "feat", "ask"],
  ["gh --repo= ready --undo", "gh --repo=o/r pr ready 1 --undo", "feat", "deny"],
  ["gh -R run rerun", "gh -R o/r run rerun 5", "feat", "deny"],
  ["gh -Ro/r glued merge", "gh -Ro/r pr merge 1", "feat", "ask"],
  ["control: gh -R pr view", "gh -R o/r pr view 1", "feat", null],
  ["control: gh -R rerun --failed", "gh -R o/r run rerun 5 --failed", "feat", null],
  // Abbreviated long options git accepts.
  ["--no-verif", "git push --no-verif origin feat", "feat", "deny"],
  ["--delet dev", "git push --delet origin dev", "feat", "deny"],
  ["--force-with dev", "git push --force-with origin dev", "feat", "deny"],
  ["--force-if dev", "git push --force-if origin dev", "feat", "deny"],
  ["--forc main", "git push --forc origin main", "feat", "deny"],
  ["--mirr", "git push --mirr", "feat", "ask"],
  ["--mirr --forc", "git push --mirr --forc", "feat", "deny"],
  ["control: --force-with-lease= on a feature branch", "git push --force-with-lease=feat/x:abc origin feat/x", "feat/x", null],
  ["control: --dry on a feature branch", "git push --dry origin feat", "feat", null],
  ["control: --no-force-with-lease is no force", "git push --no-force-with-lease origin dev", "feat", null],
  ["control: --rep takes the next word", "git push --rep origin dev", "feat", null],
  // Git's global options that take a separate value.
  ["--git-dir X push -f dev", "git --git-dir .git push -f origin dev", "feat", "deny"],
  ["--work-tree X push -f main", "git --work-tree . push -f origin main", "feat", "deny"],
  ["--namespace X push -f dev", "git --namespace x push -f origin dev", "feat", "deny"],
  ["--attr-source X push --delete main", "git --attr-source HEAD push --delete origin main", "feat", "deny"],
  ["--git-dir: a bare forced push can't be placed", "git --git-dir ../other/.git push -f", "feat", "ask"],
  ["-c then -C: the push runs in -C's directory", "git -c x.y=1 -C ../app push --force", "feat", "deny"],
  ["control: --git-dir status", "git --git-dir .git status", "feat", null],
  ["control: --work-tree feature push", "git --work-tree . push origin feat", "feat", null],
  // `@` is HEAD; a glob refspec writes every branch it matches.
  ["@ on main", "git push origin @", "main", "ask"],
  ["+@ on dev", "git push origin +@", "dev", "deny"],
  ["@:main", "git push origin @:main", "feat", "ask"],
  ["+refs/heads/*:refs/heads/*", "git push origin '+refs/heads/*:refs/heads/*'", "feat", "deny"],
  ["+*:*", "git push origin '+*:*'", "feat", "deny"],
  ["refs/heads/m*:refs/heads/m*", "git push origin 'refs/heads/m*:refs/heads/m*'", "feat", "ask"],
  [":refs/heads/d* deletes dev", "git push origin ':refs/heads/d*'", "feat", "deny"],
  ["control: @ on a feature branch", "git push origin @", "feat", null],
  ["control: +@ on a feature branch", "git push origin +@", "feat", null],
  ["control: a glob over feature branches", "git push origin '+refs/heads/feat-*:refs/heads/feat-*'", "feat", null],
  // Gh api writes, judged as the gh subcommand for the same act; reads run.
  ["DELETE refs/heads/main", "gh api -X DELETE repos/o/r/git/refs/heads/main", "feat", "deny"],
  ["PATCH dev force=true", "gh api --method PATCH repos/o/r/git/refs/heads/dev -F force=true", "feat", "deny"],
  ["-XPATCH main (glued) moves main", "gh api -XPATCH /repos/o/r/git/refs/heads/main -f sha=abc", "feat", "ask"],
  ["PATCH dev with a body from a file", "gh api -X PATCH repos/o/r/git/refs/heads/dev --input body.json", "feat", "ask"],
  ["control: PATCH dev without force (a plain push to dev)", "gh api -X PATCH repos/o/r/git/refs/heads/dev -f sha=abc", "feat", null],
  ["PATCH dev with a body from a file", "gh api -X PATCH repos/o/r/git/refs/heads/dev --input body.json", "feat", "ask"],
  ["control: PATCH dev without force (a plain push to dev)", "gh api -X PATCH repos/o/r/git/refs/heads/dev -f sha=abc", "feat", null],
  ["--method=DELETE dev", "gh api --method=DELETE repos/o/r/git/refs/heads/dev", "feat", "deny"],
  ["full rerun", "gh api -X POST repos/o/r/actions/runs/5/rerun", "feat", "deny"],
  ["dispatch (implicit POST from -f)", "gh api repos/o/r/actions/workflows/ci.yml/dispatches -f ref=dev", "feat", "ask"],
  ["repository_dispatch (--input)", "gh api repos/o/r/dispatches --input body.json", "feat", "ask"],
  ["merges endpoint", "gh api repos/o/r/merges -f base=main -f head=dev", "feat", "ask"],
  ["PUT pulls/N/merge (kept)", "gh api -X PUT repos/o/r/pulls/12/merge", "feat", "ask"],
  ["DELETE branch protection", "gh api -X DELETE repos/o/r/branches/main/protection", "feat", "deny"],
  ["PUT branch protection", "gh api -X PUT repos/o/r/branches/main/protection --input p.json", "feat", "ask"],
  ["DELETE a ruleset", "gh api -X DELETE repos/o/r/rulesets/42", "feat", "deny"],
  ["rename main", "gh api repos/o/r/branches/main/rename -f new_name=trunk", "feat", "deny"],
  ["DELETE the repository", "gh api -X DELETE repos/o/r", "feat", "deny"],
  ["DELETE a release", "gh api -X DELETE https://api.github.com/repos/o/r/releases/7", "feat", "deny"],
  ["graphql mergePullRequest", "gh api graphql -f query='mutation { mergePullRequest(input: {pullRequestId: \"x\"}) { clientMutationId } }'", "feat", "ask"],
  ["graphql markPullRequestReadyForReview", "gh api graphql -f query='mutation { markPullRequestReadyForReview(input: {pullRequestId: \"x\"}) { clientMutationId } }'", "feat", "ask"],
  ["graphql deleteBranchProtectionRule", "gh api graphql -f query='mutation { deleteBranchProtectionRule(input: {branchProtectionRuleId: \"x\"}) { clientMutationId } }'", "feat", "deny"],
  ["graphql in a heredoc on --input -", "gh api graphql --input - <<'EOF'\n{\"query\": \"mutation { convertPullRequestToDraft(input: {pullRequestId: \\\"x\\\"}) { clientMutationId } }\"}\nEOF", "feat", "deny"],
  ["graphql query from a file", "gh api graphql -F query=@q.graphql", "feat", "ask"],
  ["gh repo delete", "gh repo delete o/r --yes", "feat", "deny"],
  ["gh release delete", "gh release delete v1 --yes", "feat", "deny"],
  ["gh release delete-asset", "gh release delete-asset v1 app.zip", "feat", "deny"],
  ["control: GET pulls/12", "gh api repos/o/r/pulls/12", "feat", null],
  ["control: GET refs/heads/main", "gh api --method GET repos/o/r/git/refs/heads/main", "feat", null],
  ["control: comment on a PR (POST)", "gh api repos/o/r/issues/12/comments -f body='merge and DELETE later'", "feat", null],
  ["control: create a feature ref", "gh api -X POST repos/o/r/git/refs -f ref=refs/heads/feat -f sha=abc", "feat", null],
  ["control: rerun failed jobs", "gh api -X POST repos/o/r/actions/runs/5/rerun-failed-jobs", "feat", null],
  ["control: graphql read", "gh api graphql -f query='query { viewer { login } }'", "feat", null],
  ["control: gh release view", "gh release view v1", "feat", null],
  ["control: PR text naming the mutations", "gh pr create --draft --title 'mergePullRequest notes' --body 'gh api -X DELETE repos/o/r; gh repo delete'", "feat", null],
  // The pre-push hook skipped another way, and aliases that hide what runs.
  ["-c core.hooksPath push", "git -c core.hooksPath=/dev/null push origin feat", "feat", "deny"],
  ["-c core.hookspath (any case) push", "git -c Core.HooksPath=x push origin feat", "feat", "deny"],
  ["--config-env core.hooksPath push", "git --config-env core.hooksPath=HOOKS push origin feat", "feat", "deny"],
  ["git config core.hooksPath", "git config core.hooksPath /tmp/x", "feat", "ask"],
  ["git config --global core.hooksPath", "git config --global core.hooksPath /tmp/x", "feat", "ask"],
  ["git config set core.hooksPath", "git config set core.hooksPath /tmp/x", "feat", "ask"],
  ["git config --unset core.hooksPath", "git config --unset core.hooksPath", "feat", "ask"],
  ["git config team.prepush", "git config team.prepush fast", "feat", "ask"],
  ["git config --global team.prepush", "git config --global team.prepush fast", "feat", "ask"],
  ["git config --global (any case)", "GIT config --global Team.PrePush fast", "feat", "ask"],
  ["git config set team.prepush", "git config set --global team.prepush fast", "feat", "ask"],
  ["git config --unset team.prepush", "git config --unset team.prepush", "feat", "ask"],
  ["git config --add team.prepush", "git config --add team.prepush fast", "feat", "ask"],
  ["-c team.prepush=fast push", "git -c team.prepush=fast push origin feat", "feat", "ask"],
  ["--config-env team.prepush push", "git --config-env team.prepush=FAST push origin feat", "feat", "ask"],
  ["control: git config --get team.prepush", "git config --get team.prepush", "feat", null],
  ["control: git config team.prepush (a read)", "git config team.prepush", "feat", null],
  ["control: git config team.other", "git config team.other fast", "feat", null],
  ["-c alias.X=… X", "git -c alias.p='push -f origin main' p", "feat", "ask"],
  ["git config alias.X 'push …'", "git config alias.p 'push -f origin main'", "feat", "ask"],
  ["control: git config --get core.hooksPath", "git config --get core.hooksPath", "feat", null],
  ["control: git config alias.co (a read)", "git config alias.co", "feat", null],
  ["control: git config user.name", "git config user.name 'Ada'", "feat", null],
  ["control: -c user.name commit", "git -c user.name=x commit -m hi", "feat", null],
  // Shell writes to the guard's own files ask (the hook's entry is tested below).
  ["sed -i the guard", "sed -i 's/deny/null/' scripts/team-guard.mjs", "feat", "ask"],
  ["rm the hook entry", "rm scripts/team-guard-hook.mjs", "feat", "ask"],
  ["chmod the guard", "chmod 000 scripts/team-guard.mjs", "feat", "ask"],
  ["redirect over the Cursor hooks", "echo '{}' > .cursor/hooks.json", "feat", "ask"],
  ["heredoc over settings.json", "cat > .claude/settings.json <<'EOF'\n{}\nEOF", "feat", "ask"],
  ["settings.local.json", "echo '{\"disableAllHooks\": true}' > .claude/settings.local.json", "feat", "ask"],
  ["mv the project rules away", "mv reins.json /tmp/", "feat", "ask"],
  ["rm -rf the folder holding them", "rm -rf .claude", "feat", "ask"],
  ["cd then rm", "cd scripts && rm team-guard.mjs", "feat", "ask"],
  ["an absolute path", "rm /srv/repo/scripts/team-guard.mjs", "feat", "ask"],
  ["git rm", "git rm scripts/team-guard.mjs", "feat", "ask"],
  ["cp over a pack rule file", "cp x.json .reins/infra.json", "feat", "ask"],
  ["sed -i a rule set", "sed -i 's/deny/ask/' .team-rules/team.json", "feat", "ask"],
  ["rm the rule sets folder", "rm -rf .team-rules", "feat", "ask"],
  ["redirect over the pin file", "echo '{}' > scripts/team-guard.pin.json", "feat", "ask"],
  // A guard file named through a variable the line set, a glob or braces, or written from another commit.
  ["a rule set through a variable the line set", "d=.team-rules; echo {} > $d/team.json", "feat", "ask"],
  ["rm -rf the sets folder through a variable", "d=.team-rules; rm -rf $d", "feat", "ask"],
  ["glob ? over a rule set", "echo {} > .team-rule?/team.json", "feat", "ask"],
  ["glob * over a rule set", "cp /tmp/e.json .team-r*/team.json", "feat", "ask"],
  ["glob over the sets folder", "rm -rf .team-rule*", "feat", "ask"],
  ["braces over a rule set", "rm .team-{rules,x}/team.json", "feat", "ask"],
  ["glob over the pin file", "echo '{}' > scripts/team-guard.pin.js?n", "feat", "ask"],
  ["glob over the guard", "rm scripts/team-guard.m*", "feat", "ask"],
  ["glob over a folder holding them", "rm -rf scr*", "feat", "ask"],
  ["glob at an absolute path", "rm /srv/repo/.team-r*/team.json", "feat", "ask"],
  ["git checkout <ref> -- a rule set", "git checkout HEAD~3 -- .team-rules/team.json", "feat", "ask"],
  ["git checkout <ref> -- the sets folder", "git checkout origin/main -- .team-rules", "feat", "ask"],
  ["git checkout <ref> -- the guard", "git checkout HEAD~1 -- scripts/team-guard.mjs", "feat", "ask"],
  ["git -C scripts checkout the pin file", "git -C scripts checkout HEAD -- team-guard.pin.json", "feat", "ask"],
  ["git restore --source a rule set", "git restore --source=HEAD~5 .team-rules/team.json", "feat", "ask"],
  ["control: a glob elsewhere in scripts", "rm -f scripts/lib/*.tmp", "feat", null],
  ["control: *.json outside the repo", "rm /tmp/*.json", "feat", null],
  ["control: braces elsewhere", "rm -rf node_modules/{a,b}", "feat", null],
  ["control: git checkout a new branch", "git checkout -b feat origin/dev", "feat", null],
  ["control: git checkout <ref> -- another file", "git checkout HEAD -- src/x.ts", "feat", null],
  ["control: read the guard", "sed -n 1,20p scripts/team-guard.mjs", "feat", null],
  ["control: run its tests", "node --test scripts/command-guard.test.mjs", "feat", null],
  ["control: git add", "git add scripts/team-guard.mjs .claude/settings.json", "feat", null],
  ["control: rm elsewhere in scripts", "rm -rf scripts/lib/tmp", "feat", null],
  // Data-loss commands the guard didn't know.
  ["neon (neonctl's other name)", "neon branches delete preview-1", "feat", "deny"],
  ["turso db destroy", "turso db destroy app", "feat", "deny"],
  ["pscale database delete", "pscale database delete app --force", "feat", "deny"],
  ["wrangler r2 bucket delete", "wrangler r2 bucket delete uploads", "feat", "deny"],
  ["wrangler d1 delete", "npx wrangler d1 delete app", "feat", "deny"],
  ["wrangler d1 execute --remote DROP", "wrangler d1 execute DB --remote --command 'DROP TABLE users'", "feat", "deny"],
  ["wrangler d1 execute --remote --file unread", "wrangler d1 execute DB --remote --file drop.sql", "feat", "ask"],
  ["docker compose down -v", "docker compose down -v", "feat", "ask"],
  ["docker compose -f x down --volumes", "docker compose -f dev.yml down --volumes", "feat", "ask"],
  ["docker-compose down -v", "docker-compose down -v", "feat", "ask"],
  ["docker volume rm", "docker volume rm pgdata", "feat", "ask"],
  ["docker volume prune", "docker volume prune -f", "feat", "ask"],
  ["docker system prune --volumes", "docker system prune -af --volumes", "feat", "ask"],
  ["redis-cli FLUSHALL remote", "redis-cli -h prod.example.com FLUSHALL", "feat", "deny"],
  ["redis-cli -u URL flushdb", "redis-cli -u redis://:pw@cache.example.com:6379/0 flushdb", "feat", "deny"],
  ["redis-cli $HOST FLUSHALL", "redis-cli -h $REDIS_HOST FLUSHALL", "feat", "ask"],
  ["FLUSHALL piped into redis-cli", "echo FLUSHALL | redis-cli -h prod.example.com", "feat", "deny"],
  ["mongosh URL dropDatabase", "mongosh mongodb://prod.example.com/app --eval 'db.dropDatabase()'", "feat", "deny"],
  ["mongosh --host deleteMany", "mongosh --host rs0/db1.example.com:27017 --eval 'db.users.deleteMany({})'", "feat", "deny"],
  ["mongo host/db drop", "mongo db.example.com/app --eval 'db.users.drop()'", "feat", "deny"],
  ["ALTER COLUMN … TYPE … USING NULL", "psql -h db.example.com -c 'ALTER TABLE users ALTER COLUMN email TYPE text USING NULL'", "feat", "deny"],
  ["UPDATE … SET col = DEFAULT", "psql -h db.example.com -c 'UPDATE users SET email = DEFAULT'", "feat", "deny"],
  ["UPDATE … SET col = ''", "psql -h db.example.com -c \"UPDATE users SET email = ''\"", "feat", "deny"],
  ["UPDATE … SET (a) = (SELECT NULL)", "psql -h db.example.com -c 'UPDATE users SET (email) = (SELECT NULL)'", "feat", "deny"],
  ["control: neon branches list", "neon branches list", "feat", null],
  ["control: wrangler d1 execute local DROP", "wrangler d1 execute DB --command 'DROP TABLE users'", "feat", null],
  ["control: wrangler d1 execute --remote SELECT", "wrangler d1 execute DB --remote --command 'SELECT 1'", "feat", null],
  ["control: docker compose down", "docker compose down", "feat", null],
  ["control: docker volume ls", "docker volume ls", "feat", null],
  ["control: docker run -v", "docker run -v pgdata:/var/lib/postgresql/data postgres", "feat", null],
  ["control: redis-cli FLUSHALL on loopback", "redis-cli FLUSHALL", "feat", null],
  ["control: redis-cli -h localhost flushdb", "redis-cli -h localhost flushdb", "feat", null],
  ["control: mongosh local dropDatabase", "mongosh mongodb://localhost/app --eval 'db.dropDatabase()'", "feat", null],
  ["control: mongosh remote read", "mongosh mongodb://prod.example.com/app --eval 'db.users.find()'", "feat", null],
  ["control: a USING cast keeps the data", "psql -h db.example.com -c 'ALTER TABLE t ALTER COLUMN n TYPE int USING n::int'", "feat", null],
  ["control: '' in WHERE, not SET", "psql -h db.example.com -c \"UPDATE users SET verified = true WHERE email = ''\"", "feat", null],
  // Every loopback address is loopback to the floor too.
  ["psql -h ::1 TRUNCATE", "psql -h ::1 -c 'TRUNCATE users'", "feat", null],
  ["psql -h 127.0.0.2 TRUNCATE", "psql -h 127.0.0.2 -c 'TRUNCATE users'", "feat", null],
  ["psql [::1] URL DROP", "psql 'postgres://u@[::1]:5432/app' -c 'DROP TABLE users'", "feat", null],
  ["control: ::1 in a remote host's name is still remote", "psql -h db::1x -c 'TRUNCATE users'", "feat", "deny"],
  ["control: a remote host still refuses", "psql -h 10.0.0.1 -c 'TRUNCATE users'", "feat", "deny"],
];

describe("guard: paths, gh flags, abbreviations, refspecs, the API, data stores", () => {
  for (const [label, command, branch, expected] of pathsAndApi) {
    it(`${label} → ${String(expected)}`, () => {
      assert.equal(evaluate(command, { branch, branchIn: (dir) => DIRS[dir] ?? "" })?.decision ?? null, expected, command);
    });
  }
});

// The decision for a command on a branch, as the cases table reads it.
const judge = (command, branch) => evaluate(command, { branch, branchIn: (dir) => DIRS[dir] ?? "" })?.decision ?? null;

const upperFirst = (command) => command.replace(/^\w+/, (word) => (word[0] ?? "").toUpperCase() + word.slice(1));
const shout = (command) => command.replace(/^\w+/, (word) => word.toUpperCase());

// A file system that folds case (macOS's default) runs `GIT` as git, so a program word's case must not change a verdict.
describe("guard: a program word's case does not change the verdict", () => {
  const PROGRAMS = /^(git|gh|psql|mysql|terraform|tofu|aws|gcloud|az|dropdb|pg_dump|redis-cli|mongosh|sqlite3|sh|bash|zsh|sudo|env|xargs|docker|kubectl|prisma|npx|pnpm|npm|yarn|node)\b/;
  const rows = [
    ...cases.map(([command, branch]) => [command, branch]),
    ...pathsAndApi.map(([, command, branch]) => [command, branch]),
    ...[...infraRefused, ...infraAllowed].map(([command]) => [command, "feat"]),
    ...everyday.map((command) => [command, "feat"]),
  ].filter(([command]) => typeof command === "string" && PROGRAMS.test(command));

  it("covers a broad table", () => {
    assert.ok(rows.length > 200, String(rows.length));
  });
  for (const [label, change] of /** @type {[string, (command: string) => string][]} */ ([["Capitalized", upperFirst], ["UPPER", shout]])) {
    it(`${label} program word has the lower-case verdict, on every row`, () => {
      const differ = rows.filter(([command, branch]) => judge(change(command), branch) !== judge(command, branch)).map(([command, branch]) => `${command} [${branch}]: ${String(judge(command, branch))} → ${String(judge(change(command), branch))}`);
      assert.deepEqual(differ, []);
    });
  }

  it("denies and asks the cases that matter", () => {
    for (const [command, expected] of [["GIT push --force origin main", "deny"], ["Git push -f origin dev", "deny"], ["GH pr merge 109 --admin", "ask"], ["Psql -h db.example.com -c 'DROP TABLE users'", "deny"], ["TERRAFORM destroy", "deny"]]) {
      assert.equal(judge(command, "feat"), expected, command);
    }
  });

  it("asks for a program word with a non-ASCII character, and only then", () => {
    for (const command of ["pſql -c 'DROP TABLE users'", "ſh -c 'git push -f origin main'", "sudo gıt push -f origin main", "/opt/gİt push origin main"]) assert.equal(judge(command, "feat"), "ask", command);
    // A non-ASCII argument or directory is no program name.
    for (const command of ["echo pſql", "git commit -m 'café'", "/opt/José/bin/mytool --help"]) assert.equal(judge(command, "feat"), null, command);
  });
});

// The autopilot switch, the approvals log, and the pre-push opt-out are read on the command's decoded, case-folded
// words too, so a Mac's case-folding file system, a quote split, or an escape can't write them past the text rules.
describe("guard: guard files and opt-outs named in another case, quoted, or escaped", () => {
  const MARKER = [
    "echo 2026-10-26T00:00:00Z > .git/Team-Autopilot",
    "echo 2026-10-26T00:00:00Z > .git/team-autop''ilot",
    "echo 2026-10-26T00:00:00Z > .git/team-autop\\ilot",
    "cat $'team\\x2dautopilot'",
    "echo x >> .git/Team-Approvals.log",
    "echo x >> .git/team-appr''ovals.log",
    "pnpm Autopilot on 8",
    "pnpm autop''ilot on 8",
    "node scripts/AUTOPILOT.mjs on 8",
    "pnpm Approve 12 merge",
    "node --run=autopilot -- on 1",
    "node --run=approve -- 12",
  ];
  const SKIP = [
    "TEAM_SKIP_CHECKS=1 GIT push origin feat",
    "TEAM_SKIP_CHECKS=1 Git push origin feat",
    "TEAM_SKIP_CHECKS=1 /usr/bin/GIT push origin feat",
    "TEAM_SKIP_CHECKS=1 g''it push origin feat",
    "export TEAM_SKIP_CHECKS=1; GIT push origin feat",
    "env TEAM_SKIP_CHECKS=1 GIT push origin feat",
    "TEAM_SKIP_CHECKS=1 GIT -C . push origin feat",
    "TEAM_SKIP_CHECKS=1 git push origin feat",
  ];
  for (const command of [...MARKER, ...SKIP]) {
    it(`${command} → deny`, () => {
      assert.equal(verdictOf(command), "deny");
    });
  }
  it("still allows the neighbours", () => {
    for (const command of ["pnpm autopilot status", "pnpm Autopilot off", "cat .git/config", "echo autopilot", "TEAM_SKIP_CHECKS=1 git status", "TEAM_SKIP_CHECKS=1 GIT status"]) assert.equal(verdictOf(command), null, command);
    // Without the opt-out a push is judged as before, whatever its case.
    assert.equal(verdictOf("GIT push origin feat"), verdictOf("git push origin feat"));
  });
  it("denies through the bare hook entry too", () => {
    const root = guardIn({});
    for (const command of [MARKER[0], MARKER[1], MARKER[3], MARKER[4], SKIP[0], SKIP[3]]) {
      const answer = JSON.parse(run(root, "claude", command));
      assert.equal(answer.hookSpecificOutput.permissionDecision, "deny", command);
    }
  });
  it("asks about a write to the guard's own files, or a batch-merge, named in another case", () => {
    for (const command of ["echo x > SCRIPTS/team-guard.mjs", "rm .Claude/Settings.json", "sed -i s/a/b/ .CLAUDE/settings.local.json", "rm -rf .Claude", "mv Scripts/Team-Guard.mjs /tmp/x", "node scripts/Batch-Merge.mjs 12"]) {
      assert.notEqual(verdictOf(command), null, command);
    }
  });
});

const verdictOf = (command) => evaluate(command, { branch: "feat" })?.decision ?? null;

// The guard reads no `lock run` wrapper (scripts/lock.mjs judges the argv it spawns, scripts/lock.test.mjs), so a line
// reads as it does without the wrapper: what the words before `lock run` run is judged, and `lock run … -- <cmd>` is
// an ordinary program with arguments. These shapes hid a guarded command behind a fake or real lock run.
describe("guard: a lock run is no wrapper, so nothing hides behind one", () => {
  const SCRIPTS = { x: "git push -f origin main", lock: "git push -f origin main" };
  const withScripts = (command) => evaluate(command, { branch: "feat", scriptIn: (_dir, name) => SCRIPTS[name] ?? "" })?.decision ?? null;
  it("a package script named before `lock run` is read, and so is a project whose `lock` script is the guarded command", () => {
    for (const command of ["pnpm x lock run y -- true", "pnpm lock run y -- true", "pnpm run x lock run y -- true", "pnpm run lock run y -- true"]) assert.equal(withScripts(command), "deny", command);
    // The same lines in a project whose scripts are harmless.
    for (const command of ["pnpm x lock run y -- true", "pnpm lock run y -- true", "pnpm run x lock run y -- true"]) assert.equal(evaluate(command, { branch: "feat", scriptIn: () => "echo hi" }), null, command);
  });
  const guarded = ["git push -f origin main", 'psql postgresql://u@db.example.com/app -c "DROP TABLE users"', "gh pr ready 12", "gh pr merge 12"];
  for (const inner of guarded) {
    for (const [lead, shell] of [["pnpm -s", "sh"], ["yarn -s", "bash"], ["pnpm --silent", "sh"]]) {
      const command = `${lead} ${shell} -c '${inner}' lock run x -- true`;
      it(command, () => {
        const alone = verdictOf(inner);
        assert.notEqual(alone, null, "the table row stands for a guarded command");
        assert.equal(verdictOf(command), alone);
      });
    }
  }
  it("node --no-warnings scripts/batch-merge.mjs lock run x -- true", () => {
    assert.equal(verdictOf("node --no-warnings scripts/batch-merge.mjs lock run x -- true"), "ask");
    assert.equal(verdictOf("node --no-warnings scripts/batch-merge.mjs --ship lock run x -- true"), "ask");
  });
  it("reads `pnpm lock run x -- <cmd>` as the dev guard did: the wrapper's own words, not <cmd>", () => {
    for (const command of ["pnpm lock run x -- git push origin main", "npx lock run x -- gh pr merge 12", "node scripts/lock.mjs run x -- gh pr ready 12"]) assert.equal(verdictOf(command), null, command);
  });
});

// A temp git repo with one commit, on `branch`.
const committedRepoOn = (branch) => {
  const dir = mkdtempSync(join(tmpdir(), "branch-"));
  execFileSync("git", ["init", "-q", "-b", branch, dir]);
  execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "x"]);
  return dir;
};

describe("guard: a push gets the branch looked up however its program word is spelled", () => {
  // hookVerdict() reads the branch when a rule first needs it, once a push is parsed from the line, so no spelling of `git` can skip it.
  const main = committedRepoOn("main");
  for (const [capital, lower] of [["GIT push origin HEAD", "git push origin HEAD"], ["GIT push -f origin HEAD", "git push -f origin HEAD"], ["Git push --force origin HEAD", "git push --force origin HEAD"], ["/usr/bin/GIT push origin HEAD", "/usr/bin/git push origin HEAD"], ["g''it push origin HEAD", "git push origin HEAD"], ["$'g\\x69t' push origin HEAD", "git push origin HEAD"], ["true; g''it push origin HEAD", "git push origin HEAD"], [`sh -c "g''it push origin HEAD"`, "git push origin HEAD"], ["g\\it push -f origin HEAD", "git push -f origin HEAD"]]) {
    it(`${capital} on main is judged as ${lower}`, () => {
      const alone = hookVerdict(lower, main)?.decision ?? null;
      assert.notEqual(alone, null, "the lower-case spelling is refused or asked about on main");
      assert.equal(hookVerdict(capital, main)?.decision ?? null, alone);
    });
  }
});

// The package and its bin entry (bin/reins.mjs) in a temp root, the guard's text replaced by `guard` when given.
const hookIn = (guard) => {
  const root = guardIn({ "reins.json": { sets: ["draft-flow", "merge-conveyor", "ci-minutes", "chute-boss"] } });
  if (guard !== undefined) writeFileSync(join(root, "pkg", "src", "guard.mjs"), guard);
  return root;
};

// Runs the hook entry as a host would; { status, stdout, stderr }, whatever the exit code.
const runHook = (root, host, input, extraEnv = {}) => {
  const env = { ...process.env };
  delete env.REINS;
  delete env.WHIPPLETREE_GUARD;
  const result = spawnSync(process.execPath, [join(root, "pkg", "bin", "reins.mjs"), "hook", host], { input: JSON.stringify(input), env: { ...env, CLAUDE_PROJECT_DIR: root, ...extraEnv }, encoding: "utf8" });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
};

// A throwaway git repo on `branch`, so the hook's own branch lookup runs.
const repoOn = (branch) => {
  const root = mkdtempSync(join(tmpdir(), "command-guard-git-"));
  roots.push(root);
  const git = (...args) => execFileSync("git", ["-c", "user.email=a@b", "-c", "user.name=a", ...args], { cwd: root, stdio: "pipe" });
  git("init", "-q", "-b", branch, ".");
  git("commit", "-q", "--allow-empty", "-m", "init");
  return root;
};

// Through the real hook entry, not evaluate(): the hook looks the branch up itself, and only when the
// line names git, so a program name it matches case-sensitively would skip the lookup.
describe("guard: the hook reads program names case-insensitively", () => {
  const hookRoot = hookIn();
  const decisionOf = (command, cwd) => {
    const output = runHook(hookRoot, "claude", { tool_input: { command }, cwd });
    if (output.status !== 0) return `exit${String(output.status)}`;
    return output.stdout === "" ? null : JSON.parse(output.stdout).hookSpecificOutput.permissionDecision;
  };
  const prod = "postgres://u@db.example.com/prod";
  const rows = [
    { lower: "git push origin HEAD", branch: "main", mixed: ["GIT push origin HEAD", "Git push origin HEAD", "/usr/bin/GIT push origin HEAD", "gIt push origin HEAD"] },
    { lower: "git push --no-verify origin feat", branch: "feat", mixed: ["GIT push --no-verify origin feat", "/usr/bin/GIT push --no-verify origin feat"] },
    { lower: "git push -f origin main", branch: "feat", mixed: ["GIT push -f origin main"] },
    { lower: `psql -c "drop table x" ${prod}`, branch: "feat", mixed: [`ENV PSQL -c "drop table x" ${prod}`, `SUDO PSQL -c "drop table x" ${prod}`, `TIME PSQL -c "drop table x" ${prod}`, `PSQL -c "drop table x" ${prod}`] },
    { lower: `pgcli -c "drop table x" ${prod}`, branch: "feat", mixed: [`PGCLI -c "drop table x" ${prod}`] },
    { lower: `mysql -e "drop table x" -h db.example.com`, branch: "feat", mixed: [`MYSQL -e "drop table x" -h db.example.com`] },
    { lower: `mariadb -e "drop table x" -h db.example.com`, branch: "feat", mixed: [`MariaDB -e "drop table x" -h db.example.com`] },
    { lower: `sqlcmd -S db.example.com -Q "drop table x"`, branch: "feat", mixed: [`SQLCMD -S db.example.com -Q "drop table x"`] },
  ];
  for (const { lower, branch, mixed } of rows) {
    for (const command of mixed) {
      it(`${command} (on ${branch}) → same verdict as ${lower}`, () => {
        const cwd = repoOn(branch);
        const expected = decisionOf(lower, cwd);
        assert.notEqual(expected, null, `${lower} must be refused or asked`);
        assert.equal(decisionOf(command, cwd), expected);
      });
    }
  }
});

describe("guard: the hook entry fails closed", () => {
  it("passes the guard's answers through unchanged", () => {
    const root = hookIn();
    const asked = runHook(root, "claude", { tool_input: { command: "gh pr ready 1" }, cwd: tmpdir() });
    assert.equal(asked.status, 0);
    assert.equal(JSON.parse(asked.stdout).hookSpecificOutput.permissionDecision, "ask");
    const allowed = runHook(root, "claude", { tool_input: { command: "ls" }, cwd: tmpdir() });
    assert.deepEqual([allowed.status, allowed.stdout], [0, ""]);
    assert.equal(JSON.parse(runHook(root, "cursor", { command: "ls", cwd: tmpdir() }).stdout).permission, "allow");
  });

  it("blocks (exit 2) when the guard doesn't parse, for both hosts", () => {
    const root = hookIn("export const main = () => {\n");
    const claude = runHook(root, "claude", { tool_input: { command: "ls" } });
    assert.equal(claude.status, 2);
    assert.match(claude.stderr, /didn't load/);
    const cursor = runHook(root, "cursor", { command: "ls" });
    assert.equal(cursor.status, 2);
    assert.equal(JSON.parse(cursor.stdout).permission, "deny");
  });

  it("blocks when the guard is missing", () => {
    const root = hookIn();
    rmSync(join(root, "pkg", "src", "guard.mjs"));
    assert.equal(runHook(root, "claude", { tool_input: { command: "ls" } }).status, 2);
  });

  it("blocks when the guard exits any other way than an answer (exit 1, a throw after loading)", () => {
    assert.equal(runHook(hookIn("export const main = () => process.exit(1);\n"), "claude", {}).status, 2);
    const thrown = runHook(hookIn("export const main = () => setTimeout(() => { throw new Error('late'); }, 1);\n"), "claude", {});
    assert.equal(thrown.status, 2);
    assert.match(thrown.stderr, /exited with code 1/);
  });

  it("the human's off switch still lets a broken guard through, by either name", () => {
    for (const name of ["REINS", "WHIPPLETREE_GUARD"]) {
      const off = runHook(hookIn("syntax error ("), "claude", { tool_input: { command: "ls" } }, { [name]: "off" });
      assert.deepEqual([off.status, off.stdout], [0, ""], name);
    }
  });

  it("asks when the input has no command where the host puts one", () => {
    const root = hookIn();
    for (const input of [{ tool_input: { cmd: "git push -f origin main" } }, { tool_input: { command: ["git", "push"] } }, {}]) {
      const output = runHook(root, "claude", input);
      assert.equal(JSON.parse(output.stdout).hookSpecificOutput.permissionDecision, "ask", JSON.stringify(input));
    }
  });

  it("the shell form of the hook line blocks when the entry is missing, and the off switch sits in front of node", () => {
    // The line a project's hook config runs: a missing entry or node exits other than 0, and `|| exit 2` blocks.
    const line = (bin) => `[ "$REINS" = off ] || node "${bin}" hook claude || exit 2`;
    const missing = join(hookIn(), "pkg", "bin", "no-such-entry.mjs");
    const env = { ...process.env, REINS: "" };
    assert.equal(spawnSync("sh", ["-c", line(missing)], { env, input: "{}" }).status, 2);
    assert.equal(spawnSync("sh", ["-c", line(missing)], { env: { ...env, REINS: "off" }, input: "{}" }).status, 0);
    const present = join(hookIn(), "pkg", "bin", "reins.mjs");
    assert.equal(spawnSync("sh", ["-c", line(present)], { env, input: JSON.stringify({ tool_input: { command: "ls" } }) }).status, 0);
  });
});

// git exits 128 where it cannot read a branch (a folder that is no repository): a push that names no branch, or HEAD, lands somewhere the guard cannot tell.
describe("guard: a push whose branch cannot be read asks", () => {
  const nowhere = mkdtempSync(join(tmpdir(), "no-repo-"));
  for (const command of ["git push", "git push origin HEAD", "git push origin", "GIT push origin HEAD", "git push -f origin HEAD", "g''it push"]) {
    it(command, () => {
      assert.equal(hookVerdict(command, nowhere)?.decision ?? null, "ask");
    });
  }
  it("a push that names its branch is judged by the name, as before", () => {
    assert.equal(hookVerdict("git push origin feat", nowhere)?.decision ?? null, null);
    assert.equal(hookVerdict("git push origin main", nowhere)?.decision ?? null, "ask");
    assert.equal(hookVerdict("git push -f origin main", nowhere)?.decision ?? null, "deny");
  });
});

// pnpm's `-c` / `--shell-mode` and npm's `-c` / `--call` hand what follows to a shell as a command string, before or after `exec`.
describe("guard: a package runner's command-string options", () => {
  const push = "'git push -f origin main'";
  for (const lead of ["pnpm exec -c", "pnpm exec --shell-mode", "pnpm -c exec", "pnpm --shell-mode exec", "pnpm -c exec --", "pnpm dlx -c", "pnpm -c", "npm exec -c", "npm exec --call", "npm x --call", "yarn exec -c"]) {
    it(`${lead} ${push} → deny`, () => {
      assert.equal(verdictOf(`${lead} ${push}`), "deny");
    });
  }
  for (const lead of ["npm exec --call=", "npm x --call="]) {
    it(`${lead}${push} → deny`, () => {
      assert.equal(verdictOf(`${lead}${push}`), "deny");
    });
  }
  it("a harmless string stays allowed", () => {
    for (const command of ["pnpm exec -c 'echo hi'", "pnpm -c exec 'echo hi'", "npm exec --call='echo hi'", "npm exec --call 'git push origin feat'"]) assert.equal(verdictOf(command), null, command);
  });
});

// Words the shell fills in where the git and gh rules read by name: braces are expanded and read; a
// variable this line set is filled in; anything else the guard can't read asks where it would decide
// a forced or deleting push, git's or gh's subcommand, or the program.
describe("guard: shell-filled git and gh words", () => {
  const rows = [
    ["git push -f origin ma{in,x}", "deny"],
    ["git push -f origin {feat,main}", "deny"],
    ["{git,push} -f origin main", "deny"],
    ["git push origin {a,b}", null],
    ["G=git; $G push -f origin main", "deny"],
    ["B=main; git push -f origin $B", "deny"],
    ["B=feat; git push -f origin $B", null],
    ["git $(echo push) -f origin main", "ask"],
    ["$(which git) push origin feat", "ask"],
    ["$G push origin feat", "ask"],
    ["git push -f origin $(echo main)", "ask"],
    ["git push -f origin ${B:-main}", "ask"],
    ["git push -f origin $B", "ask"],
    ["git push -f origin +$B", "ask"],
    ["git push origin :$B", "ask"],
    ["git push -f origin feat:$B", "ask"],
    ["gh $X merge 1", "ask"],
    ["gh pr $(echo merge) 1", "ask"],
    // A plain push's unread ref asks too, as `git push origin main` does (test/standalone.test.mjs).
    ["git push origin $B", "ask"],
    // Controls: a read ref and gh words past the subcommand stay as they were.
    ["git push -f origin $B:feat", null],
    ["git push -f $R", null],
    ['git push -f origin "$(git branch --show-current)"', null],
    ["git push --force-with-lease -u origin $(git rev-parse --abbrev-ref HEAD)", null],
    ["gh pr view $N", null],
    ["gh api repos/$O/r/pulls", null],
    ["$EDITOR notes.txt", null],
  ];
  for (const [command, expected] of rows) it(`${command} → ${String(expected)}`, () => assert.equal(verdictOf(command), expected));
  it("a current-branch substitution reads as the branch the push runs on", () => {
    assert.equal(evaluate('git push -f origin "$(git branch --show-current)"', { branch: "main" })?.decision, "deny");
  });
});

describe("guard: git config from the environment, gh aliases, and plumbing pushes", () => {
  const rows = [
    ["GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.p GIT_CONFIG_VALUE_0=push git p -f origin main", "ask"],
    ["env GIT_CONFIG_PARAMETERS=x git p", "ask"],
    ["export GIT_CONFIG_COUNT=1; git status", "ask"],
    ["gh alias set m 'pr merge'", "ask"],
    ["gh -R o/r alias import aliases.yml", "ask"],
    ["GIT_CONFIG_COUNT=1 ls", null],
    ["gh alias list", null],
    // git's plumbing pushes skip the pre-push hook.
    ["git send-pack origin +x:main", "ask"],
    ["git -C repo http-push https://example.com/r.git main", "ask"],
  ];
  for (const [command, expected] of rows) it(`${command} → ${String(expected)}`, () => assert.equal(verdictOf(command), expected));
});

// A shell running what another command prints reads it as `echo … | sh` is read.
describe("guard: shells fed by cat, <(…), and find -exec", () => {
  const rows = [
    ["cat <<EOF | sh\ngit push -f origin main\nEOF", "deny"],
    ["cat <<<'git push -f origin main' | bash", "deny"],
    ["bash <(echo git push -f origin main)", "deny"],
    ["source <(echo git push -f origin main)", "deny"],
    [". <(printf 'gh pr merge 1')", "ask"],
    ["bash < <(echo git push -f origin main)", "deny"],
    // find -exec is read in outline, so what it runs asks.
    ["find . -exec git push -f origin main \;", "ask"],
    ["find . -execdir gh pr merge 1 \;", "ask"],
    ["find . -name x -exec sh -c 'git push -f origin main' \;", "ask"],
    ["cat <<EOF | sh\necho hi\nEOF", null],
    ["bash <(echo ls)", null],
    ["find . -name '*.md' -exec grep -l main {} +", null],
  ];
  for (const [command, expected] of rows) it(`${JSON.stringify(command)} → ${String(expected)}`, () => assert.equal(verdictOf(command), expected));
});

describe("guard: more writers of the guard's own files", () => {
  const rows = [
    ["find .claude -delete", "ask"],
    ["find . -delete", "ask"],
    ["find . -name reins.json -delete", "ask"],
    ["find . -path './.claude/*' -delete", "ask"],
    ["find node_modules -name '*.mjs' -delete", "ask"],
    ["ex -sc '%d|x' .claude/settings.json", "ask"],
    ["ed reins.json", "ask"],
    ["vim -es -c x .cursor/hooks.json", "ask"],
    ["find . -name '*.log' -delete", null],
    ["find dist -type f -delete", null],
    ["find .claude -name x", null],
    ["ex -sc x notes.txt", null],
  ];
  for (const [command, expected] of rows) it(`${command} → ${String(expected)}`, () => assert.equal(verdictOf(command), expected));
});

// The Phase 3 delta review: empty and oversized brace expansions, brace sequences, a shell string
// built from a substitution or a variable, unread push refs, git config from files, find -exec writers,
// and unread git flags in front of a read-only subcommand.
describe("guard: brace expansions as the shell makes them", () => {
  const rows = [
    // Bash drops the empty word an unquoted brace makes.
    ["{git,} push -f origin main", "deny"],
    ["git push -f origin {main,}", "deny"],
    // Past 64 words braceWords() gives up, which reads as a match.
    ["git push -f origin ma{in,x}{,}{,}{,}{,}{,}{,}", "ask"],
    // Sequences: letters (with a step) and numbers; one bash leaves as typed stays text.
    ["git push -f origin m{a..b}in", "deny"],
    ["git push -f origin m{a..z..2}in", "deny"],
    ["rm -rf .clau{c..e}e", "ask"],
    ["git push -f origin {main..main}", null],
    ["git add src/{a,b}.ts", null],
    ["mkdir -p out/{1..3}", null],
    // Too many words asks only where the rules read them: git, gh, a braced program.
    ["gh pr view {1..100}", "ask"],
    ["{git,x}{,}{,}{,}{,}{,}{,} push -f origin main", "ask"],
    ["touch f{1..100}.txt", null],
    ["mkdir -p a{1..9}/b{1..9}", null],
  ];
  for (const [command, expected] of rows) it(`${command} → ${String(expected)}`, () => assert.equal(verdictOf(command), expected));
});

describe("guard: a shell string this shell builds", () => {
  const rows = [
    ['bash -c "$(echo git push -f origin main)"', "deny"],
    ['sh -c "`printf \'gh pr merge 1\'`"', "ask"],
    ["X='git push -f origin main'; bash -c \"$X\"", "deny"],
    ['eval "$(echo git push -f origin main)"', "deny"],
    ['sh -c "$(echo git push -f origin main) && ls"', "deny"],
    ['bash -c "$(echo $(echo git push -f origin main))"', "deny"],
    ['bash -c "$(printf \'%s \' git push -f origin main)"', "deny"],
    ['bash -c "git push -f origin $(echo main)"', "ask"],
    // An unread part that is the whole string or a command asks.
    ['bash -c "$(cat run.sh)"', "ask"],
    ['bash -c "$CMD"', "ask"],
    ['bash -c "ls; $CMD"', "ask"],
    // Elsewhere the line is read with its variables unseen (was ask in fix2).
    ['sh -c "cd $D && make"', null],
    ['bash -c "echo $HOME"', null],
    ['bash -c "npm test -- $ARGS"', null],
    // Controls: the inner shell's own expansions, and eval's everyday setup.
    ["bash -c 'echo $HOME'", null],
    ['bash -c "$(echo ls)"', null],
    ['eval "$(ssh-agent -s)"', null],
    // A substitution as the command runs what it prints.
    ["$(echo git push -f origin main)", "deny"],
    ["$(echo $(echo git push -f origin main))", "deny"],
    ["`echo git push -f origin main`", "deny"],
    ["$(echo git push) -f origin main", "deny"],
    ["$(cat f)", "ask"],
    ["echo $(date)", null],
    // printf's format is applied; one the guard doesn't model asks.
    ["printf '%s ' git push -f origin main | sh", "deny"],
    ["printf 'git push -f origin m%sin' a | sh", "deny"],
    ["printf '%x' 1 | sh", "ask"],
    ["echo -e 'git push -f origin m\\x61in' | sh", "deny"],
    ["printf 'hi\\n' | sh", null],
  ];
  for (const [command, expected] of rows) it(`${command} → ${String(expected)}`, () => assert.equal(verdictOf(command), expected));
});

describe("guard: unread git words, git config from files, and find -exec writers", () => {
  const rows = [
    // An unread push ref asks wherever a protected branch there would ask.
    ['git push origin HEAD:"$(echo main)"', "ask"],
    ['git push origin "HEAD:$B"', "ask"],
    // An unread word where git's subcommand goes asks, even in front of a read-only one: it can be
    // the subcommand itself (fix2 let these through; `${X:-push -f origin main}` force-pushed).
    ["git $GIT_FLAGS status", "ask"],
    ["git $GIT_FLAGS log --oneline", "ask"],
    ["git $A $B diff", "ask"],
    ["git ${X:-push -f origin main} status", "ask"],
    ["read X <<< 'push -f origin main'; git $X status", "ask"],
    ["X=$(echo push -f origin main); git $X status", "ask"],
    ['git "$X" "$Y" status', "ask"],
    ["git $GIT_FLAGS push -f origin main", "ask"],
    ["git $GIT_FLAGS", "ask"],
    // A config file read in place of the user's, or included.
    ["GIT_CONFIG_GLOBAL=/tmp/g git p origin main", "ask"],
    ["export GIT_CONFIG_SYSTEM=/tmp/g; git status", "ask"],
    ["git -c include.path=/tmp/g p origin main", "ask"],
    ["git -c includeIf.onbranch:main.path=/tmp/g status", "ask"],
    ["git config --global include.path /tmp/g", "ask"],
    ["GIT_CONFIG_NOSYSTEM=1 git status", null],
    ["git -c user.name=x commit -m x", null],
    // find -exec running a writer on what could be a guard file, by a starting point or a glob.
    ["find . -name 'settings*.json' -exec sed -i s/a/b/ {} +", "ask"],
    ["find . -name 'settings*.json' -delete", "ask"],
    ["find . -path '*/.claude/*' -exec rm {} \\;", "ask"],
    ["find . -path '*/.claude/*' -delete", "ask"],
    ["find . -wholename '*settings.json' -exec rm {} \\;", "ask"],
    ["find . -iname 'REINS*' -exec rm {} \\;", "ask"],
    [`find . -path './node_modules/.pnpm/${core.PACKAGE_NAME.slice(0, 2)}*' -exec rm -rf {} +`, "ask"],
    ["find src -name 'settings*.json' -delete", null],
    ["find . -path './src/*' -exec rm {} \\;", null],
    ["find node_modules -name x -exec rm -rf {} +", "ask"],
    ["find node_modules -execdir sudo rm {} \;", "ask"],
    ["find . -name reins.json -exec cp /tmp/x {} \;", "ask"],
    ["find . -name '*.orig' -exec rm {} \;", null],
    ["find /tmp/elsewhere -name x -exec rm {} \;", null],
    ["find . -name x -exec grep y {} \;", null],
  ];
  for (const [command, expected] of rows) it(`${command} → ${String(expected)}`, () => assert.equal(verdictOf(command), expected));
});
