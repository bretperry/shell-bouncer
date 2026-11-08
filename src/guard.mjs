// Refuses or escalates agent shell commands that only a human should run: the guard's core.
// In the app: nothing at runtime; a coding agent's pre-command hook (Claude Code PreToolUse on Bash, Cursor beforeShellExecution) runs it before every agent command, through bin/reins.mjs.
// Used by: bin/reins.mjs (`reins hook`, `reins explain`, `reins sets`), and any caller that imports the package; tested by test/*.test.mjs.
// Uses: git (the branch where each commit or push runs); .env, package.json, Prisma config, and SQL files a database command reads; the rule sets named (sets/*.json, each must load); the project's reins.json, its rule folder, and its branch file when present (`files`).
// Run: `reins hook claude` or `reins hook cursor`, from the agent's hook; a hook payload on stdin.
// When: before every agent shell command runs; not for a person's own shell, and not a substitute for the rules it enforces.
// Env: REINS or WHIPPLETREE_GUARD (`off`: no verdict, so the command runs as it would with no guard; `offEnv` replaces the names); CLAUDE_PROJECT_DIR or CURSOR_PROJECT_DIR (the project root, when the caller names none); a database URL variable a command names, read from this process's environment, then the repo's .env.
// Writes: nothing (read-only): `git rev-parse --abbrev-ref HEAD` (and `--git-common-dir` for a push) in the command's directory, and the rule and config files named in Uses, plus a freeze marker a set names; the verdict JSON on stdout.
// Exit: 0 always; the verdict is JSON on stdout (deny, ask, or none, which Claude reads as no opinion); a crash or the 3 s watchdog answers ask.
//
// Written rules say what an agent never does; this makes the worst of them a refusal instead of a
// memory test. "deny" is for acts no session may take (flipping a ready PR back to draft,
// force-pushing or deleting a protected branch, deleting data). "ask" is for acts that are fine with the user's OK in the
// moment (marking a PR ready, merging, shipping main, a manual workflow run): the user sees the prompt and decides.
// Fails closed to ask (crash, size or time budget, watchdog); details at main(). Off switch: REINS=off.
//
// The full list, so no agent reads the body to learn it (project and pack rule files add their own).
// The rules that belong to one team's workflow (its branches and switches, a merge conveyor, a draft
// flow, CI minutes, a lock) are data in the bundled rule sets in sets/ (BUNDLED_SETS), read by the
// knobs in loadSets(); this file holds the general rules and the evaluators.
// - deny, git: `--no-verify`, `-c core.hooksPath=… push`, or a set's variable that skips the pre-push checks on a push;
//   force-pushing, deleting, or renaming a protected branch (main and master, or a set's or the config's protectedBranches);
//   any push to a workflow-only branch (a set's); `[skip ci]` on a commit off the branches a set allows; any push to a branch
//   while its freeze marker (a set's) is set.
// - deny, GitHub: a ready PR back to draft; a full `gh run rerun` (only `--failed`/`--job`);
//   deleting branch protection or a ruleset; `gh repo|release delete`, and the same through `gh api`.
// - deny, a set's own switches: a state file only the user writes, and a command only the user runs (a write to a pattern that could name the marker asks).
// - ask, a set's repository variables: setting one to anything but its free values, or deleting it, the same through `gh api` or curl.
// - deny, a set's runner policy: setting or deleting a variable it names, the same through `gh api` or curl.
// - deny, a set's commit statuses: a raw post of a context it names (an unreadable context asks). Variables the same line set are filled in first.
// - deny, other agents' processes: `pkill -f`, or `pkill`/`killall` of node or a browser.
// - deny, data: destructive SQL (DROP, TRUNCATE, DELETE, MERGE … DELETE, …) or a store's own delete
//   (Redis FLUSHALL/FLUSHDB, a mongo drop) against a non-loopback database; a migration reset,
//   drop, rollback, or dev migrate against one; `dropdb`; Neon, Turso, PlanetScale, Cloudflare
//   D1/R2/KV deletes; cloud CLI deletes (aws, gcloud, az, gsutil, …); `terraform|tofu apply|destroy`,
//   Terraform state rm/push/migrate; `cdk|cdktf deploy|destroy|…`. A data deny can be lifted for an
//   exact command in the project's reins.json (`allow`).
// - deny, any line: a rule file that is present but doesn't load.
// - ask: `gh pr ready`, `gh pr merge` (and its GraphQL/API forms);
//   pushing or moving main or master (`askOnPush`); `gh workflow run` or a dispatch; changing branch protection or
//   a ruleset; setting core.hooksPath or a key a set names; a git alias; a forced push from a branch it can't read.
// - ask, data: destructive SQL, a migration, or a store delete where it can't tell the target; SQL it
//   can't read or built at run time (DO, EXECUTE, \gexec) against a non-loopback database; destructive
//   SQL in a container; removing Docker volumes; `terraform test`, `cdk bootstrap|import`.
// - ask, the guard itself: writing, moving, or deleting a guard file (its config, its rule files, its
//   installed package, the hook config); changing the guard's own package with a package manager;
//   a line it can't read in time, in size, or in depth.
//
// One shell parser, parseLine(), reads the line as a shell would (quotes and heredoc bodies stay
// with their command), and each rule reads a command in command position, so `grep -rn "terraform
// destroy" docs` or a commit message that mentions `dropdb` is not a delete. runs() walks the
// wrappers in front of a program (sudo, timeout, xargs, `sh -c`, ssh, docker exec: WRAPPERS) for
// the git, GitHub, delete, and infrastructure rules. Each commit and push is judged on the branch
// where it runs: a leading `cd X &&` or `git -C X` moves it, not the hook's own cwd.
//
// Database commands are judged by where they point: each SQL client's
// own SQL is read per client, with the wrappers in front read for what they do to the environment
// (prefixOf()), and the original whole-line destructive-SQL rule stays beneath it as a floor
// (FLOOR_*), so the per-client reading can only tighten a verdict.
//
// The built-in git and GitHub acts are a table (POLICY) in a project rule's shape. A project's own
// rules live in its reins.json (deny, ask, and exact-command exemptions from a data-delete deny),
// a pack's in the config's rule folder (`ruleDir`, deny and ask), and the branches no agent
// rewrites in the config's protectedBranches. A caller may rename those files (`files`). A rule
// file that is present but doesn't load fails closed: every command is refused, naming the file,
// because a broken file read as "no rules" would quietly allow everything it exists to stop.
// The rule sets are stricter: they load from the package's own folder or a path the caller names
// (never the hook's cwd), each one named must load, and no exemption lifts their rows.

// Node builtins only, so the hook runs before `pnpm install`.
import { execFileSync } from "node:child_process";
import { lstatSync, opendirSync, readdirSync, readFileSync, statSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";

// The files the guard reads from the project root (`files`; a caller may rename any of them):
// - `config`: the project's config and its own rules (reins.json; CONFIG_KEYS). Absent: the core alone.
// - `ruleDir`: a folder of pack rule files (*.json, deny and ask, name order). None by default; the
//   config's `ruleDir` names one too. Absent folder: nothing added.
// - `branches`: a file whose `protectedBranches` key alone is the guard's (another tool's config file
//   may carry it). None by default.
// A key not listed here is an error, so a misspelt one can't drop a file silently.
// The package's npm name: the one place the code names it (the guard's own package, its install
// folder). It must equal package.json's "name"; test/package.test.mjs checks that.
export const PACKAGE_NAME = "reins";

export const DEFAULT_FILES = Object.freeze({ config: "reins.json", ruleDir: null, branches: null });

// The keys reins.json may hold. `sets` names bundled sets; `deny`, `ask`, and `allow` are the
// project's own rules, as a project rule file holds them; the rest are knobs (loadRules()).
const CONFIG_KEYS = ["$comment", "sets", "ruleDir", "protectedBranches", "askOnPush", "askTags", "deny", "ask", "allow"];

// The bundled rule sets: a team's own rules as data, one JSON file each in the package's sets/ folder
// (sets/<name>.json). None loads unless the config or the caller names it (`sets`), and then every
// one named must load: a set that is missing or broken refuses every command, unlike a project or
// pack file, where absent adds nothing. The order named decides which reason shows when two rows of
// a kind fire on one command.
const SET_DIR = "sets";
export const BUNDLED_SETS = Object.freeze(["draft-flow", "merge-conveyor", "ci-minutes", "chute-boss"]);

// The off switch: any of these set to `off` turns the guard off (`offEnv` replaces the list). The
// second is the name the guard had before it was a package, still read.
export const DEFAULT_OFF_ENV = Object.freeze(["REINS", "WHIPPLETREE_GUARD"]);

// Unix-socket directories that are this machine's Postgres or MySQL. Any other path is not: `/cloudsql/…`
// is the Cloud SQL proxy's socket for a production database.
const LOOPBACK_SOCKET_DIRS = ["/tmp", "/private/tmp", "/var/run/postgresql", "/run/postgresql", "/var/run/mysqld", "/run/mysqld"];

// One IPv4 octet, 0–255, so `127.999.0.1` (not an address) isn't read as loopback.
const OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";

// A host that means "this machine's database": destructive SQL against it is the agent's to run.
// Matched against a parsed host, never the whole line, so `-h db.example.com -c "… -- localhost"`
// and `localhost.example.com` don't count.
const LOOPBACK_HOST = new RegExp(`^(localhost|127(\\.${OCTET}){3}|::1|\\[::1\\]|(${LOOPBACK_SOCKET_DIRS.join("|")})/?)$`, "i");

// Database CLIs that execute SQL against whatever URL they are handed, read from the client's own
// word (its basename); `prisma db execute` and `turso db shell` too (clientAt).
const SQL_CLIENTS = new Set(["psql", "mysql", "mariadb", "sqlcmd", "pgcli", "pg_restore"]);

// SQL that removes rows, columns, tables, types, or whole databases, read one `;`-piece at a time
// (lowercased, with and without comments). Each rule is patterns that must appear in this order,
// each searched from where the last one ended: one linear pass per pattern, where a single
// `update[^;]*set[^;]*=\s*null` backtracks cubically on a long piece with no `;`.
const DESTRUCTIVE_SQL = [
  [/\bdrop\s+(table|column|database|schema|type|domain|view|materialized\s+view|sequence|owned|extension|function|procedure)\b/],
  [/\btruncate\b/],
  // `DELETE FROM t`, and MySQL's multi-table `DELETE u FROM users u` (a bounded table list, so a long one can't backtrack).
  [/\bdelete\s+(?:\w+(?:\s*,\s*\w+){0,15}\s+)?from\b/],
  // A statement that starts with DELETE: T-SQL's `DELETE users` has no FROM.
  [/^\s*delete\b/],
  // `MERGE … WHEN MATCHED THEN DELETE` deletes the rows it matches.
  [/\bmerge\b/, /\bthen\s+delete\b/],
  // `ALTER TABLE t DROP c` (COLUMN is optional); dropping a constraint, default, or NOT NULL loses no data.
  [/\balter\s+table\b/, /\bdrop\s+(?!(constraint|default|not\s+null|identity|expression)\b)/],
  // A clearing UPDATE nulls a column: a delete wearing an update's name.
  [/\bupdate\b/, /\bset\b/, /=\s*null\b/],
  // The same as a row, `SET (a, b) = (NULL, NULL)`, or from a subquery, `SET (a) = (SELECT NULL)`.
  [/\bupdate\b/, /\bset\b/, /=\s*(?:row\s*)?\(\s*(?:select\s+)?null\b/],
  // Cleared to the column's default or an empty string: the old value is gone all the same. Read in
  // the SET list only (up to WHERE), so `SET ok = true WHERE email = ''` isn't one; anchored to where
  // SET ended, so the lazy scan is one linear pass.
  [/\bupdate\b/, /\bset\b/, /^(?:(?!\bwhere\b)[\s\S])*?=\s*(?:default\b|''|"")/],
  // A type change that rewrites every row from NULL: `ALTER COLUMN c TYPE t USING NULL`.
  [/\balter\s+table\b/, /\btype\b/, /\busing\s*\(*\s*null\b/],
  // CASCADE takes dependants with it (`DROP TYPE mood CASCADE` drops the columns of that type).
  [/\bdrop\b/, /\bcascade\b/],
];

// The floor under the per-client SQL reading (evaluateLine): the original whole-line rule, kept
// verbatim so the parser can only make a verdict stricter, never looser. A command at position runs
// a SQL client, the line (heredoc bodies included) has destructive SQL, and no loopback word
// appears anywhere on it → deny. Crude on purpose: it reads no flags, so no flag shape slips past it.
// The loopback words are LOOPBACK_HOST's: any 127.0.0.0/8 address, and `::1` read with lookarounds,
// because `\b` can't sit next to a `:`.
const FLOOR_LOOPBACK = new RegExp(`\\b(localhost|127(\\.${OCTET}){3})\\b|\\[::1\\]|(?<![\\w:])::1(?![\\w:])`);
const FLOOR_SQL_CLIENT = /^(psql|mysql|mariadb|sqlcmd|pgcli|prisma\s+db\s+execute|turso\s+db\s+shell)\b/i;
const FLOOR_DESTRUCTIVE_SQL = /\b(drop\s+(table|column|database|schema)|truncate\b|delete\s+from)\b/i;

// A `;`-piece that builds SQL at run time (`DO $$ … EXECUTE … $$`, a prepared `EXECUTE`), and psql's
// `\gexec`, which runs each result cell as SQL: the guard can't read what either will run.
// Read at the piece's start, so `GRANT EXECUTE ON FUNCTION` is not one.
const DYNAMIC_SQL = /^\s*(do|execute)\b/;
const GEXEC = /\\gexec\b/;

// Most SQL the guard reads for one command line (every client's files, every `\i` they pull in,
// and the lines it runs, together); more counts as SQL it can't read. Per line, not per client, so
// 350 clients each given a 1 MB file read 1 MB once and ask, instead of reading 350 MB.
const MAX_SQL_FILE_BYTES = 1_000_000;

// Most SQL files one command line may open (`-f`, `<`, `\i`, `source`, `cat f |`); past it the SQL can't all be read.
const MAX_SQL_FILES = 20;

// Longest `;`-piece of SQL the guard judges; a longer one (a COPY block, a dump) counts as SQL it can't read.
const MAX_SQL_STATEMENT_CHARS = 100_000;

// How deep `eval`, `sh -c`, and package scripts may nest before the line asks: each level re-reads
// the whole line, so thousands of `eval`s would run past the hook's timeout.
const MAX_NESTING = 8;

// libpq variables that override `-h` (PGHOSTADDR) or pull the host from a file (PGSERVICE).
const PG_HOST_OVERRIDES = ["PGHOSTADDR", "PGSERVICE"];

// libpq's default host, used when the line names none (`PGHOST=db.example.com psql -c …`).
const PG_HOST_DEFAULT = "PGHOST";

// Migration-tool commands, by what they do to the database they point at, matched from the tool's
// own word (its basename, `@version` removed) wherever it sits on the command:
// `destroys` drops, resets, or rolls back (data goes); `dev` is Prisma's dev loop, which offers to
// reset the database when its history differs; `applies` runs pending migrations. `vars` are where
// the tool reads its URL from when none is on the command line. Optional: `config` (the URL usually
// comes from a config file the guard doesn't read, so a loopback reading isn't trusted), `envFiles`
// (dotenv files the tool loads itself), `schemaFlags` (flags that point it at another project dir),
// `hiddenFlags` (flags that load variables from elsewhere), `urlFlags` (its own URL flags),
// `remoteFlag` (a flag that always means the hosted database), `unset` (what no target means),
// `prisma` (read Prisma's schema and config files: PRISMA_CONFIGS).
const MIGRATE_COMMANDS = [
  { match: /^prisma\s+migrate\s+reset\b/, effect: "destroys", what: "`prisma migrate reset` drops every table and re-applies the migrations", vars: ["DATABASE_URL"], envFiles: [".env", "prisma/.env"], schemaFlags: ["--schema", "--config"], prisma: true },
  { match: /^prisma\s+db\s+push\b.*\s--(accept-data-loss|force-reset)\b/, effect: "destroys", what: "`prisma db push` with --accept-data-loss or --force-reset drops what the schema no longer has", vars: ["DATABASE_URL"], envFiles: [".env", "prisma/.env"], schemaFlags: ["--schema", "--config"], prisma: true },
  { match: /^prisma\s+migrate\s+dev\b/, effect: "dev", what: "`prisma migrate dev` offers to reset the database when its history differs", vars: ["DATABASE_URL"], envFiles: [".env", "prisma/.env"], schemaFlags: ["--schema", "--config"], prisma: true },
  { match: /^prisma\s+migrate\s+deploy\b/, effect: "applies", what: "`prisma migrate deploy`", vars: ["DATABASE_URL"], envFiles: [".env", "prisma/.env"], schemaFlags: ["--schema", "--config"], prisma: true },
  // sqlx-cli aliases `database` as `db` and `migrate` as `mig`.
  { match: /^sqlx\s+((database|db)\s+(drop|reset)|(migrate|mig)\s+revert)\b/, effect: "destroys", what: "`sqlx database drop/reset` or `migrate revert` drops a database or rolls a migration back", vars: ["DATABASE_URL"] },
  { match: /^sqlx\s+((migrate|mig)\s+run|(database|db)\s+setup)\b/, effect: "applies", what: "`sqlx migrate run`", vars: ["DATABASE_URL"] },
  { match: /^diesel\s+(database\s+(drop|reset)|migration\s+(revert|redo))\b/, effect: "destroys", what: "`diesel database reset/drop` or `migration revert/redo` drops a database or rolls a migration back", vars: ["DATABASE_URL"] },
  { match: /^diesel\s+(migration\s+run|database\s+setup)\b/, effect: "applies", what: "`diesel migration run`", vars: ["DATABASE_URL"] },
  // `goose create down sql` makes a file named "down"; it touches no database.
  { match: /^goose\b(?!.*\s(create|fix)\s).*\s(reset|down|down-to|redo)(\s|$)/, effect: "destroys", what: "`goose down/down-to/redo/reset` rolls migrations back", vars: ["GOOSE_DBSTRING"] },
  { match: /^goose\b(?!.*\s(create|fix)\s).*\s(up|up-by-one|up-to)(\s|$)/, effect: "applies", what: "`goose up`", vars: ["GOOSE_DBSTRING"] },
  // `goto V` rolls back when V is below the current version.
  { match: /^migrate\b.*\s(down|drop|force|goto)(\s|$)/, effect: "destroys", what: "golang-migrate `down/drop/force/goto` rolls back, drops everything, or rewrites the recorded version", vars: [] },
  { match: /^migrate\b.*\sup(\s|$)/, effect: "applies", what: "golang-migrate `up`", vars: [] },
  { match: /^dbmate\b.*\s(drop|rollback|down)(\s|$)/, effect: "destroys", what: "`dbmate drop/rollback` drops the database or rolls a migration back", vars: ["DATABASE_URL"], urlFlags: ["-u"], hiddenFlags: ["-e", "--env", "--env-file"] },
  { match: /^dbmate\b.*\s(up|migrate)(\s|$)/, effect: "applies", what: "`dbmate up`", vars: ["DATABASE_URL"], urlFlags: ["-u"], hiddenFlags: ["-e", "--env", "--env-file"] },
  { match: /^alembic\b.*\sdowngrade\b/, effect: "destroys", what: "`alembic downgrade` rolls migrations back", vars: ["DATABASE_URL"], config: true },
  { match: /^alembic\b.*\supgrade\b/, effect: "applies", what: "`alembic upgrade`", vars: ["DATABASE_URL"], config: true },
  { match: /^knex\b.*\smigrate:(rollback|down)\b/, effect: "destroys", what: "`knex migrate:rollback/down` rolls migrations back", vars: ["DATABASE_URL"], config: true },
  { match: /^drizzle-kit\s+push\b.*\s--force\b/, effect: "destroys", what: "`drizzle-kit push --force` applies data-loss statements without asking", vars: ["DATABASE_URL"], config: true },
  // Without --linked or --db-url it resets the local Docker database.
  { match: /^supabase\s+db\s+reset\b/, effect: "destroys", what: "`supabase db reset` drops the database and re-applies the migrations", vars: [], remoteFlag: "--linked", unset: "loopback" },
];

// Tool words MIGRATE_COMMANDS starts from.
const MIGRATE_TOOLS = new Set(MIGRATE_COMMANDS.map((command) => /^\^([\w-]+)/.exec(command.match.source)?.[1] ?? ""));

// Prisma's config files and default schemas, where the commands with `prisma: true` may have a
// URL written in (`url = "postgres://…"`); with a config file present, Prisma loads no .env itself.
const PRISMA_CONFIGS = ["prisma.config.ts", "prisma.config.mts", "prisma.config.cts", "prisma.config.js", "prisma.config.mjs", "prisma.config.cjs", ".config/prisma.ts"];
const PRISMA_SCHEMAS = ["prisma/schema.prisma", "schema.prisma", "prisma/schema"];

// A multi-file schema folder (`prisma/schema/*.prisma`, nested folders too) is read up to this many
// `.prisma` files, this many folders deep, and MAX_SQL_FILE_BYTES in all; past any of them it is
// unseen, so a reset asks.
const MAX_PRISMA_FILES = 64;
const MAX_PRISMA_DEPTH = 3;

// Where a Prisma schema or config says the datasource is: `url` and `directUrl` (migrate uses
// directUrl when there is one), each `= "postgres://…"`, `url: "…"`, `env("NAME")`, or `process.env.NAME`.
// The value is read by prismaUrl(); `shadowDatabaseUrl` is a scratch database, not the target.
const PRISMA_URL_KEY = /\b(url|directUrl)\s*[=:]\s*([^\n,}]*)/g;

// Flags that hand a migration tool or SQL client its connection string (sqlx -D, golang-migrate -database).
const URL_FLAGS = new Set(["--url", "--database-url", "--db-url", "-D", "-database", "--database", "-d", "--dbname"]);

// Secret loaders that run a command with variables the line doesn't show (after `--`, or not).
const LOADERS = /^(dotenv|dotenvx|doppler|op|infisical|env-cmd|railway|heroku|vercel|fly|flyctl|chamber|aws-vault|sops|teller|envchain)$/i;

// Words in front of a database tool that pass its variables and directory through unchanged
// (their flags and flag values too). Any other word in front means the guard can't vouch for the target.
const PLAIN_WRAPPERS = new Set(["sudo", "env", "time", "nice", "command", "exec", "node", "npx", "bunx", "nohup", "timeout", "cross-env", "pnpm", "yarn", "npm", "bun", "dlx", "x", "run", "run-script", "--"]);

// Programs that run a command line somewhere else (another machine, a container, another user's
// login shell): what they run is judged as a line of its own, where nothing local counts (handedOn).
const REMOTE_RUNNERS = new Set(["ssh", "kubectl", "oc", "docker", "podman", "nerdctl", "docker-compose", "su", "chroot", "nsenter", "vagrant", "gcloud"]);

// The REMOTE_RUNNERS that run a local container (`docker compose exec db psql …`): a SQL client with
// no host there reaches the container's own database, so the floor asks instead of refusing.
// Not kubectl or ssh: a cluster's or another machine's database may be production.
const CONTAINER_RUNNERS = new Set(["docker", "podman", "nerdctl", "docker-compose"]);

// A variable removed for a command (`unset X`, `env -u X`): it reads X from its .env, not the environment.
const UNSET = Symbol("unset");

// Package-manager and `env` flags that run the tool in another directory or package.
const MOVING_FLAGS = /^(-C|--chdir|--dir|--prefix|--cwd|--filter|-F|-r|--recursive|-w|--workspace-root|--workspace|--workspaces|-ws)(=|$)/;

// Variables a database tool reads its target from; `source`, `eval`, or a loader leaves each unseen.
const DB_VARS = [...new Set([...MIGRATE_COMMANDS.flatMap((command) => command.vars), ...PG_HOST_OVERRIDES, PG_HOST_DEFAULT])];

// Commands that delete data, a recovery point, or the key that decrypts it, whatever the target
// (matched at command position). Cloud CLI deletes (aws, gcloud, az, gsutil, bq) are read by
// evaluateInfra() instead, which knows each CLI's help and option shapes (`aws s3 rb help` is help).
// Read from each program's words (programArgv()), so a full path (`/usr/bin/dropdb`), gh's `-R o/r`,
// or a wrapper in front (`timeout 9 dropdb x`) hides nothing.
const ALWAYS_DESTRUCTIVE = [
  /^dropdb\b/,
  // `neon` is neonctl's other name.
  /^neon(ctl)?\b.*\b(branches?|projects?|databases?)\s+(delete|reset)\b/,
  // Hosted databases and stores: Turso, PlanetScale, Cloudflare D1 / R2 / KV.
  /^turso\b.*\b(db|group)\s+destroy\b/,
  /^pscale\b.*\b(database|db|branch|backup)\s+delete\b/,
  /^wrangler\b.*\b(d1|r2\s+(bucket|object)|kv[:\s]+namespace)\s+delete\b/,
  // A GitHub repository or release (its assets too) is gone for everyone once deleted.
  /^gh\s+(repo|release)\s+delete(-asset)?\b/,
];

// Branches no agent rewrites or deletes (`protected`). This is the core's default; a rule set's
// `protectedBranches` replaces it (a set may name main, dev, and a generated branch), and the
// config's (or the `branches` file's) `protectedBranches` replaces that in turn (loadRules()).
// `workflowOnly` are the ones only a workflow writes, so an agent never pushes them at all: a set's
// `workflowOnlyBranches` (a generated branch that one publish workflow alone writes). A branch keeps
// that rule whenever it is protected; a project without one loses nothing.
const CORE_PROTECTED = ["main", "master"];

// Branches whose every push (or ref move) asks, since pushing one usually ships production: the
// config's `askOnPush` replaces the default.
const CORE_ASK_ON_PUSH = ["main", "master"];
const CORE_ASK_ON_PUSH_SET = new Set(CORE_ASK_ON_PUSH);
const askOnPushOf = (branches) => branches.askOnPush ?? CORE_ASK_ON_PUSH_SET;

// The freeze markers (a set's `freezeMarkers`; a ship freeze stops pushes to a branch while a release is open) sit in the clone's shared git dir (`git rev-parse
// --git-common-dir`) so every worktree of the clone sees them; while one is there, a push to its branch
// is refused (shipFreeze()).

// Words that run the command after them, so the command word is the next one (`builtin cd x` is a cd).
const PREFIXES = new Set(["sudo", "env", "time", "nice", "command", "builtin", "exec", "npx", "bunx"]);

// ── Infrastructure: IaC apply/destroy/state surgery and cloud CLI deletes ──
// Built in, not a pack rule file: deleting data is a human action whatever the stack, so this holds when
// a project drops its infra pack too. Read by evaluateInfra() below, which parses the line as a shell would.

// Infrastructure-as-code CLIs, by program name (a versioned binary like terraform_1.9 too; `tf` is
// the usual alias). Any case: macOS and Windows file systems run `TERRAFORM` as terraform.
const IAC_CLI = /^(terraform|tofu|terragrunt|tf)([-_]?v?\d[\w.]*)?(\.exe)?$/i;

// Cloud CLIs whose delete verbs remove real resources or the data in them; any case, as above.
// The object-storage tools (azcopy, rclone, s5cmd, mc, s3cmd) and the PaaS CLIs (doctl, fly, heroku) too.
const CLOUD_CLI = /^(aws|gcloud|az|gsutil|bq|azcopy|rclone|s5cmd|mc|s3cmd|doctl|flyctl|fly|heroku)(\.exe)?$/i;

// Shells: `bash script`, `bash -c '…'`, or one reading stdin from a pipe, heredoc, or here-string.
const SHELL = /^(ba|z|da|k|fi|c|tc|a|mk|lk|y|po|rba)?sh$/;

// ── Work budget: the hook's own timeout lets the command run, so the guard stops early and asks ──

// Longest command line read at all; a longer one asks before parsing. Room for a big heredoc file
// write or PR body; a line this size takes a few ms to read once every pass is linear.
const MAX_COMMAND_CHARS = 64 * 1024;

// Most CPU time (user + system, the evaluating thread) evaluate() may spend; past it the verdict is ask.
// CPU, not wall-clock, so a guard the scheduler leaves waiting on a loaded machine (nine agents,
// load average in the hundreds) is not charged for the wait. A backstop for any shape the size
// budget lets through that is still slow; child processes (git lookups) are not counted here.
const MAX_EVALUATE_MS = 250;

// Longest evaluate() may take on the wall clock, whatever its CPU use; past it the verdict is ask.
// For a read that blocks without using CPU (a git lookup waiting on a slow disk, which has its own
// GIT_LOOKUP_MS timeout). Far above MAX_EVALUATE_MS so load alone does not trip it, and under
// WATCHDOG_MS and the hook's 10 s timeout (which fails open), so it answers first.
const MAX_EVALUATE_WALL_MS = 2500;

// The budgets, as evaluate() reads them; a test passes its own to time one parser path alone.
// `now` and `cpu` (milliseconds) are clock readers a test may replace to stall one without the other.
export const LIMITS = { chars: MAX_COMMAND_CHARS, ms: MAX_EVALUATE_MS, wallMs: MAX_EVALUATE_WALL_MS };

// Longest the hook entry waits for a verdict, from start to answer; past it the verdict is ask (main()).
export const WATCHDOG_MS = 3000;

// Longest one `git rev-parse` branch lookup may take before it is killed and the branch reads as
// unknown (ask). A FIFO or a slow repo can hold git up, and the watchdog can stop JavaScript but
// not a blocked child process, so the lookup bounds itself. (A git stuck where SIGKILL can't reach
// it, as on a hard-hung NFS mount, is not bounded by this.)
const GIT_LOOKUP_MS = 1000;

// Deepest `$(`/`${`/`"` nesting the span scanners (closeParen and friends) follow; deeper asks by
// design instead of overflowing the call stack.
const MAX_SCAN_NESTING = 256;

// Thrown by tick() when a time budget is spent; evaluate() turns it into an ask. `kind` is "cpu" or "wall".
class OverBudget extends Error {
  constructor(kind) {
    super(`over the ${kind} time budget`);
    this.kind = kind;
  }
}

// Milliseconds of CPU time (user + system) the evaluating thread has used; children not included.
// Per thread where Node has it (23.9+, 22.19+), so V8's helper threads (GC, JIT) running beside a
// sleeping guard are not charged to it; else the whole process, which only over-counts (asks sooner).
const cpuNow = () => {
  const { user, system } = typeof process.threadCpuUsage === "function" ? process.threadCpuUsage() : process.cpuUsage();
  return (user + system) / 1000;
};

// True for the error vm throws when main()'s watchdog stops the evaluation (it surfaces inside
// evaluate()). Read by shape, not instanceof: inside the run it can come from the vm context's realm.
const watchdogFired = (error) => typeof error === "object" && error !== null && (Reflect.get(error, "code") === "ERR_SCRIPT_EXECUTION_TIMEOUT" || String(Reflect.get(error, "message")).startsWith("Script execution timed out"));

// Thrown by the span scanners past MAX_SCAN_NESTING; evaluate() turns it into an ask.
class TooDeep extends Error {}

// What the current evaluate() must stop at (null outside one): the CPU and wall-clock readings it
// may not pass, and the readers. And a step counter, so the clocks are read once per 1024 steps
// rather than on every character.
let budget = null;
let steps = 0;

// Throws OverBudget once either budget is spent; read after any step that can be slow on its own (a branch lookup).
const checkClock = () => {
  if (budget === null) return;
  if (budget.cpu() > budget.cpuEnd) throw new OverBudget("cpu");
  if (budget.now() > budget.wallEnd) throw new OverBudget("wall");
};

// One step of work in a loop that could run long; throws OverBudget once a budget is spent.
const tick = () => {
  steps += 1;
  if ((steps & 1023) === 0) checkClock();
};

// Reads the current branch in `dir`; empty when it cannot be read (not a repo, detached, missing, too slow).
const currentBranch = (dir) => {
  // execFileSync, not a shell string, so an odd path can't inject anything. The timeout kills a
  // git that blocks (a FIFO HEAD), so the lookup returns "" and the guard asks.
  try {
    return execFileSync("git", ["-C", dir, "rev-parse", "--abbrev-ref", "HEAD"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: GIT_LOOKUP_MS,
      killSignal: "SIGKILL",
    }).trim();
  } catch {
    return "";
  }
};

// The freeze marker's text in `dir`'s clone (trimmed; "" when empty), or null when there is none
// or git can't say where the clone's git dir is. `file` is the marker's name (a set's `freezeMarkers`).
export const shipFreeze = (dir, file) => {
  if (typeof file !== "string" || file === "") return null;
  try {
    const common = execFileSync("git", ["-C", dir, "rev-parse", "--git-common-dir"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: GIT_LOOKUP_MS,
      killSignal: "SIGKILL",
    }).trim();
    return readFileSync(resolve(dir, common, file), "utf8").trim();
  } catch {
    return null;
  }
};

// ── The shell parser every rule reads: parseLine() ──

// Characters that end an unquoted word: blanks and the shell's operators.
const WORD_END = " \t\n;&|()<>";

// `$'…'` escapes the shell decodes (ANSI-C quoting); \xHH, \uHHHH, and octal are decoded in ansiC().
const ANSI_ESCAPES = { n: "\n", t: "\t", r: "\r", a: "\x07", b: "\b", e: "\x1b", E: "\x1b", f: "\f", v: "\v" };

// ASCII upper case to lower, nothing else: a file system that folds case (macOS's default) runs `GIT`
// as git, so every rule reads a program by its folded name. Not toLowerCase(): that folds some
// non-ASCII letters (the Kelvin sign, a dotted I) and leaves the rest; those words ask (judge()).
// A word with no capital is returned as it is, and a run of capitals is lowered at once: this runs on every program word of a long line.
const foldAscii = (value) => (/[A-Z]/.test(value) ? value.replace(/[A-Z]+/g, (run) => run.toLowerCase()) : value);

// A word as a program name: the part after the last `/`, case folded (`/usr/local/bin/Terraform` → terraform).
const programName = (value) => foldAscii(value.slice(value.lastIndexOf("/") + 1));

// Reads a heredoc opener at i (`<<WORD`, `<<-WORD`, `<<'WO'RD`, `<<"WORD"`, `<<\WORD`); null when
// there is none. Returns { delim, expands, strip, end }.
//
// The terminator is the whole word after quote removal, as bash reads it: `<<E\OF` and `<<"E"OF`
// both end at a line `EOF`. Any quote or backslash in the word stops the body expanding, and `<<-`
// strips leading tabs (only tabs) from each body line and the terminator line.
const heredocAt = (text, i) => {
  if (text[i] !== "<" || text[i + 1] !== "<" || text[i + 2] === "<") return null;
  let j = i + 2;
  const strip = text[j] === "-";
  if (strip) j += 1;
  while (text[j] === " " || text[j] === "\t") j += 1;
  const start = j;
  let delim = "";
  let quoted = false;
  while (j < text.length && !WORD_END.includes(text[j] ?? "")) {
    const char = text[j];
    if (char === "\\") {
      delim += text[j + 1] ?? "";
      quoted = true;
      j += 2;
    } else if (char === "'") {
      const close = text.indexOf("'", j + 1);
      const end = close === -1 ? text.length : close;
      delim += text.slice(j + 1, end);
      quoted = true;
      j = end + 1;
    } else if (char === '"') {
      // Inside double quotes a backslash escapes only \ " $ ` (the word is never expanded).
      j += 1;
      while (j < text.length && text[j] !== '"') {
        if (text[j] === "\\" && '\\"$`'.includes(text[j + 1] ?? "x")) j += 1;
        delim += text[j] ?? "";
        j += 1;
      }
      quoted = true;
      j += 1;
    } else {
      delim += char;
      j += 1;
    }
  }
  return j === start ? null : { delim, expands: !quoted, strip, end: Math.min(j, text.length) };
};

// Reads the bodies of `docs` (heredocs opened on one line) from `at`, the start of the next line.
// Returns { bodies, next }, next being the index after the last terminator line.
//
// A body ends at a line that is exactly its terminator (after `<<-`'s tab strip), as in bash: a
// trailing blank or a leading space makes it a body line, so `EOF ` can't end a body early and
// hide the commands after it inside the next heredoc. An unterminated body runs to the end.
const readBodies = (text, at, docs) => {
  const bodies = [];
  let i = at;
  for (const doc of docs) {
    const lines = [];
    while (i < text.length) {
      tick();
      const lineEnd = text.indexOf("\n", i);
      const end = lineEnd === -1 ? text.length : lineEnd;
      const raw = text.slice(i, end);
      const line = doc.strip ? raw.replace(/^\t+/, "") : raw;
      i = end + 1;
      if (line === doc.delim) break;
      lines.push(line);
    }
    bodies.push(lines.join("\n"));
  }
  return { bodies, next: Math.min(i, text.length) };
};

// Index of the backtick closing one opened before `from` (escapes skipped), or the end of the text.
const closeTick = (text, from) => {
  for (let i = from; i < text.length; i += 1) {
    if (text[i] === "\\") i += 1;
    else if (text[i] === "`") return i;
  }
  return text.length;
};

// True when `word` stands alone at i, with an operator, a blank, or an edge on both sides.
const wordAt = (text, i, word) => text.startsWith(word, i) && (i === 0 || WORD_END.includes(text[i - 1] ?? "")) && (i + word.length >= text.length || WORD_END.includes(text[i + word.length] ?? ""));

// Index of the `)` closing a `$(` / `<(` / `(` opened before `from`, or the end of the text.
//
// Iterative over `$(` and quotes (a stack of open parens, double quotes, and `case`s), and one
// pass, so it stays linear. A `${…}` recurses through closeBrace(), so `nesting` counts those hops
// and past MAX_SCAN_NESTING it throws TooDeep (an ask) before the call stack can overflow. It skips
// what bash skips, or a `)` in it would end the substitution early and leave the rest as text:
// quotes, `$'…'` (with `\'`), `${…}`, heredoc bodies (a commit message's `(scope)`), comments
// (`# )`), and `case` patterns (`a)`).
const closeParen = (text, from, nesting = 0) => {
  if (nesting > MAX_SCAN_NESTING) throw new TooDeep("nested too deep");
  const open = ["("];
  let docs = [];
  for (let i = from; i < text.length; i += 1) {
    tick();
    const char = text[i];
    if (char === "\\") {
      i += 1;
      continue;
    }
    // Inside double quotes only an escape, a substitution, or the closing quote matters.
    if (open.at(-1) === '"') {
      if (char === '"') open.pop();
      else if (char === "`") i = closeTick(text, i + 1);
      else if (char === "$" && text[i + 1] === "(") {
        open.push("(");
        i += 1;
      } else if (char === "$" && text[i + 1] === "{") i = closeBrace(text, i + 2, nesting + 1);
      continue;
    }
    if (char === "$" && text[i + 1] === "'") {
      i = ansiC(text, i + 2).next - 1;
      continue;
    }
    if (char === "$" && text[i + 1] === "{") {
      i = closeBrace(text, i + 2, nesting + 1);
      continue;
    }
    if (char === "'") {
      const close = text.indexOf("'", i + 1);
      i = close === -1 ? text.length : close;
      continue;
    }
    if (char === '"') {
      open.push('"');
      continue;
    }
    if (char === "`") {
      i = closeTick(text, i + 1);
      continue;
    }
    // A comment (a `#` starting a word) runs to the end of the line.
    if (char === "#" && (i === from || WORD_END.includes(text[i - 1] ?? ""))) {
      const end = text.indexOf("\n", i);
      i = (end === -1 ? text.length : end) - 1;
      continue;
    }
    // A heredoc opener (not inside a `<<<` here-string): its body follows the next newline.
    if (char === "<" && text[i - 1] !== "<") {
      const opener = heredocAt(text, i);
      if (opener) {
        docs.push(opener);
        i = opener.end - 1;
        continue;
      }
    }
    if (char === "\n" && docs.length > 0) {
      i = readBodies(text, i + 1, docs).next - 1;
      docs = [];
      continue;
    }
    // `case … in`: a `)` ends a pattern, not the substitution, until the `esac`.
    if (char === "c" && wordAt(text, i, "case")) {
      open.push("case");
      i += 3;
      continue;
    }
    if (char === "e" && open.at(-1) === "case" && wordAt(text, i, "esac")) {
      open.pop();
      i += 3;
      continue;
    }
    if (char === "(") open.push("(");
    else if (char === ")" && open.at(-1) !== "case") {
      open.pop();
      if (open.length === 0) return i;
    }
  }
  return text.length;
};

// Index of the `}` closing a `${` opened before `from`, or the end of the text. Quotes inside
// count, as bash reads them (`"${x:-'}'}"` and `"${x:-"}"}"` are one expansion each), and so do
// nested `${`, `$(`, and backticks; a bare `{` does not nest. `nesting` as in closeParen().
const closeBrace = (text, from, nesting = 0) => {
  if (nesting > MAX_SCAN_NESTING) throw new TooDeep("nested too deep");
  let depth = 1;
  for (let i = from; i < text.length; i += 1) {
    tick();
    const char = text[i];
    if (char === "\\") i += 1;
    else if (char === "'") {
      const close = text.indexOf("'", i + 1);
      i = close === -1 ? text.length : close;
    } else if (char === '"') i = closeDouble(text, i + 1, nesting + 1);
    else if (char === "`") i = closeTick(text, i + 1);
    else if (char === "$" && text[i + 1] === "(") i = closeParen(text, i + 2, nesting + 1);
    else if (char === "$" && text[i + 1] === "{") {
      depth += 1;
      i += 1;
    } else if (char === "}") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return text.length;
};

// Index of the `"` closing a double quote opened before `from` (escapes and substitutions skipped), or the end.
const closeDouble = (text, from, nesting = 0) => {
  if (nesting > MAX_SCAN_NESTING) throw new TooDeep("nested too deep");
  for (let i = from; i < text.length; i += 1) {
    tick();
    const char = text[i];
    if (char === "\\") i += 1;
    else if (char === '"') return i;
    else if (char === "`") i = closeTick(text, i + 1);
    else if (char === "$" && text[i + 1] === "(") i = closeParen(text, i + 2, nesting + 1);
    else if (char === "$" && text[i + 1] === "{") i = closeBrace(text, i + 2, nesting + 1);
  }
  return text.length;
};

// Decodes a `$'…'` body starting at `from` (just past the quote); returns { decoded, next }.
const ansiC = (text, from) => {
  let decoded = "";
  let i = from;
  while (i < text.length && text[i] !== "'") {
    if (text[i] !== "\\") {
      decoded += text[i];
      i += 1;
      continue;
    }
    const rest = text.slice(i + 1, i + 10);
    const code = /^x([0-9A-Fa-f]{1,2})/.exec(rest) ?? /^u([0-9A-Fa-f]{1,4})/.exec(rest) ?? /^U([0-9A-Fa-f]{1,8})/.exec(rest);
    const octal = /^[0-7]{1,3}/.exec(rest);
    if (code) {
      decoded += String.fromCodePoint(Math.min(Number.parseInt(code[1], 16), 0x10ffff));
      i += 1 + code[0].length;
    } else if (octal) {
      decoded += String.fromCharCode(Number.parseInt(octal[0], 8));
      i += 1 + octal[0].length;
    } else {
      const next = text[i + 1] ?? "";
      decoded += Object.hasOwn(ANSI_ESCAPES, next) ? ANSI_ESCAPES[next] : next;
      i += 2;
    }
  }
  return { decoded, next: i + 1 };
};

// An empty simple command for parseLine(); `piped` says a pipe feeds its stdin.
const newCommand = (piped) => ({ words: [], tokens: [], expands: [], starts: [], heredocs: [], herestrings: [], stdinProcs: [], outProcs: [], piped, opens: 0, closes: 0, funcdef: false, inCase: false, background: false, start: -1, end: -1 });

// Parses a command line the way a shell reads it, into { commands, nested }.
//
// Each command: `words` ({ value: quotes and escapes removed, adjacent parts joined; dynamic: it
// expands at run time ($VAR, $(…), `…`, a brace expansion); brace; proc: a process substitution
// word's { dir, text } }), the heredoc bodies ({ body, expands, delim }) and here-strings it is fed,
// `stdinProcs` (the text of a `< <(…)` it reads), `outProcs` (the text of each `>(…)` it writes
// into), `piped` (a pipe feeds its stdin), and its span in the line. `nested` is the text of every
// substitution the shell would run on its own: in bare and double-quoted words and
// unquoted-terminator heredoc bodies, never in single quotes or a `<<'EOF'` body. A line
// continuation (backslash-newline) joins its lines.
//
// For the database rules, which read flags and redirects side by side, each command also has
// `tokens`: its words and redirects in order as plain strings (`>`, `out`; `2>&1`; `<<<sql`; `<<EOF`,
// glued as typed), `expands` (per token: a `$` or backtick outside single quotes, so its text is only
// known when it runs), and `starts` (each token's offset). `opens` and `closes` count the subshell
// parens around it, `funcdef` marks a function's name (`f()`), `inCase` a command in a `case` arm,
// and `background` one a lone `&` ends; an arm's pattern (`a|b)`) and `esac` are read here and are
// no command.
export const parseLine = (text) => {
  const commands = [];
  const nested = [];
  let command = newCommand(false);
  // Heredocs opened on the current line: { delim, expands, strip, command }; bodies follow the next newline.
  let pending = [];
  // `(`s read since the last command ended, which the next one opens.
  let opens = 0;
  // Open `case … esac` blocks, innermost last: "pattern" while an arm's pattern is read, else "body".
  const cases = [];
  // A file descriptor glued to the redirect that follows it (`2>`).
  let fd = null;
  let i = 0;

  const filled = (each) => each.tokens.length + each.heredocs.length + each.herestrings.length + each.stdinProcs.length + each.outProcs.length > 0 || pending.some((doc) => doc.command === each);

  // Ends the current command; `piped` says a pipe feeds the next one.
  const endCommand = (piped) => {
    if (filled(command)) {
      command.inCase = cases.length > 0;
      commands.push(command);
    }
    command = newCommand(piped);
  };

  // Starts the current command at `at` unless it has started; it takes the `(`s read before it.
  const begin = (at) => {
    if (command.start !== -1) return;
    command.start = at;
    command.opens = opens;
    opens = 0;
  };

  const token = (value, expands, at) => {
    command.tokens.push(value);
    command.expands.push(expands);
    command.starts.push(at);
  };

  // A redirect's tokens: its operator glued to its target as typed (`>out`, `2>&1`), else apart.
  const redirect = (operator, target, glued, at) => {
    if (target !== null && glued) token(operator + target.value, target.dollar, at);
    else {
      token(operator, false, at);
      if (target !== null) token(target.value, target.dollar, target.start);
    }
  };

  // Records every substitution in text that expands (an unquoted-terminator heredoc body, a `${…}`).
  const scanExpansions = (body) => {
    for (let k = 0; k < body.length; k += 1) {
      if (body[k] === "\\") k += 1;
      else if (body[k] === "`") {
        const end = closeTick(body, k + 1);
        nested.push(body.slice(k + 1, end));
        k = end;
      } else if (body[k] === "$" && body[k + 1] === "(") {
        const end = closeParen(body, k + 2);
        nested.push(body.slice(k + 2, end));
        k = end;
      }
    }
  };

  // The expansion at i (`$(…)`, `` `…` ``, `${…}`, `$NAME`): records what runs; returns the text the word keeps.
  const expansion = () => {
    const at = i;
    if (text[at] === "`") {
      const end = closeTick(text, at + 1);
      nested.push(text.slice(at + 1, end));
      i = end + 1;
      return { kept: text.slice(at, end + 1), dynamic: true };
    }
    if (text[at + 1] === "(") {
      const end = closeParen(text, at + 2);
      nested.push(text.slice(at + 2, end));
      i = end + 1;
      return { kept: text.slice(at, end + 1), dynamic: true };
    }
    if (text[at + 1] === "{") {
      const end = closeBrace(text, at + 2);
      scanExpansions(text.slice(at + 2, end));
      i = end + 1;
      return { kept: text.slice(at, end + 1), dynamic: true };
    }
    // `$NAME`, `$1`, `$@`: the name follows as ordinary characters. A `$` before anything else is literal.
    i += 1;
    return { kept: "$", dynamic: /[A-Za-z0-9_@*#?$!-]/.test(text[at + 1] ?? "") };
  };

  // Reads one word at i (leading blanks skipped); null when there is none.
  const readWord = () => {
    while (text[i] === " " || text[i] === "\t" || (text[i] === "\\" && text[i + 1] === "\n")) i += text[i] === "\\" ? 2 : 1;
    const start = i;
    let value = "";
    let dynamic = false;
    // Any `$` or backtick outside single quotes, even escaped or literal: the token's `expands`.
    let dollar = false;
    // Brace expansion turns one word into several at run time (`terraform {apply,-auto-approve}`):
    // an unquoted `{` (1), then a `,` or `..` (2), then a `}`.
    let brace = 0;
    let expands = false;
    let proc = null;
    while (i < text.length) {
      const char = text[i];
      // A backslash takes the next character literally; before a newline it joins two lines.
      if (char === "\\") {
        if (text[i + 1] !== "\n") value += text[i + 1] ?? "";
        dollar ||= text[i + 1] === "$" || text[i + 1] === "`";
        i += 2;
        continue;
      }
      // Single quotes: everything literal, no expansion.
      if (char === "'") {
        const close = text.indexOf("'", i + 1);
        const end = close === -1 ? text.length : close;
        value += text.slice(i + 1, end);
        i = end + 1;
        continue;
      }
      // `$'…'`: literal with C escapes decoded.
      if (char === "$" && text[i + 1] === "'") {
        const { decoded, next } = ansiC(text, i + 2);
        value += decoded;
        dollar = true;
        i = next;
        continue;
      }
      // `$"…"` is a double-quoted string (translated); the `$` goes.
      if (char === "$" && text[i + 1] === '"') {
        dollar = true;
        i += 1;
        continue;
      }
      // Double quotes: \ escapes only \ " $ ` and a newline; substitutions still run.
      if (char === '"') {
        i += 1;
        while (i < text.length && text[i] !== '"') {
          const inner = text[i];
          const next = text[i + 1] ?? "";
          if (inner === "\\" && next !== "" && '$`"\\\n'.includes(next)) {
            if (next !== "\n") value += next;
            dollar ||= next === "$" || next === "`";
            i += 2;
          } else if (inner === "$" || inner === "`") {
            const part = expansion();
            value += part.kept;
            dynamic ||= part.dynamic;
            dollar = true;
          } else {
            value += inner;
            i += 1;
          }
        }
        i += 1;
        continue;
      }
      if (char === "$" || char === "`") {
        const part = expansion();
        value += part.kept;
        dynamic ||= part.dynamic;
        dollar = true;
        continue;
      }
      // Process substitution at the start of a word. `<(X)` runs X on its own; `>(X)` runs X on what
      // this command writes into it, so evaluateInfra() reads X with the command (outProcs).
      if ((char === "<" || char === ">") && text[i + 1] === "(" && i === start) {
        const end = closeParen(text, i + 2);
        const inner = text.slice(i + 2, end);
        if (char === "<") nested.push(inner);
        else command.outProcs.push(inner);
        proc = { dir: char, text: inner };
        value += text.slice(i, end + 1);
        dynamic = true;
        dollar ||= /[$`]/.test(inner);
        i = end + 1;
        continue;
      }
      // An array assignment `a=(x y)` keeps its parentheses.
      if (char === "(" && i > start && /^[A-Za-z_][A-Za-z0-9_]*\+?=$/.test(value)) {
        const end = closeParen(text, i + 1);
        value += text.slice(i, end + 1);
        dollar ||= /[$`]/.test(text.slice(i, end));
        i = end + 1;
        continue;
      }
      // Blanks and operators end the word.
      if (WORD_END.includes(char)) break;
      if (char === "{" && brace === 0) brace = 1;
      else if (brace === 1 && (char === "," || (char === "." && text[i + 1] === "."))) brace = 2;
      else if (char === "}" && brace === 2) expands = true;
      value += char;
      i += 1;
    }
    return i > start ? { value, dynamic: dynamic || expands, brace: expands, proc, dollar, start, end: i } : null;
  };

  while (i < text.length) {
    tick();
    const char = text[i];
    const arm = cases.at(-1);
    if (char === " " || char === "\t") {
      i += 1;
      continue;
    }
    if (char === "\\" && text[i + 1] === "\n") {
      i += 2;
      continue;
    }
    // A comment (a `#` starting a word) runs to the end of the line.
    if (char === "#") {
      const end = text.indexOf("\n", i);
      i = end === -1 ? text.length : end;
      continue;
    }
    // A newline ends the command; heredocs opened on the line take the lines after it.
    if (char === "\n") {
      endCommand(false);
      i += 1;
      if (pending.length > 0) {
        const { bodies, next } = readBodies(text, i, pending);
        pending.forEach((doc, k) => {
          const body = bodies[k] ?? "";
          doc.command.heredocs.push({ body, expands: doc.expands, delim: doc.delim });
          if (doc.expands) scanExpansions(body);
        });
        pending = [];
        i = next;
      }
      continue;
    }
    // A `case` arm's pattern (`a|b)`, `(x)`): its words up to the `)` run nothing.
    if (arm === "pattern" && (char === "(" || char === "|" || char === ")")) {
      if (char === ")") {
        command = newCommand(false);
        cases[cases.length - 1] = "body";
      }
      i += 1;
      continue;
    }
    // `;;`, `;&`, `;;&` end a `case` arm; the next pattern follows.
    if (arm === "body" && char === ";" && (text[i + 1] === ";" || text[i + 1] === "&")) {
      endCommand(false);
      i += text[i + 1] === ";" && text[i + 2] === "&" ? 3 : 2;
      cases[cases.length - 1] = "pattern";
      continue;
    }
    // `f() …` / `function f() …` define a function: the `()` is no subshell.
    if (char === "(") {
      let close = i + 1;
      while (text[close] === " " || text[close] === "\t") close += 1;
      const named = command.words.length === 1 || (command.words.length === 2 && command.words[0]?.value === "function");
      if (text[close] === ")" && named && command.tokens.length === command.words.length && /^[A-Za-z_][\w.:-]*$/.test(command.words.at(-1)?.value ?? "")) {
        command.funcdef = true;
        endCommand(false);
        i = close + 1;
        continue;
      }
      endCommand(false);
      opens += 1;
      i += 1;
      continue;
    }
    // A `)` closes the subshell the command before it ran in.
    if (char === ")") {
      if (filled(command)) command.closes += 1;
      else if (commands.length > 0) (commands.at(-1) ?? command).closes += 1;
      endCommand(false);
      i += 1;
      continue;
    }
    // Command separators: ; & && || end a command; | and |& feed the next one. A lone `&` runs it in the background.
    if (char === ";" || (char === "&" && text[i + 1] !== ">")) {
      if (char === "&" && text[i + 1] !== "&") command.background = true;
      endCommand(false);
      i += char === "&" && text[i + 1] === "&" ? 2 : 1;
      continue;
    }
    if (char === "|") {
      if (text[i + 1] === "|") {
        endCommand(false);
        i += 2;
      } else {
        endCommand(true);
        i += text[i + 1] === "&" ? 2 : 1;
      }
      continue;
    }
    // Redirects (process substitution `<(…)` is a word, below).
    if (((char === "<" || char === ">") && text[i + 1] !== "(") || char === "&") {
      const at = fd?.start ?? i;
      const prefix = fd?.value ?? "";
      fd = null;
      begin(at);
      // `<<<word`: the word is fed on stdin.
      if (text.startsWith("<<<", i)) {
        i += 3;
        const glued = !/[ \t]/.test(text[i] ?? "");
        const word = readWord();
        if (word) command.herestrings.push(word);
        redirect(`${prefix}<<<`, word, glued, at);
        command.end = i;
        continue;
      }
      // `<<EOF`: a heredoc, whose body follows the next newline.
      const opener = heredocAt(text, i);
      if (opener) {
        pending.push({ ...opener, command });
        const operator = opener.strip ? "<<-" : "<<";
        redirect(prefix + operator, { value: opener.delim, dollar: false, start: i + operator.length }, !/[ \t]/.test(text[i + operator.length] ?? ""), at);
        i = opener.end;
        command.end = i;
        continue;
      }
      // Any other redirect: the operator, then its target (read, so a substitution in it is still seen).
      const from = i;
      while (/[<>&]/.test(text[i] ?? "")) i += 1;
      if (text[i] === "|" && text[i - 1] === ">") i += 1;
      const operator = text.slice(from, i);
      const glued = !/[ \t]/.test(text[i] ?? "");
      const target = readWord();
      // `bash < <(X)`: the command reads X's output on stdin.
      if (operator === "<" && target?.proc?.dir === "<") command.stdinProcs.push(target.proc.text);
      redirect(prefix + operator, target, glued, at);
      command.end = i;
      continue;
    }
    const word = readWord();
    if (word === null) {
      i += 1;
      continue;
    }
    // A file descriptor glued to a redirect (`2>`, `2>&1`) belongs to the redirect, not the command.
    if (/^\d+$/.test(word.value) && word.end - word.start === word.value.length && (text[i] === "<" || text[i] === ">")) {
      fd = word;
      continue;
    }
    // `esac` where a pattern or a command would start closes the innermost case.
    if (arm !== undefined && command.tokens.length === 0 && word.value === "esac" && !word.dynamic) {
      cases.pop();
      continue;
    }
    begin(word.start);
    command.end = word.end;
    command.words.push(word);
    token(word.value, word.dollar, word.start);
    // `case WORD in` opens a case: its first pattern follows.
    if (arm !== "pattern" && command.words.length === 3 && word.value === "in" && !word.dynamic && command.words[0]?.value === "case" && command.words[0]?.dynamic === false) {
      endCommand(false);
      cases.push("pattern");
    }
  }
  endCommand(false);
  return { commands, nested };
};

// A command line's tokens, every command's in order (parseLine()): what an exemption compares.
export const words = (line) => parseLine(line).commands.flatMap((command) => command.tokens);

// A file's key for `written`: its path from the hook's cwd (`at` is the command's directory), normalized.
const fileKey = (at, path) => normalize(isAbsolute(path) || path.startsWith("~") ? path : join(at ?? "", path));

// Index of the program in a command's tokens, as the database rules read it: past `VAR=value`,
// `sudo`, `npx`, `pnpm` / `pnpm exec` and friends (the wrappers prefixOf() models).
const programStart = (list) => {
  let start = 0;
  // Walk past environment assignments and wrapper words.
  while (start < list.length) {
    tick();
    const word = list[start] ?? "";
    const name = programName(word);
    // By basename, so `/usr/bin/env git push …` is read past its `env` too.
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(word) || PREFIXES.has(name)) start += 1;
    else if (/^(pnpm|yarn|npm)$/.test(name) && list[start + 1] === "exec") start += 2;
    else if (/^(pnpm|yarn)$/.test(name)) start += 1;
    // `doppler run -- cmd`, `dotenv -e f -- cmd`: the program is the one after `--`.
    else if (LOADERS.test(word) && list.indexOf("--", start) !== -1) start = list.indexOf("--", start) + 1;
    else break;
  }
  return start;
};

// The command with those prefixes removed, so a rule can match the program that actually runs at
// the start of the string.
// The program word is case folded (programName()'s reading), so `GIT push` reads as `git push`.
const commandText = (list) => {
  const [program = "", ...rest] = list.slice(programStart(list));
  return [foldAscii(program), ...rest].join(" ");
};

// Tokens split again at blanks, the way a command's text re-read as words splits (`cd "a b"` is two
// words to the `cd` reading, so it loses track rather than guess).
const blankSplit = (list) => list.flatMap((word) => word.split(/\s+/).filter(Boolean));

// gh's flags that may come before its subcommand (`gh -R o/r pr merge 1`), with or without `=`.
const GH_REPO_FLAG = /^(-R|--repo)$/;
const GH_REPO_GLUED = /^(-R.|--repo=)/;

// A program's words as the built-in git, gh, and delete rules read them: the program by its
// basename (`/usr/bin/git` and `git.exe` are git), and gh's `-R`/`--repo` taken out from in front
// of its subcommand. Not for project rules: one may match a program's path (`^\./scripts/deploy`).
const programArgv = (list) => {
  const argv = [...list];
  if (argv.length === 0) return argv;
  argv[0] = programName(argv[0] ?? "").replace(/\.exe$/i, "");
  if (argv[0] === "gh") {
    let at = 1;
    while (at < argv.length && (GH_REPO_FLAG.test(argv[at] ?? "") || GH_REPO_GLUED.test(argv[at] ?? ""))) at += GH_REPO_FLAG.test(argv[at] ?? "") ? 2 : 1;
    argv.splice(1, at - 1);
  }
  return argv;
};

// The whole command as a rule's `unless` reads it: prefixes kept (quotes and spacing aside), and a
// `VAR=` dropped when the same VAR is assigned again before the program, because the shell keeps the last.
const asAssigned = (list) => {
  const start = programStart(list);
  // Where each variable is last assigned in the prefix: one pass, so 50k `A=1` words stay linear.
  const last = new Map();
  for (let index = 0; index < start; index += 1) {
    tick();
    const name = assigned(list[index] ?? "");
    if (name !== undefined) last.set(name, index);
  }
  // Keep every word, except an assignment whose variable is assigned again later in the prefix.
  return list.filter((word, index) => index >= start || assigned(word) === undefined || last.get(assigned(word)) === index).join(" ");
};

// The variable a `VAR=value` word assigns, or undefined.
const assigned = (word) => /^([A-Za-z_][A-Za-z0-9_]*)=/.exec(word)?.[1];

// The value a `VAR=value` word assigns (the parser has already removed its quotes).
const assignedValue = (word) => word.slice(word.indexOf("=") + 1);

// Verdict for one command line: { decision: "deny" | "ask", reason } or null to let it run.
// `branch` is the branch where the hook runs; `branchIn(dir)` reads it for a `cd X` / `git -C X`
// directory, relative to there (empty string when unknown). `shipFreezeIn(dir)` reads the
// freeze marker there the same way (`shipFreezeIn(dir, file)`, file a set's marker name; shipFreeze();
// null when none). `rules` is loadRules()' result; the rule sets come with it (`rules.sets`), or, when
// a caller hands in rules of its own without them, from this script's folder (defaultSets()), so a
// caller's rules never drop the sets' rules, as they never dropped the built-in ones.
// `limits` the size and time budgets (LIMITS), which a test may widen to time one parser path.
// Every other option reaches the line evaluator and each nested line unchanged, so a rule added
// later gets its own lookups without evaluate() naming them.
//
// The database rules read the disk where a command runs (`dir` is null for the hook's cwd, else a
// `cd` target relative to it): `targetIn(dir, name, file, useEnv)` gives a variable's value and
// where it came from ({ value, from }, or null when unset), from the environment (skipped when
// `useEnv` is false) and then the dotenv `file` (default .env; null for the environment only);
// `scriptIn(dir, name)` a package.json script's command ("" when none); `fileIn(dir, path)` a file's
// text (null when missing, not a regular file, unreadable, or too big; null by default, so a caller
// that reads no files gets an ask for SQL it can't read, never an allow); `dirExists(dir)` whether a
// `cd` target is a directory; `dirIn(dir, path)` what a directory holds, for a multi-file Prisma
// schema (null when nothing is there; { dir: false } for something that isn't a directory; else
// { dir: true, files, dirs, more }, `more` when it holds more than the guard lists; null by
// default, so a caller that lists nothing gets an ask for a reset whose schema it can't read).
//
// Fails closed to ask (main()): over a budget, or on any exception, naming it.
export const evaluate = (command, { limits = LIMITS, ...options } = {}) => {
  const { branch = "", branchIn = () => "", rules = NO_RULES } = options;
  // Callers may pass a partial limits object, so the wall-clock backstop falls back to its default.
  const wallMs = /** @type {{ wallMs?: number }} */ (limits).wallMs ?? MAX_EVALUATE_WALL_MS;
  // A rule file that didn't load refuses everything, so a typo can't switch the project's rules off.
  if (rules.error !== "") return deny(rules.error);
  // So does a rule set that didn't load: its rules would be missing without a word.
  const sets = rules.sets ?? defaultSets();
  if (sets.error !== "") return deny(sets.error);
  if (command.length > limits.chars) {
    return ask(`This command line is ${command.length} characters, over the guard's ${limits.chars}-character budget, so it wasn't read; the user confirms it. A big file belongs in a file write, not a heredoc.`);
  }
  // A nested call (exemption() checking a rule file) keeps the outer budget.
  const outer = budget === null;
  if (outer) {
    const { now = () => performance.now(), cpu = cpuNow } = limits;
    budget = { now, cpu, cpuEnd: cpu() + limits.ms, wallEnd: now() + wallMs };
  }
  try {
    // One lookup per directory however many commands run there (`cd .;` then 5000 commands), and
    // one SQL-read budget for the whole line, every nested line included (MAX_SQL_FILES, MAX_SQL_FILE_BYTES).
    return evaluateLine(command, { ...options, branch, branchIn, rules, sets, guard: rules.guard ?? defaultGuard(), lookups: new Map(), sqlBudget: { files: 0, bytes: 0 } });
  } catch (error) {
    // Defensive, likely unreachable: vm's timeout terminates the script and does not run this
    // catch, but if a runtime ever surfaces it here, main() still answers it, naming the watchdog.
    if (watchdogFired(error)) throw error;
    if (error instanceof OverBudget && error.kind === "wall") return ask(`Reading this command line took more than ${wallMs} ms of wall-clock time (the guard's backstop for a read that blocks), so it stopped; the user confirms it.`);
    if (error instanceof OverBudget) return ask(`Reading this command line used more than the guard's ${limits.ms} ms budget of CPU time, so it stopped; the user confirms it.`);
    if (error instanceof TooDeep) return ask(`This command line nests \`$(\`, \`\${\`, or quotes more than ${MAX_SCAN_NESTING} levels deep, deeper than the guard reads; the user confirms it.`);
    return ask(`The guard failed reading this line (${error instanceof Error ? error.message : String(error)}), so the user confirms it. Tell the user: a guard bug must not let a command through unseen.`);
  } finally {
    if (outer) budget = null;
  }
};

// evaluate() without the budgets. `depth` counts substitutions followed for the git and rule checks;
// `infra` is false for a nested line, which evaluateInfra() already read from the top-level one.
// `options` is evaluate()'s, passed whole to each nested line so options added later survive.
//
// A line the rules follow (`sh -c`, `eval`, a package script, `ssh h …`) comes back here through
// nested(), with: `startDir` and `env` (the parent's `cd` and variables); `nesting` (MAX_NESTING);
// `lost` (the parent did something the guard can't follow, such as `source`, `eval`, or a loader,
// so no database variable is known); `wrapped` (it runs behind a wrapper the guard doesn't model:
// `pnpm --filter`, `doppler --command`); `remote` (on another machine or in a container: `ssh`,
// `docker exec`, where no local file, .env, or loopback host means anything); `container` (run in a
// local container, `docker compose exec db psql …`, so the floor asks: the container's own database
// is most likely the dev one, but the guard can't read it); `written` (files an earlier command on
// the line writes); `sqlBudget` (the line's SQL reads so far). `sets` is the loaded rule sets (evaluate()).
const evaluateLine = (command, options) => {
  const { branch, rules, sets, guard = defaultGuard(), depth = 0, infra = true, targetIn = () => null, scriptIn = () => "", fileIn = () => null, dirIn = () => null, dirExists = () => true, startDir = null, env = new Map(), nesting = 0, lost: lostIn = false, wrapped = false, remote = false, container = false, written: writtenIn = new Set(), sqlBudget = { files: 0, bytes: 0 } } = options;
  // Nested past MAX_NESTING: one prompt costs less than reading on past the hook's timeout.
  if (nesting > MAX_NESTING) return ask(`This line nests \`eval\`, \`sh -c\`, or scripts more than ${MAX_NESTING} deep, so the guard stopped reading it: confirm what it runs.`);
  const branches = rules.branches ?? sets.branches;
  // Rule-set rows read as a pack's are (no `on`), ahead of the pack and project rules.
  const ruled = sets.deny.length + sets.ask.length === 0 ? rules : { deny: [...sets.deny, ...rules.deny], ask: [...sets.ask, ...rules.ask] };
  const verdicts = [];
  // The directory later commands run in, after any `cd`; null means the hook's own cwd.
  let dir = startDir;
  // Where the last `cd` left from, for `cd -`; undefined until this line moves (the shell's OLDPWD is unseen).
  let oldDir;
  // True once a `cd`, `pushd`, or `popd` has run on this line: an exemption names one command in
  // the directory the hook runs in, so after a move it no longer lifts anything.
  let moved = false;
  // `pushd` and `( … )` directories to go back to.
  const pushed = [];
  const subshells = [];
  // Subshells that close at the end of the previous command, so the next one runs back outside them.
  let closing = 0;
  // `{ … }` groups and function bodies open here, innermost last: a function body runs only when
  // (and if) the function is called, so a `cd` in it can't be placed and loses track.
  const braces = [];
  // True right after a function's name (`f()`, `function f`): the `{` that follows is its body, not a group.
  let defining = false;
  // Variables set for later commands on this line (`export X=v`); null means "set to something
  // unseen", UNSET means `unset X` (the tool then reads its .env, not the environment).
  const lineEnv = new Map(env);
  // True once the line did something that sets variables or moves directories in a way the guard can't read.
  let lost = lostIn;
  // From here on no database variable is known: each is set to something unseen.
  const loseTrack = () => {
    lost = true;
    for (const name of DB_VARS) lineEnv.set(name, null);
  };
  if (lost) loseTrack();
  // Files an earlier command on this line writes (`>`, `cp`, `tee`, a heredoc into a file): what
  // is on disk now is not what a later `psql -f` will read, so those count as unreadable.
  const written = new Set(writtenIn);
  const readAt = (at, path) => (remote || written.has(fileKey(at, path)) ? null : fileIn(at, path));
  // A directory's listing (dirIn), or, when an earlier command on the line writes into it, one
  // that holds more than can be read: what a later reader finds there is not what is on disk now.
  const listAt = (at, path) => {
    if (remote) return null;
    const key = fileKey(at, path);
    for (const each of written) {
      tick();
      if (each === key || each.startsWith(`${key}/`)) return { dir: true, files: [], dirs: [], more: true };
    }
    return dirIn(at, path);
  };
  // A SQL file for a client, within the line's one budget (every client and nested line share it):
  // past MAX_SQL_FILES reads or MAX_SQL_FILE_BYTES in all, nothing more is opened and it is unreadable.
  const readSqlAt = (at, path) => {
    if (sqlBudget.files >= MAX_SQL_FILES || sqlBudget.bytes > MAX_SQL_FILE_BYTES) return null;
    sqlBudget.files += 1;
    const text = readAt(at, path);
    if (text === null) return null;
    sqlBudget.bytes += text.length;
    return sqlBudget.bytes > MAX_SQL_FILE_BYTES ? null : text;
  };
  // A variable as a command here sees it (in front of it, earlier on the line, the environment):
  // undefined when unset, null when set to something unseen.
  const varAt = (name, prefix = null) => {
    const own = prefix?.vars.has(name) ? prefix.vars.get(name) : prefix?.cleared === true ? UNSET : lineEnv.has(name) ? lineEnv.get(name) : targetIn(dir, name, null)?.value;
    return own === UNSET ? undefined : own;
  };
  // The previous command on the line ({ list, expands, heredocs, head }): what a SQL client with no
  // SQL of its own may be reading from a pipe.
  let previous = null;
  // Branches where this line commits, for the [skip ci] rule (null = couldn't tell).
  const commitBranches = [];
  // The branch for a command in `at`, or the hook's branch when it hasn't moved. Each directory is
  // looked up once (memoized for the whole line), and the clock is read right after, because one
  // lookup can take as long as the whole budget and tick() only reads it every 1024 steps.
  const branchAt = (at) => {
    if (at === null) {
      if (typeof branch !== "function") return branch;
      // The hook's branch, read the first time a rule needs it (a push or a commit parsed from the line, however its program word is spelled), then kept.
      if (!options.lookups.has(null)) {
        options.lookups.set(null, branch());
        checkClock();
      }
      return options.lookups.get(null);
    }
    if (!options.lookups.has(at)) {
      options.lookups.set(at, options.branchIn(at));
      checkClock();
    }
    return options.lookups.get(at);
  };
  // The freeze marker `file` for a command in `at` (null for none), looked up once per directory like branchAt.
  const freezeAt = (at, file) => {
    const key = `\0freeze:${file}:${at ?? ""}`;
    if (!options.lookups.has(key)) {
      options.lookups.set(key, (options.shipFreezeIn ?? (() => null))(at, file));
      checkClock();
    }
    return options.lookups.get(key);
  };
  // Judges a line this one runs (`sh -c`, a package script, `ssh h …`) where this one has got to,
  // through evaluateLine() so the outer budget and the line's SQL budget hold.
  const nested = (line, extraEnv, extra = {}) =>
    evaluateLine(line, {
      ...options,
      branch: branchAt(extra.dir ?? dir),
      startDir: extra.dir ?? dir,
      env: new Map([...lineEnv, ...extraEnv]),
      nesting: nesting + 1,
      lost: lost || extra.lost === true,
      wrapped: wrapped || extra.wrapped === true,
      remote: remote || extra.remote === true,
      container: extra.container ?? container,
      written,
      infra: false,
    });

  const { commands, nested: substitutions } = parseLine(command);
  for (const parsed of commands) {
    tick();
    // Leave the subshells the previous command closed, and enter the ones this one opens: a `cd`
    // inside `( … )` lasts until its `)`. (`pop() ?? dir` would keep the inner dir when the outer one is null.)
    for (; closing > 0 && subshells.length > 0; closing -= 1) dir = subshells.pop() ?? null;
    for (let n = 0; n < parsed.opens; n += 1) subshells.push(dir);
    closing = parsed.closes;
    // A function's name: its body runs only when (and if) it is called.
    if (parsed.funcdef) {
      braces.push("function");
      defining = true;
      continue;
    }
    // Keywords in front of the command: `{ … }` and `!` run it in this shell, so a `cd` counts;
    // behind `if`/`then`/`while`/`do`, in a `case` arm, or in a function body it may not run, so a
    // `cd` there loses track.
    let k = 0;
    let conditional = false;
    for (;;) {
      const word = parsed.tokens[k];
      if (word === "{") {
        if (!defining) braces.push("group");
        defining = false;
      } else if (word === "function" && k + 1 < parsed.tokens.length) {
        braces.push("function");
        defining = true;
        k += 1;
      } else if (/^(if|then|else|elif|while|until|do)$/.test(word ?? "")) conditional = true;
      else if (word !== "!") break;
      k += 1;
    }
    defining = false;
    if (parsed.inCase || braces.includes("function")) conditional = true;
    const list = parsed.tokens.slice(k);
    // A closing word on its own (`}`, `fi`, `done`) runs nothing; `}` closes what it opened. A
    // `case x in` header runs nothing either (parseLine() reads its arms).
    if (list.length === 0 || (list.length === 1 && /^(\}|fi|done|esac)$/.test(list[0] ?? "")) || list[0] === "case") {
      if (list[0] === "}") braces.pop();
      continue;
    }
    const expands = parsed.expands.slice(k);
    // The command as typed (line continuations joined), and with its heredoc bodies after it: what
    // the whole-command rules read (a set's own switches, a GraphQL query, a store's delete).
    const head = command.slice(parsed.starts[k], parsed.end).replace(/\\\n/g, "");
    const segment = parsed.heredocs.length === 0 ? head : `${head}\n${parsed.heredocs.map((doc) => `${doc.body}\n${doc.delim}`).join("\n")}`;
    const text = commandText(list);
    if (/^(cd|pushd|popd)(\s|$)/.test(text)) moved = true;
    const before = previous;
    previous = { list, expands, heredocs: parsed.heredocs, head };
    // What this command writes, for a later `psql -f` on the line.
    for (const path of writes(list)) written.add(fileKey(dir, path));
    // `VAR=value` words in front of this command, as the shell will set them for it.
    const start = programStart(list);
    const inline = new Map(list.slice(0, start).filter((word) => assigned(word) !== undefined).map((word) => [assigned(word), assignedValue(word)]));
    // `cd X` / `pushd X` moves every later command on this line. A form the guard can't follow
    // (`$X`, CDPATH, a directory that isn't there, `cd a b`, behind `if`, a HOME the line set)
    // loses track: the directory is a best guess and every database variable counts as unseen.
    // In the background (`cd x &`) it runs in a subshell: whatever it sets or moves, the guard loses track.
    if (parsed.background && (/^(cd|pushd|popd|export|unset|source|\.|set|read|declare|typeset|local)(\s|$)/.test(text) || (text === "" && inline.size > 0))) {
      loseTrack();
      continue;
    }
    const cd = /^(cd|pushd)(?:\s+|$)/.exec(text);
    if (cd) {
      const args = blankSplit(list.slice(start + 1));
      // `cd -P x`, `cd -L x`, `cd -- x`: options before the directory.
      let at = 0;
      while (at < args.length && /^(-[LPe@]+|--)$/.test(args[at] ?? "")) at += 1;
      const target = args.at(at);
      let unsure = conditional || args.length > at + 1;
      // `HOME=x` or `export HOME=x` earlier: `cd` and `~` go there, not to the home the guard reads.
      const homeSet = lineEnv.has("HOME") || inline.has("HOME");
      let next = dir;
      if (target === undefined) {
        // Bare `cd` goes home; bare `pushd` swaps the top two directories.
        if (cd[1] === "cd") next = "~";
        else unsure = true;
        if (homeSet) unsure = true;
      } else if (target === "-") {
        if (oldDir === undefined) unsure = true;
        else next = oldDir;
      } else {
        // A variable, or `pushd +1`, is only known when it runs.
        if (/[$`]/.test(target) || /^[+-]\d/.test(target)) unsure = true;
        if (target.startsWith("~") && homeSet) unsure = true;
        // With CDPATH set, a bare name may be found under one of its entries instead.
        const cdpath = varAt("CDPATH", prefixOf(list.slice(0, start)));
        if (cdpath !== undefined && cdpath !== "" && !isAbsolute(target) && !/^(\.\.?(\/|$)|~)/.test(target)) unsure = true;
        next = dir === null || isAbsolute(target) || target.startsWith("~") ? target : join(dir, target);
      }
      if (!unsure && next !== null && !dirExists(next)) unsure = true;
      if (cd[1] === "pushd") pushed.push(dir);
      oldDir = dir;
      dir = next;
      if (unsure) loseTrack();
      continue;
    }
    if (/^popd\b/.test(text)) {
      if (pushed.length === 0) loseTrack();
      else dir = pushed.pop() ?? null;
      continue;
    }
    // `export X=v`, or a line of bare `X=v`, sets X for every later command on this line. A value the
    // guard can't read (`$(…)`, `$X`) is unseen, and `export $(cat f | xargs)` sets who knows what.
    const exported = /^export\s/.test(text);
    if (exported || (text === "" && inline.size > 0)) {
      for (const word of exported ? blankSplit(list.slice(start + 1)) : list) {
        tick();
        const name = assigned(word);
        if (name !== undefined) lineEnv.set(name, /[$`]/.test(assignedValue(word)) ? null : assignedValue(word));
        else if (!word.startsWith("-")) loseTrack();
      }
      continue;
    }
    // `unset X` clears X for every later command on this line (`unset -f` clears functions).
    if (/^unset\s/.test(text)) {
      const names = blankSplit(list.slice(start + 1));
      if (!names.includes("-f")) for (const name of names) if (!name.startsWith("-")) lineEnv.set(name, UNSET);
      continue;
    }
    // `source f` / `. f`, `set -a`, `read X < f` and friends can set any variable to anything.
    if (/^(source|\.)\s/.test(text) || /^(read|mapfile|readarray|declare|typeset|local)\b/.test(text) || /^set\s+(-\w*a\b|-o\s+allexport\b)/.test(text)) {
      loseTrack();
      continue;
    }
    // What the command runs through its wrappers (runs()): each program, for the git, GitHub, and
    // delete rules below, and each line a wrapper runs (`sh -c '…'`, `eval`, `env -S`, `ssh h '…'`,
    // a shell fed a heredoc), judged as a line of its own. `eval` runs what the guard can only partly read.
    const targets = runs(parsed.words);
    const followed = new Set();
    const follow = (line, extra) => {
      if (followed.has(line)) return;
      followed.add(line);
      const inner = nested(line, inline, extra);
      if (inner) verdicts.push(inner);
    };
    for (const target of targets) {
      if (target.line === undefined && target.stdin !== true) continue;
      if (target.via === "eval") loseTrack();
      const extra = SHELL.test(target.via ?? "") ? {} : (LINE_FLAGS[target.via ?? ""] ?? { lost: true, wrapped: true });
      for (const line of target.line === undefined ? fedLines(parsed, before) : [target.line]) follow(line, extra);
    }
    // `ssh h psql …`, `kubectl exec p -- psql …`, `watch psql …`: a line run behind a wrapper the
    // guard doesn't model, judged on its own with every variable unseen.
    for (const line of handedOn(list)) follow(line.text, { lost: true, wrapped: true, remote: line.remote, container: line.container });
    // `doppler run --command "…"` and friends run a line behind variables the guard can't see.
    for (const [index, word] of list.entries()) {
      tick();
      const value = word.startsWith("--command=") ? word.slice("--command=".length) : word === "--command" && clientAt(list) === -1 ? list[index + 1] : undefined;
      if (value !== undefined) follow(value, { lost: true, wrapped: true });
    }
    // `pnpm db:reset` / `npm run db:reset` runs package.json's command for it, plus any arguments after;
    // `pnpm -C dir` / `--dir` runs it there, and `--filter` / `-r` in packages the guard can't see.
    const run = packageScript(list) ?? scriptCall(text);
    const runDir = run?.dir === undefined || run.dir === null ? dir : isAbsolute(run.dir) ? run.dir : join(dir ?? "", run.dir);
    // `pnpm -C dir exec …` runs a command there; a script name runs package.json's command for it
    // (that dir's, else this one's, so a missing package.json can't hide it).
    const script = run === null || nesting >= 3 ? "" : run.line ?? (scriptIn(runDir, run.name ?? "") || (runDir === dir ? "" : scriptIn(dir, run.name ?? "")));
    if (script !== "") {
      const inner = nested(`${script}${run?.rest ?? ""}`, inline, { dir: runDir, wrapped: run?.wrapped === true });
      if (inner) verdicts.push(inner);
    }
    // A SQL client: where it connects, and the SQL it runs (its own; a heredoc's words aren't its flags).
    const client = clientAt(list);
    if (client !== -1) {
      // PGHOSTADDR / PGSERVICE as psql sees them: in front of it, set earlier on the line, or in the environment.
      const prefix = prefixOf(list.slice(0, client));
      const heredoc = parsed.heredocs.length === 0 ? null : parsed.heredocs.map((doc) => doc.body).join("\n");
      const heredocExpands = parsed.heredocs.some((doc) => doc.expands && /[$`]/.test(doc.body));
      const judged = sqlClient(list.slice(client), { readFile: (path) => readSqlAt(dir, path), heredoc, heredocExpands, piped: before, pgHost: pgHostKinds((name) => varAt(name, prefix)), pgDefault: pgDefaultKinds((name) => varAt(name, prefix)), expands: expands.slice(client) });
      // On another machine, its "localhost" is that machine's database.
      verdicts.push(judgeSql(remote && judged.kind === "loopback" ? { ...judged, kind: "unknown" } : judged));
    }
    // A migration tool's verdict depends on where it points: the line, this command's variables, then the environment.
    const migrate = evaluateMigrate(list, lineEnv, {
      wrapped: wrapped || remote,
      targetIn: (name, file, useEnv) => targetIn(dir, name, file, useEnv),
      readIn: (path) => readAt(dir, path),
      listIn: (path) => listAt(dir, path),
    });
    // The command's words after the shell's quote and escape removal (redirect targets included), ASCII-lowered.
    const heredocText = parsed.heredocs.map((doc) => `${doc.body}\n${doc.delim}`);
    const decoded = foldAscii([list.join(" "), ...heredocText].join("\n"));
    const found = [...segmentVerdicts(segment, decoded, sets), migrate, guardWrites(list, dir, guard)];
    // The same words with the variables this line set earlier filled in (`c=x; pnpm $c tick`), read by the same text rules;
    // and a write whose target is a pattern that could name a set's marker file (markerWrites()).
    const fill = filledWith(lineEnv);
    const filledList = list.map(fill);
    if (filledList.some((word, index) => word !== list[index]) || fill(segment) !== segment) {
      found.push(...segmentVerdicts(fill(segment), foldAscii([filledList.join(" "), ...heredocText].join("\n")), sets));
    }
    found.push(markerWrites(filledList, sets.markerFiles));
    // A guard file named through a variable the line set (`d=.reins; rm -rf $d`).
    if (filledList.some((word, index) => word !== list[index])) found.push(guardWrites(filledList, dir, guard));
    // A pre-push opt-out (a set's `pushEnvDeny`), set for this push in front of it, earlier on the line, or as the command's own prefix.
    const skipping = sets.pushEnvDeny.find((name) => inline.has(name) || (lineEnv.has(name) && lineEnv.get(name) !== UNSET) || segment.trim().startsWith(`${name}=`));
    const skipDeny = () => deny(`${skipping} skips the pre-push checks; only the user bypasses them.`);
    // Read as typed and as decoded and folded (`GIT push`, `g''it push`); the programs below are read too.
    if (skipping !== undefined && (/\bgit\b.*\bpush\b/.test(segment) || /\bgit\b.*\bpush\b/.test(decoded))) found.push(skipDeny());
    // A data store's own delete (FLUSHALL, dropDatabase, a remote D1 DROP), judged by where it points;
    // on another machine, its "localhost" is that machine's.
    found.push(evaluateStore(programArgv(list.slice(start)), { text: `${before?.head ?? ""}\n${segment}`, readFile: (path) => readSqlAt(dir, path), remote }), ownPackage(list));
    // Each program the command runs, past its wrappers: the policy table, then the push, git
    // config, and gh api rules. `git -C X …` runs in X for that program only (each `-C` from the one
    // before); `--git-dir` or `--work-tree` points it at a repository whose branch isn't looked up.
    // The push rule asks for the branch only when it needs it, so plain commands look nothing up.
    const programs = targets.filter((target) => target.argv !== undefined).map((target) => target.argv.map((word) => word.value));
    for (const program of programs) {
      const argv = programArgv(program);
      const git = argv[0] === "git" ? gitGlobals(argv) : null;
      const at = (git?.dirs ?? []).reduce((from, target) => (isAbsolute(target) ? target : join(from ?? "", target)), dir);
      const gitBranch = () => (git?.elsewhere === true ? "" : branchAt(at));
      if (skipping !== undefined && git !== null && argv[git.sub] === "push") found.push(skipDeny());
      if (/^git\b.*\bcommit\b/.test(argv.join(" "))) commitBranches.push(gitBranch());
      found.push(...policyVerdicts(argv.join(" "), sets.program), evaluatePush(argv, gitBranch, branches, (file) => (git?.elsewhere === true ? null : freezeAt(at, file)), sets.freezeMarkers), evaluateGitConfig(argv, sets.gitConfigAsk), evaluateGhApi(argv, segment, branches, sets), evaluateGhVariable(argv, sets.repoVariables));
      // The program again with this line's variables filled in, for the text rules and `gh api`'s.
      const filledArgv = argv.map(fill);
      if (filledArgv.some((word, index) => word !== argv[index])) found.push(...policyVerdicts(filledArgv.join(" "), sets.program), evaluateGhApi(filledArgv, fill(segment), branches, sets), evaluateGhVariable(filledArgv, sets.repoVariables));
    }
    // Rule-set rows read as a pack's are, then pack and project rules, when there are any: `match`
    // reads the program text (prefixes removed, heredoc words after it) and each program run behind a
    // wrapper; `unless` the whole command.
    if (ruled.deny.length + ruled.ask.length > 0) {
      const typed = asAssigned(list);
      const bodies = parsed.heredocs.flatMap((doc) => blankSplit([doc.body, doc.delim]));
      // Each read as typed too: a project's rule may match a program's exact case or path.
      const raw = list.slice(start).join(" ");
      const texts = new Set([[text, ...bodies].join(" "), raw, ...programs.flatMap((program) => [program.join(" "), programArgv(program).join(" ")])]);
      for (const each of texts) found.push(...ruleVerdicts(ruled, each, typed));
    }
    // An exemption lifts only a data-delete deny (the built-in delete list or a pack's) of exactly this command.
    const exempt = !moved && rules.allow.size > 0 && rules.allow.has(JSON.stringify(list));
    verdicts.push(...found.filter((verdict) => !(exempt && verdict?.liftable === true)));
  }

  // Substitutions run too (`echo "$(git push -f origin main)"`); an exemption lifts only a command typed at the top level.
  if (depth < MAX_DEPTH) {
    for (const text of substitutions) {
      verdicts.push(evaluateLine(text, { ...options, rules: { ...rules, allow: new Set() }, depth: depth + 1, infra: false }));
    }
  }

  // A commit message that skips CI (a set's `skipCi`) is safe only on the branches it allows; on a PR
  // branch it strands required checks. Read from the whole line, because a heredoc commit message
  // spans what looks like commands. `{branch}` in the reason names the branch.
  for (const skip of sets.skipCi) {
    if (!skip.match.test(command)) continue;
    for (const where of commitBranches) {
      // Couldn't read the branch: the user decides, rather than a deny that blocks a real commit on an allowed branch.
      if (where === "") verdicts.push(ask(skip.unreadable));
      else if (!skip.allowOn.includes(where)) verdicts.push(deny(skip.reason.replaceAll("{branch}", () => where)));
    }
  }

  // The floor under the per-client reading above (FLOOR_*): a SQL client at command position,
  // destructive SQL anywhere on the line (a heredoc body included), and no loopback word on it.
  // The per-client reading may make a line stricter than this, never looser. The one exception: a
  // line a local container runs (`docker compose exec db psql -c "DROP …"`) asks, since no host
  // inside it is the container's own database, most likely the dev one; a remote host still denies (judgeSql).
  if (FLOOR_DESTRUCTIVE_SQL.test(command) && !FLOOR_LOOPBACK.test(command) && commands.some((each) => FLOOR_SQL_CLIENT.test(commandText(each.tokens)))) {
    if (container) verdicts.push(ask("Destructive SQL inside a container: the guard can't see which database the container's client reaches, most likely its own dev one. Fine on loopback or a throwaway only: confirm the target."));
    else verdicts.push(deny("Destructive SQL against a non-loopback database is a human action. Write it, test it on localhost, and hand the user the command."));
  }

  // Applies, destroys, state surgery, and cloud deletes, read from the whole line (through wrappers,
  // substitutions, and a shell fed on stdin); an exemption lifts only its exact command.
  if (infra) verdicts.push(evaluateInfra(command, { allow: rules.allow, parsed: { commands, nested: substitutions } }));

  // GitHub's GraphQL can flip a ready PR back to draft too.
  if (/convertPullRequestToDraft/.test(command)) verdicts.push(deny(DRAFT_DENY));

  return strongest(verdicts);
};

// How a line a wrapper runs is read (nested()): a shell's (`sh -c`) is this line's own; `eval`'s
// and `env -S`'s are behind a wrapper the guard doesn't model; ssh's runs on another machine. Any
// other wrapper's (a loader's `--command`, `npx -c`) also hides its variables.
const LINE_FLAGS = { eval: { wrapped: true }, env: { wrapped: true }, ssh: { lost: true, wrapped: true, remote: true } };

// What a shell reading stdin runs: the heredocs and here-strings fed to it, or what an `echo` or
// `printf` before it pipes in (`echo 'git push …' | sh`).
const fedLines = (parsed, before) => {
  const fed = [...parsed.heredocs.map((doc) => doc.body), ...parsed.herestrings.map((word) => word.value)];
  const printer = before === null ? "" : programName(before.list[programStart(before.list)] ?? "");
  if (parsed.piped && /^(echo|printf)$/.test(printer)) fed.push(before.list.slice(programStart(before.list) + 1).filter((word) => !/^-[neE]+$/.test(word)).join(" "));
  return fed;
};

// Each act's reason, shared by its gh subcommand and the API road to the same act. The gh
// subcommands' rows for a ready PR, a rerun, and a dispatch are in the draft-flow and ci-minutes rule
// sets, with the same words; the API roads below are code, which no rule-set row can express.
const DRAFT_DENY = "Never flip a ready PR back to draft. Tell the user why you think it isn't ready.";
const MERGE_ASK = "Merging needs the user's OK for this batch.";
const RERUN_DENY = "Rerun only the failed jobs: `gh run rerun <id> --failed`, after reading the failure.";
const PATTERN_KILL_DENY = "A pattern kill (`pkill -f`, or `pkill`/`killall` of node or a browser) also hits other agents' runs on this machine. Kill by the PID you started.";
const DISPATCH_ASK = "A manual workflow run bills the full suite; say what it is for.";
// A package manager's verbs that add, remove, move, or patch a named package.
const PACKAGE_VERBS = new Set(["add", "remove", "rm", "uninstall", "un", "unlink", "link", "ln", "update", "up", "upgrade", "install", "i", "in", "isntall", "patch", "patch-commit"]);
const PACKAGE_MANAGERS = new Set(["pnpm", "npm", "yarn", "bun"]);

// Ask when a package manager adds, removes, updates, or patches the guard's own package (`reins`,
// `reins@1.2.3`): what judges every command after it would change. `list` is the command's words;
// assignments and prefixes (`sudo`, `env`) in front are read past.
const ownPackage = (list) => {
  let at = 0;
  while (at < list.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(list[at] ?? "") || PREFIXES.has(programName(list[at] ?? "")))) at += 1;
  if (!PACKAGE_MANAGERS.has(programName(list[at] ?? "").replace(/\.(exe|cmd)$/i, ""))) return null;
  const words = list.slice(at + 1).filter((word) => !word.startsWith("-"));
  if (!words.some((word) => PACKAGE_VERBS.has(word.toLowerCase()))) return null;
  return words.some((word) => word.toLowerCase() === PACKAGE_NAME || word.toLowerCase().startsWith(`${PACKAGE_NAME}@`)) ? ask(OWN_PACKAGE_ASK) : null;
};
const OWN_PACKAGE_ASK = "This changes the guard's own package, which judges every command after it: the user confirms, and the change goes in a reviewed PR.";
const DELETE_DENY = "Deleting data, a backup, or a key is a human action. Hand the user the exact command and what it destroys.";

// The built-in git and GitHub acts, in a project rule's shape: `match` reads each program the
// command runs (programArgv(), joined); `unless` reads the same text and lets the command pass. A
// `liftable` deny is a data delete, the one kind a project exemption may lift. What a pattern can't
// read is code below: a push's refspecs (evaluatePush), git config and aliases, and gh api's method
// and body. A rule set's rows with `on: "program"` or `"segment"` read the same way and come first
// (loadSets()); never liftable.
const POLICY = [
  // Merging is allowed with the user's OK for this batch, so the user decides here; the REST API's
  // road to the same act is read by evaluateGhApi().
  { match: /^gh\s+pr\s+merge\b/, verdict: "ask", reason: MERGE_ASK },
  // Several agents share one machine: a kill by pattern or by program name takes their runs down too.
  { match: /^pkill\b(?:.*\s)?(?:-\w*f\w*|--full)(?=\s|$)/, verdict: "deny", reason: PATTERN_KILL_DENY },
  { match: /^(?:pkill|killall)\b(?:.*\s)?(?:node|chrome|chromium|google\s+chrome)(?=\s|$)/i, verdict: "deny", reason: PATTERN_KILL_DENY },
  // Deleting data or a recovery point is a human action, wherever it points.
  ...ALWAYS_DESTRUCTIVE.map((match) => ({ match, verdict: "deny", liftable: true, reason: DELETE_DENY })),
];

// The verdicts of a table of rows (a rule set's `program` or `segment` rows, POLICY last) for one
// text: each program's, or the command as typed.
const policyVerdicts = (text, rows) =>
  rows.filter((rule) => rule.match.test(text) && !(rule.unless?.test(text) ?? false)).map((rule) => {
    const verdict = { decision: rule.verdict, reason: rule.reason };
    return rule.liftable === true ? liftable(verdict) : verdict;
  });
// The segment rules (a rule set's `on: "segment"` rows) read the command as typed, and again as the
// shell decodes it with its case folded: `.git/Team-Marker`, `team-mar''ker`, and
// `$'team\x2dmarker'` name the same file on a case-folding file system.
const segmentVerdicts = (segment, decoded, sets) => [...policyVerdicts(segment, sets.segment), ...policyVerdicts(decoded, sets.segment)];

// git's global options that take the next word as their value (git(1)); `--opt=value` carries it.
const GIT_GLOBAL_VALUED = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env", "--attr-source"]);

// A git command's global options, read the way git reads them: `sub`, the index of its subcommand;
// `dirs`, its `-C` directories in order; `config`, its `-c` / `--config-env` settings (`name=value`);
// and `elsewhere`, true when `--git-dir` or `--work-tree` points it at a repository the guard didn't look up.
const gitGlobals = (argv) => {
  const dirs = [];
  const config = [];
  let elsewhere = false;
  let at = 1;
  while (at < argv.length && (argv[at] ?? "").startsWith("-")) {
    tick();
    const word = argv[at] ?? "";
    const equals = word.indexOf("=");
    const name = word.startsWith("--") && equals !== -1 ? word.slice(0, equals) : word;
    const separate = GIT_GLOBAL_VALUED.has(name) && name === word;
    const value = !GIT_GLOBAL_VALUED.has(name) ? "" : separate ? (argv[at + 1] ?? "") : word.slice(equals + 1);
    if (name === "-C") dirs.push(value);
    if (name === "-c" || name === "--config-env") config.push(value);
    if (name === "--git-dir" || name === "--work-tree") elsewhere = true;
    at += separate ? 2 : 1;
  }
  return { sub: at, dirs, config, elsewhere };
};

// The name a git setting (`name=value`) sets, lowercased: git's section and key names ignore case.
const settingName = (setting) => (setting.split("=")[0] ?? "").toLowerCase();

// git push's long options (git-push(1)), the negations parse-options adds that matter here, and
// which take their value as the next word. git accepts any unambiguous prefix (`--delet`,
// `--force-w`), so a word is read as every option it could be the start of (pushOption()).
const PUSH_LONG = ["--all", "--branches", "--mirror", "--tags", "--follow-tags", "--delete", "--dry-run", "--porcelain", "--force", "--force-with-lease", "--no-force-with-lease", "--force-if-includes", "--no-force-if-includes", "--repo", "--recurse-submodules", "--no-recurse-submodules", "--thin", "--no-thin", "--receive-pack", "--exec", "--set-upstream", "--progress", "--no-progress", "--prune", "--no-prune", "--verify", "--no-verify", "--signed", "--no-signed", "--atomic", "--no-atomic", "--push-option", "--no-push-option", "--ipv4", "--ipv6", "--verbose", "--no-verbose", "--quiet", "--no-quiet"];
const PUSH_VALUED = new Set(["--repo", "--receive-pack", "--exec", "--push-option", "--recurse-submodules"]);

// The long options a `git push` word could be: itself when exact, else every one it is a prefix of.
// git refuses an ambiguous prefix, so reading it as each candidate only ever over-reads a command
// that would fail anyway; an unambiguous one (`--no-verif`) is the option git runs.
const pushOption = (word) => {
  const name = word.split("=")[0] ?? "";
  if (PUSH_LONG.includes(name)) return [name];
  return name.length > 2 ? PUSH_LONG.filter((option) => option.startsWith(name)) : [];
};

// The protected branches a refspec glob's destination covers (`refs/heads/*`, `*`, `m*`): git's `*`
// matches any run of characters, `/` included, against the full ref name.
const globTargets = (ref, protectedBranches) => {
  const pattern = new RegExp(`^${ref.split("*").map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`);
  return [...protectedBranches].filter((name) => pattern.test(`refs/heads/${name}`) || pattern.test(name) || pattern.test(`heads/${name}`));
};

// Rules for one `git push` (at command position): what it targets, and whether it forces, deletes, or skips the hook.
// `argv` is programArgv(); `branchOf()` reads the branch it runs on, called only for a push that needs
// it; `branches` the protected and workflow-only sets (the rule sets', or the project's);
// `frozenOf(file)` reads a freeze marker (null when none), one of `freezeMarkers` (the sets').
const evaluatePush = (/** @type {string[]} */ argv, /** @type {() => string} */ branchOf, branches, /** @type {(file: string) => string | null} */ frozenOf = () => null, freezeMarkers = []) => {
  // Require `git`, skip its global options (-C dir, -c key=value, --git-dir …), and require `push`.
  if (argv[0] !== "git") return null;
  const { sub, config } = gitGlobals(argv);
  if (argv[sub] !== "push") return null;
  // `-c core.hooksPath=…` points git at another hooks folder for this push: the pre-push guard doesn't run.
  if (config.some((setting) => settingName(setting) === "core.hookspath")) {
    return deny("`git -c core.hooksPath=… push` runs another hooks folder, so the pre-push guard is skipped: the same as --no-verify, and only the user bypasses it.");
  }

  // Read flags and positionals; a cluster like -uf carries every letter in it.
  let force = false;
  let remove = false;
  let all = false;
  let noVerify = false;
  const positionals = [];
  for (let j = sub + 1; j < argv.length; j += 1) {
    tick();
    const word = argv[j] ?? "";
    if (word.startsWith("--")) {
      const options = pushOption(word);
      if (options.includes("--no-verify")) noVerify = true;
      if (options.some((option) => /^--force(-with-lease|-if-includes)?$/.test(option))) force = true;
      if (options.includes("--delete")) remove = true;
      if (options.some((option) => /^--(all|mirror|branches)$/.test(option))) all = true;
      // `--repo X`: the value is the next word (not with `=`, and not for a word git would refuse).
      if (!word.includes("=") && options.length > 0 && options.every((option) => PUSH_VALUED.has(option))) j += 1;
    } else if (word === "-o") j += 1;
    else if (/^-[A-Za-z]+$/.test(word)) {
      if (word.includes("f")) force = true;
      if (word.includes("d")) remove = true;
    } else if (!word.startsWith("-")) positionals.push(word);
  }
  if (noVerify) {
    return deny("`git push --no-verify` bypasses the pre-push guard; only the user bypasses it.");
  }

  // The branches this push writes: each refspec's destination, or the current branch when none.
  const [, ...refspecs] = positionals;
  const targets = [];
  // The branches this push names outright (not through a glob or --all, which write only branches that exist locally).
  const named = [];
  for (const spec of refspecs) {
    tick();
    // `+src:dst` forces just this ref; `:dst` deletes dst.
    if (spec.startsWith("+")) force = true;
    // `split` returns fewer parts than the destructuring names when there is no `:`.
    const [src = "", dst] = /** @type {(string | undefined)[]} */ (spec.replace(/^\+/, "").split(":"));
    if (dst !== undefined && src === "") remove = true;
    const ref = dst ?? src;
    // A glob (`+refs/heads/*:refs/heads/*`) writes every branch it matches.
    if (ref.includes("*")) {
      targets.push(...globTargets(ref, branches.protected));
      continue;
    }
    const name = ref.replace(/^(refs\/)?heads\//, "");
    // `@` is git's short name for HEAD.
    named.push(name === "HEAD" || name === "@" ? branchOf() : name);
  }
  if (refspecs.length === 0 && !all) named.push(branchOf());
  targets.push(...named);
  if (refspecs.length === 0 && all) targets.push(...branches.protected);
  const hits = targets.filter((name) => branches.protected.has(name));

  // Deleting or force-pushing a protected branch rewrites history everyone builds on; rulesets forbid it too.
  if (hits.length > 0 && (force || remove)) {
    return deny(`${remove ? "Deleting" : "Force-pushing"} ${[...new Set(hits)].join("/")} is never an agent's call. Force-push only your own feature branch.`);
  }
  // A branch only its workflow writes: no agent push, forced or not.
  const workflowOnly = named.filter((name) => branches.workflowOnly.has(name) && branches.protected.has(name));
  if (workflowOnly.length > 0) {
    return deny(`Only its own workflow writes ${[...new Set(workflowOnly)].join("/")}; an agent never pushes it.`);
  }
  // Can't tell where a push lands (the branch lookup failed, and the push names none): the user decides.
  if (targets.includes("")) {
    return ask(`${force ? "A forced push" : "A push"} from a branch the guard couldn't read: confirm it isn't ${[...branches.protected].join(" or ")}.`);
  }
  // A freeze marker is set for a branch this push writes (a ship freeze: a release is open, and its
  // PR's head is that branch, so a push there cancels the checks it waits on). `{pr}` in the
  // reason is the marker's text, as ` #12`, or nothing when the marker is empty.
  for (const marker of freezeMarkers) {
    if (!targets.includes(marker.branch)) continue;
    const pr = frozenOf(marker.file);
    if (pr !== null) return deny(marker.reason.replaceAll("{pr}", () => (pr === "" ? "" : ` #${pr}`)));
  }
  // A branch the project asks about before any push (`askOnPush`; main and master by default):
  // pushing it usually ships production, so the user confirms here.
  const asked = [...new Set(targets.filter((name) => askOnPushOf(branches).has(name)))];
  if (asked.length > 0) {
    return ask(`Pushing ${asked.join("/")} usually ships to production: the user confirms it.`);
  }
  return null;
};

// git settings that hide what a later command does: a `core.hooksPath` written to config skips the
// pre-push guard on every push after it, a set's `gitConfigAsk` key (one that trims what a
// pre-push hook runs, say) is the owner's choice for their computer, and an alias runs whatever it was
// defined as while the guard reads only its name (`git -c alias.p='push -f origin main' p`, `alias.x='!sh …'`).
const evaluateGitConfig = (argv, gitConfigAsk = []) => {
  if (argv[0] !== "git") return null;
  const { sub, config } = gitGlobals(argv);
  // A set's key, set on this command or written to config (keys lowercased, as settingName() reads them).
  const keyAsk = (names) => {
    const row = gitConfigAsk.find((each) => names.includes(each.key));
    return row === undefined ? null : ask(row.reason);
  };
  const aliasAsk = ask("A git alias runs whatever it is defined as, and the guard reads only the alias's name; the user confirms what it runs.");
  if (config.some((setting) => settingName(setting).startsWith("alias."))) return aliasAsk;
  const configured = keyAsk(config.map(settingName));
  if (configured !== null) return configured;
  if (argv[sub] !== "config") return null;
  // `git config [--global] name value`, `--add`/`--replace-all`/`--unset`, or git 2.46's `set`/`unset`;
  // a read (`--get`, `name` alone, `get`, `list`) changes nothing. `-f file` and friends take a value.
  const positionals = [];
  let writes = false;
  for (let at = sub + 1; at < argv.length; at += 1) {
    const word = argv[at] ?? "";
    if (/^(-f|--file|--blob|--type|--default|--comment|--value)$/.test(word)) at += 1;
    else if (/^--(add|replace-all|unset|unset-all|rename-section|remove-section)$/.test(word)) writes = true;
    else if (!word.startsWith("-")) positionals.push(word);
  }
  const verb = /^(set|unset|get|list|edit|rename-section|remove-section)$/.test(positionals[0] ?? "") ? positionals.shift() : "";
  if (verb === "set" || verb === "unset" || (verb === "" && positionals.length >= 2)) writes = true;
  const key = (positionals[0] ?? "").toLowerCase();
  if (!writes) return null;
  if (key === "core.hookspath") return ask("Setting core.hooksPath moves git's hooks folder, which can switch the pre-push guard off for every push after it; the user confirms.");
  if (key.startsWith("alias.")) return aliasAsk;
  return keyAsk([key]);
};

// gh api's options that take a value (the next word, `--name=value`, or glued to a short flag:
// `-XDELETE`), and the ones that send a body, which makes its default method POST.
const GH_API_VALUED = new Set(["-X", "--method", "-H", "--header", "-f", "--raw-field", "-F", "--field", "--input", "-q", "--jq", "-t", "--template", "--cache", "--hostname", "-p", "--preview"]);
const GH_API_BODY = new Set(["-f", "--raw-field", "-F", "--field", "--input"]);

// GraphQL mutations by what they do, judged as the gh subcommand for the same act is.
const GRAPHQL_DENY = /\b(deleteBranchProtectionRule|deleteRepositoryRuleset)\b/;
const GRAPHQL_MERGE = /\b(mergePullRequest|enablePullRequestAutoMerge|mergeBranch)\b/;
const GRAPHQL_ASK = /\b(markPullRequestReadyForReview|updateRefs?|deleteRef|createBranchProtectionRule|updateBranchProtectionRule|createRepositoryRuleset|updateRepositoryRuleset)\b/;

// One `gh api` call: its method (gh's default is GET, POST once a field or `--input` is given), the
// endpoint's path (no host, no leading `/`, no query), each field's `name=value`, and its `--input` file.
const ghApiCall = (argv) => {
  let method = "";
  let body = false;
  let endpoint = "";
  let input = "";
  const fields = [];
  for (let at = 2; at < argv.length; at += 1) {
    tick();
    const word = argv[at] ?? "";
    const equals = word.indexOf("=");
    const long = word.startsWith("--") && equals !== -1 ? word.slice(0, equals) : word;
    let name = long;
    let value = "";
    if (GH_API_VALUED.has(long)) value = long === word ? (argv[(at += 1)] ?? "") : word.slice(equals + 1);
    else if (/^-[A-Za-z]./.test(word) && GH_API_VALUED.has(word.slice(0, 2))) {
      name = word.slice(0, 2);
      value = word.slice(2);
    } else {
      if (!word.startsWith("-") && endpoint === "") endpoint = word;
      continue;
    }
    if (name === "-X" || name === "--method") method = value.toUpperCase();
    if (GH_API_BODY.has(name)) body = true;
    if (name === "--input") input = value;
    else if (GH_API_BODY.has(name)) fields.push(value);
  }
  const path = endpoint.replace(/^https?:\/\/[^/]+/i, "").replace(/^\/+/, "").split("?")[0] ?? "";
  return { method: method || (body ? "POST" : "GET"), path, fields, input };
};

// `gh api` calls that are a gh subcommand's act by another road, judged as that subcommand is: a
// merge, Ready, a draft flip, a full rerun, a manual dispatch, a protected branch moved, force-moved,
// renamed, or deleted, branch protection or a ruleset changed, a repository or release deleted; and
// the rule sets' commit statuses and repository variables (`sets.statusContexts`, `repoVariables`).
// Reads (GET) run, apart from the merge endpoint, which asked before this rule existed.
const evaluateGhApi = (argv, segment, branches, sets) => {
  if (argv[0] !== "gh" || argv[1] !== "api") return null;
  const { method, path, fields, input } = ghApiCall(argv);
  if (path === "graphql") {
    // The query is a field (or a heredoc on `--input -`), read with the segment; `query=@file` or an
    // `--input` file the guard doesn't open could hold any mutation.
    if (GRAPHQL_DENY.test(segment)) return deny(PROTECTION_DELETE_DENY);
    if (/\bconvertPullRequestToDraft\b/.test(segment)) return deny(DRAFT_DENY);
    if (GRAPHQL_MERGE.test(segment)) return ask(MERGE_ASK);
    if (GRAPHQL_ASK.test(segment)) return ask("This GraphQL mutation marks a PR ready, moves or deletes a branch, or changes branch protection, and the guard can't read which: the user confirms.");
    if ((input !== "" && input !== "-") || fields.some((field) => field.startsWith("query=@"))) return ask("This GraphQL call reads its query from a file the guard doesn't open, so it can't tell a read from a mutation: the user confirms.");
    return null;
  }
  if (/\/pulls\/\d+\/merge\b/.test(path) || (/^repos\/[^/]+\/[^/]+\/merges$/.test(path) && method !== "GET")) return ask(MERGE_ASK);
  if (method === "GET" || method === "HEAD") return null;
  // A commit status a set names (a team's review gates, a conveyor's clearance: each has its
  // own script). A context the guard can't read (a variable, a glob, `@file`) or a body from
  // `--input` could be any of them, so it asks, built in: with the first row's `unreadable` reason, or UNREAD_CONTEXT.
  if (sets.statusContexts.length > 0 && /^repos\/[^/]+\/[^/]+\/statuses\/[^/]+$/.test(path)) {
    const context = fields.find((field) => /^context=/i.test(field))?.slice("context=".length);
    const named = context === undefined ? undefined : sets.statusContexts.find((row) => row.match.test(context));
    if (named !== undefined) return rowVerdict(named);
    const unreadable = sets.statusContexts.find((row) => row.unreadable !== undefined)?.unreadable ?? UNREAD_CONTEXT;
    if (input !== "" || (context !== undefined && /^@|[$`*?[{]/.test(context))) return ask(unreadable);
  }
  // A repository variable a set names, by its path or a name field; repo, org, and environment
  // variables (`environments/<env>/variables/…`). Deny rows first; then a body the guard doesn't
  // open (`--input`, or `-F name=@f`) asks, built in (a row's `unreadableBody`, or UNREAD_VARIABLE_BODY); then ask rows.
  if (sets.repoVariables.length > 0 && /\/(?:actions\/|environments\/[^/]+\/)variables(?:\/|$)/.test(path)) {
    const names = [path, ...fields.filter((field) => /^name=/i.test(field))];
    const named = (row) => names.some((text) => row.inPath.test(decodeURI(text)));
    const denied = sets.repoVariables.find((row) => row.verdict === "deny" && named(row));
    if (denied !== undefined) return deny(denied.reason);
    const unreadable = sets.repoVariables.find((row) => row.unreadableBody !== undefined)?.unreadableBody ?? UNREAD_VARIABLE_BODY;
    if (input !== "" || fields.some((field) => /^(?:name|value)=@/i.test(field))) return ask(unreadable);
    const asked = sets.repoVariables.find((row) => row.verdict === "ask" && named(row));
    if (asked !== undefined) return ask(asked.reason);
  }
  // `actions/runs/<id>/rerun` reruns every job; `rerun-failed-jobs` and one job's rerun are the `--failed` / `--job` roads.
  if (/\/actions\/runs\/\d+\/rerun$/.test(path)) return deny(RERUN_DENY);
  if (/\/actions\/workflows\/[^/]+\/dispatches$/.test(path) || /^repos\/[^/]+\/[^/]+\/dispatches$/.test(path)) return ask(DISPATCH_ASK);
  // A protected branch's ref: deleting or force-moving it is a force-push; moving main ships it.
  const ref = /\/git\/refs\/heads\/(.+)$/.exec(path)?.[1] ?? "";
  if (branches.protected.has(ref)) {
    const forced = fields.some((field) => /^force=(true|1)$/i.test(field));
    if (method === "DELETE" || forced) return deny(`${method === "DELETE" ? "Deleting" : "Force-moving"} ${ref} is never an agent's call. Force-push only your own feature branch.`);
    if (branches.workflowOnly.has(ref)) return deny(`Only its own workflow moves ${ref}; an agent never does.`);
    if (askOnPushOf(branches).has(ref)) return ask(`Moving ${ref} usually ships to production: the user confirms it.`);
    // A body from `--input` may say `"force": true`, which the guard doesn't open.
    if (input !== "") return ask(`This moves ${ref} with a body the guard doesn't read (\`--input\`), which may force it: confirm it doesn't.`);
  }
  if (ref !== "" && askOnPushOf(branches).has(ref)) return ask(`Moving ${ref} usually ships to production: the user confirms it.`);
  const renamed = /\/branches\/([^/]+)\/rename$/.exec(path)?.[1] ?? "";
  if (branches.protected.has(renamed)) return deny(`Renaming ${renamed} deletes it under the name everything builds on; a human does it.`);
  if (/\/branches\/[^/]+\/protection\b/.test(path) || /\/rulesets\b/.test(path)) {
    if (method === "DELETE") return deny(PROTECTION_DELETE_DENY);
    return ask("Changing branch protection or a ruleset changes what CI and review must pass before a merge; the user confirms.");
  }
  // The repository itself, or a release or its asset.
  if (method === "DELETE" && (/^repos\/[^/]+\/[^/]+$/.test(path) || /^repos\/[^/]+\/[^/]+\/releases\//.test(path))) return liftable(deny(DELETE_DENY));
  return null;
};

// `gh variable`'s flags that take a value (`--json`, `--jq`, `--template` are the readers').
const GH_VARIABLE_VALUED = new Set(["-b", "--body", "-e", "--env", "-f", "--env-file", "-o", "--org", "-R", "--repo", "-r", "--repos", "-v", "--visibility", "-q", "--jq", "-t", "--template", "--json"]);

// `gh variable set` or `delete` of a variable a set names (`repoVariables`; GitHub's variable names
// ignore case), unless a set gives it one of its `free` values (stopping is safe: a conveyor's
// `off`). Also, built in, a name the shell fills in (a row's `unreadableName`, or UNREAD_VARIABLE_NAME),
// and an env file, which the guard doesn't open (a row's `unreadableBody`, or UNREAD_VARIABLE_BODY).
// A deny row reads a verb the shell fills in as a write.
const shellFilled = (word) => /[$`*?{[]/.test(word);
const evaluateGhVariable = (argv, rows = []) => {
  if (argv[0] !== "gh" || argv[1] !== "variable" || rows.length === 0) return null;
  const positional = [];
  let body = null;
  let envFile = false;
  for (let at = 2; at < argv.length; at += 1) {
    tick();
    const word = argv[at] ?? "";
    const equals = word.indexOf("=");
    const long = word.startsWith("--") && equals !== -1 ? word.slice(0, equals) : word;
    if (GH_VARIABLE_VALUED.has(long)) {
      const value = long === word ? (argv[(at += 1)] ?? "") : word.slice(equals + 1);
      if (long === "-b" || long === "--body") body = value;
      if (long === "-f" || long === "--env-file") envFile = true;
    } else if (/^-[A-Za-z]./.test(word) && GH_VARIABLE_VALUED.has(word.slice(0, 2))) {
      if (word.startsWith("-b")) body = word.slice(2);
      if (word.startsWith("-f")) envFile = true;
    } else if (!word.startsWith("-")) positional.push(word);
  }
  const [verb = "", name = ""] = positional;
  const writes = verb === "set" || verb === "delete";
  const free = (row) => verb === "set" && body !== null && row.free.includes(body);
  // A verb or name the shell fills in (`gh variable "$verb" "$name"`) that the guard couldn't resolve: a
  // deny row's name with any verb that may write is refused; a name that could be any row's (a glob,
  // a variable) is the user's call.
  const denied = rows.find((row) => row.verdict === "deny" && row.exact.test(name) && !free(row));
  if (denied !== undefined && (writes || shellFilled(verb))) return deny(denied.reason);
  if (!writes && !(shellFilled(verb) && shellFilled(name))) return null;
  const unreadName = rows.find((row) => row.unreadableName !== undefined)?.unreadableName ?? UNREAD_VARIABLE_NAME;
  if (shellFilled(name)) return ask(unreadName);
  const unreadBody = rows.find((row) => row.unreadableBody !== undefined)?.unreadableBody ?? UNREAD_VARIABLE_BODY;
  if (verb === "set" && envFile) return ask(unreadBody);
  const asked = rows.find((row) => row.verdict === "ask" && row.exact.test(name));
  return asked === undefined || free(asked) ? null : ask(asked.reason);
};

// The built-in asks when a rule set guards some commit statuses or repository variables and the
// guard can't read which one a call writes; a set row's `unreadable*` text replaces them.
const UNREAD_CONTEXT = "This posts a commit status whose context the guard can't read (a variable, a glob, `@file`, or an `--input` body), and a rule set guards some contexts: the user confirms.";
const UNREAD_VARIABLE_BODY = "This writes a repository variable from a body the guard doesn't open (`--input`, `@file`, or an env file), and a rule set guards some variables: the user confirms.";
const UNREAD_VARIABLE_NAME = "This sets or deletes a repository variable whose name the shell fills in, and a rule set guards some variables: the user confirms.";

// Why deleting branch protection or a ruleset is refused, over REST or GraphQL.
const PROTECTION_DELETE_DENY = "Deleting branch protection or a ruleset takes away what stops a force-push or an unreviewed merge; a human changes it.";

// Data stores whose own delete the guard reads, outside SQL. A loopback target runs, a remote one is
// refused, and one the guard can't place asks, as SQL is judged (judgeSql()).
const REDIS_FLUSH = /\bflush(all|db)\b/i;
const MONGO_DELETE = /\.(dropDatabase|drop|dropCollection|deleteMany|deleteOne|remove|findOneAndDelete)\s*\(/;

// Where a host word points: a `$VAR` is unknown, else loopback or remote (hostsKind()).
const hostKind = (host) => (/[$`]/.test(host) ? "unknown" : hostsKind(host.split(",")));

// The value of the first of `flags` in argv (`--flag v`, `--flag=v`, `-h v`), or undefined.
const flagValue = (argv, flags) => {
  for (let at = 1; at < argv.length; at += 1) {
    tick();
    const word = argv[at] ?? "";
    for (const flag of flags) {
      if (word === flag) return argv[at + 1] ?? "";
      if (flag.startsWith("--") && word.startsWith(`${flag}=`)) return word.slice(flag.length + 1);
    }
  }
  return undefined;
};

// Where a mongo shell connects: a `mongodb://` word, `--host` (`rs/host:port,…`), or a
// `host[:port]/db` address; with none, this machine.
const mongoTarget = (argv) => {
  const url = argv.find((word) => /^mongodb(\+srv)?:\/\//i.test(word));
  if (url !== undefined) return targetOf(url);
  const host = flagValue(argv, ["--host"]);
  if (host !== undefined) return hostKind(host.replace(/^[^/]*\//, "").replace(/:\d+(?=,|$)/g, ""));
  const address = argv.slice(1).find((word, index) => !word.startsWith("-") && !(argv[index] ?? "").startsWith("-") && /^[\w.-]+(:\d+)?\//.test(word));
  return address === undefined ? "loopback" : hostKind(address.replace(/[:/].*$/, ""));
};

// Verdict for a data store's own delete: Redis FLUSHALL/FLUSHDB, a mongo shell's drop or delete, a
// remote D1 execute's SQL, and Docker volumes. `text` is the command with its heredoc bodies and the
// command before it (what may be piped in), where the delete is looked for; `readFile(path)` reads a
// SQL file within the line's budget (null when it can't); `remote` is a line run on another machine,
// where "localhost" is that machine's.
const evaluateStore = (argv, { text, readFile, remote }) => {
  const program = argv[0] ?? "";
  const judged = (kind, what) => {
    const where = remote && kind === "loopback" ? "unknown" : kind;
    if (where === "loopback") return null;
    if (where === "remote") return deny(`${what} against a non-loopback server deletes data: a human action. Hand the user the exact command.`);
    return ask(`${what}, and the guard can't tell which server it reaches (a \`$VAR\`, or another machine's localhost): fine on loopback or a throwaway only. Confirm the target.`);
  };
  if (/^(redis|valkey)-cli$/.test(program) && REDIS_FLUSH.test(text)) {
    const url = flagValue(argv, ["-u", "--uri"]);
    const host = flagValue(argv, ["-h"]);
    return judged(url !== undefined ? targetOf(url) : host !== undefined ? hostKind(host) : "loopback", "FLUSHALL / FLUSHDB");
  }
  if (/^mongo(sh)?$/.test(program) && MONGO_DELETE.test(text)) return judged(mongoTarget(argv), "A mongo shell drop or delete");
  // `wrangler d1 execute` is local unless `--remote`; there its `--command` or `--file` SQL is read.
  if (program === "wrangler" && argv[1] === "d1" && argv[2] === "execute" && argv.some((word) => /^--remote(=true)?$/.test(word))) {
    const sql = flagValue(argv, ["--command"]);
    const file = flagValue(argv, ["--file"]);
    const texts = [sql ?? "", file === undefined ? "" : readFile(file)];
    if (texts.some((each) => each !== null && destroysSql(each))) return judged("remote", "Destructive SQL in `wrangler d1 execute --remote`");
    if (texts.includes(null)) return ask("`wrangler d1 execute --remote --file` runs SQL the guard can't read against the hosted database: confirm it deletes nothing.");
    return null;
  }
  // Docker volumes hold a container's data, most likely a local dev database's; DOCKER_HOST or a
  // context can point at another machine's, and the guard reads neither, so the user confirms.
  const docker = /^(docker|podman|nerdctl)$/.test(program);
  const compose = (docker && argv.includes("compose")) || /^(docker|podman)-compose$/.test(program);
  const down = argv.indexOf("down");
  const downVolumes = compose && down !== -1 && argv.slice(down + 1).some((word) => /^(--volumes(=true)?|-[A-Za-z]*v[A-Za-z]*)$/.test(word));
  if (downVolumes || (docker && /\bvolume\s+(rm|remove|prune)\b|\bsystem\s+prune\b.*\s--volumes\b/.test(argv.join(" ")))) {
    return ask("Removing Docker volumes deletes the data in them: a local database's, most likely, but DOCKER_HOST or a context can point elsewhere. Fine on a throwaway: the user confirms.");
  }
  return null;
};

// A word with each `$name` / `${name}` that the line set to a plain value filled in; one set to
// something unseen (`$(…)`, another variable) stays as typed. Reads only what the line itself assigned.
const filledWith = (lineEnv) => (word) =>
  word.replace(/\$(?:([A-Za-z_]\w*)|\{([A-Za-z_]\w*)\})/g, (whole, bare, braced) => {
    const value = lineEnv.get(bare ?? braced);
    return typeof value === "string" ? value : whole;
  });

// Ask when a write's target is a pattern or an unseen expansion that could be a set's marker file
// (`markerFiles`; for a marker `.git/team-marker`: `.git/team-mar*`, `.git/t{a,b}*`, `$(git rev-parse
// --git-common-dir)/$name`): the text rules can't read what the shell makes of it. Outside a `.git`
// path a pattern needs 3 literal characters, so `> out*` isn't asked about. A plain name is a
// segment row's (deny). Still unread: `eval`, a substitution that builds the name, and a glob run
// after a `cd` into the folder.
const markerWrites = (list, markerFiles = []) => {
  if (markerFiles.length === 0) return null;
  for (const path of writes(list)) {
    tick();
    const name = path.replace(/\$\([^)]*\)|`[^`]*`/g, "\0");
    const base = name.slice(name.lastIndexOf("/") + 1);
    if (!/[*?[{$\0]/.test(base)) continue;
    let literals = 0;
    const pattern = [...base.matchAll(/\$\{[^}]*\}|\$[A-Za-z_]\w*|[\0*?]|\[[^\]]*\]|\{[^}]*\}|[\s\S]/g)].map(([part]) => {
      if (part === "?") return ".";
      if (/^[\0*$[{]/.test(part) && (part.length > 1 || /^[\0*]$/.test(part))) return ".*";
      literals += 1;
      return part.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    });
    const gitish = /(^|\/)\.git(\/|$)|git-common-dir|rev-parse/i.test(path);
    if (literals < (gitish ? 0 : 3)) continue;
    const could = new RegExp(`^${pattern.join("")}$`, "i");
    const marker = markerFiles.find((each) => could.test(each.name));
    if (marker !== undefined) return ask(marker.reason);
  }
  return null;
};

// The guard's own files, from the repo root: what a shell write to them (an edit, a move, a delete, a
// chmod) could switch off. The hook doesn't see the Edit and Write tools (those show in the diff);
// this catches the shell's road to the same files. The core's list is its config file, its rule
// folder and branch file when the caller names them (`files`), the hook configs, and the installed
// package; a rule set's `guardFiles` adds its own. A path ending in `/` is a folder: a path inside
// it is a guard file too. compileGuard() builds the matcher: one by its path's end, so an absolute
// path counts too, and in any case (a Mac's file system folds it).
const HOOK_FILES = [".claude/settings.json", ".claude/settings.local.json", ".cursor/hooks.json", `node_modules/${PACKAGE_NAME}/`];

// The matcher for a list of guard paths (folders end in `/`): `files` (lowercased, no trailing `/`),
// `dirs` (the folders among them), and `match` (a path that is one, or inside a folder that is one).
const compileGuard = (paths) => {
  const unique = [...new Set(paths.map((path) => path.toLowerCase()))];
  const files = unique.map((path) => path.replace(/\/+$/, ""));
  const dirs = new Set(unique.filter((path) => path.endsWith("/")).map((path) => path.replace(/\/+$/, "")));
  const escape = (path) => path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const alternatives = files.map((path) => (dirs.has(path) ? `${escape(path)}(\\/.*)?` : escape(path)));
  return { files, dirs, match: new RegExp(`(^|\\/)(${alternatives.join("|")})$`, "i") };
};

// The core's guard files with nothing configured: the default config file and the hook configs.
let defaultGuardFiles = null;
const defaultGuard = () => {
  defaultGuardFiles ??= compileGuard([DEFAULT_FILES.config, ...HOOK_FILES]);
  return defaultGuardFiles;
};

// Programs that delete, move, or change the mode of their operands (writes() reads what writes files).
const REMOVERS = /^(rm|unlink|shred|mv|chmod|chown|chattr|chflags|truncate)$/;

// True when a relative folder path holds one of the guard's files (`.claude`, `node_modules`); `.` and paths
// outside the repo don't count (`rm -rf .` is refused by rm itself).
const holdsGuardFile = (path, guard) => !isAbsolute(path) && !path.startsWith("..") && path !== "." && guard.files.some((file) => file.startsWith(`${path.toLowerCase()}/`));

// A word's brace expansion, as the shell makes it before globbing (`x.{sets,d}` is `x.sets` and
// `x.d`); null past 64 words, which the caller reads as a match. `{a..z}` is left for globSegment().
const braceWords = (word) => {
  const done = [];
  const todo = [word];
  while (todo.length > 0) {
    tick();
    const next = todo.pop() ?? "";
    const split = braceSplit(next);
    if (split === null) done.push(next);
    else todo.push(...split);
    if (done.length + todo.length > 64) return null;
  }
  return done;
};

// The words one `{a,b}` in `word` expands to (the first with a comma at its own depth), or null when there is none.
const braceSplit = (word) => {
  for (let open = word.indexOf("{"); open !== -1; open = word.indexOf("{", open + 1)) {
    let depth = 0;
    const cuts = [open];
    for (let at = open; at < word.length; at += 1) {
      tick();
      const char = word[at];
      if (char === "{") depth += 1;
      else if (char === "," && depth === 1) cuts.push(at);
      else if (char === "}" && --depth === 0) {
        if (cuts.length === 1) break;
        cuts.push(at);
        return cuts.slice(1).map((cut, index) => `${word.slice(0, open)}${word.slice((cuts[index] ?? open) + 1, cut)}${word.slice(at + 1)}`);
      }
    }
  }
  return null;
};

// One path segment's glob as a test for a name: `*` and `{a..z}` any run, `?` and `[…]` one character; any case.
const globSegment = (segment) => {
  const parts = [...segment.matchAll(/\{[^{}/]*\.\.[^{}/]*\}|\[[^\]/]+\]|[*?]|[\s\S]/g)].map(([part]) => {
    if (part === "*" || (part.length > 1 && part.startsWith("{"))) return ".*";
    if (part === "?" || (part.startsWith("[") && part.length > 1)) return ".";
    return part.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  });
  return new RegExp(`^${parts.join("")}$`, "i");
};

// True when a write's target, as the shell expands its braces and globs (`.rein*/x`,
// `.claude/settings{,.local}.json`), could be one of the guard's files, a file in one of its folders, or (relative)
// a folder holding one. A relative path is read from the repo root, as holdsGuardFile() reads it; any
// other matches by its end, as `guard.match` does.
const couldBeGuardFile = (path, guard) => {
  const expanded = braceWords(path);
  if (expanded === null) return true;
  return expanded.some((each) => {
    const word = normalize(each).replace(/\/+$/, "");
    if (!/[*?[]|\{[^{}]*\.\.[^{}]*\}/.test(word)) return guard.match.test(word) || holdsGuardFile(word, guard);
    const raw = word.split("/").filter((segment) => segment !== "");
    const segments = raw.map(globSegment);
    const rooted = !isAbsolute(word) && !word.startsWith("~") && !word.startsWith("..");
    // Outside the repo root, a root-level name (reins.json) needs 3 literal characters
    // besides `.json` in its glob, so `rm /tmp/*.json` isn't asked about.
    const loose = !rooted && (raw.at(-1) ?? "").replace(/\.json$/i, "").replace(/\{[^{}]*\}|\[[^\]]*\]|[*?]/g, "").length < 3;
    return guard.files.some((file) => {
      const parts = file.split("/");
      if (loose && parts.length === 1) return false;
      const fits = (from) => parts.every((part, index) => from + index >= segments.length || (segments[from + index]?.test(part) ?? false));
      const ends = (from) => from + parts.length === segments.length || (from + parts.length < segments.length ? guard.dirs.has(file) : rooted);
      if (rooted) return segments.length > 0 && fits(0) && ends(0);
      for (let from = 0; from + parts.length <= segments.length; from += 1) if (fits(from) && ends(from)) return true;
      return false;
    });
  });
};

// An ask when this command writes, moves, or deletes one of the guard's files, or a folder that holds
// one (`rm -rf .claude`); `dir` is where it runs (null for the hook's cwd). Still unread: a write
// from inside an interpreter (`node -e`, `python3 -c`), `find -delete`, and an archive's `-C`/`-d`.
const guardWrites = (headWords, dir, guard) => {
  const start = programStart(headWords);
  const program = programName(headWords[start] ?? "");
  const operands = headWords.slice(start + 1).filter((word) => !word.startsWith("-"));
  // `git rm` / `git mv` remove or move a tracked file the same way; `git checkout <ref> -- <path>` and
  // `git restore` write it from another commit. `git -C X` runs them in X.
  const git = program === "git" ? gitGlobals(headWords.slice(start)) : null;
  const gitArgs = git === null ? [] : headWords.slice(start + git.sub).filter((word) => !word.startsWith("-"));
  const gitDir = (git?.dirs ?? []).reduce((from, target) => (isAbsolute(target) ? target : join(from ?? "", target)), dir);
  const gitWrites = /^(rm|mv|checkout|restore)$/.test(gitArgs[0] ?? "") ? gitArgs.slice(1).map((path) => fileKey(gitDir, path)) : [];
  const paths = [...[...writes(headWords), ...(REMOVERS.test(program) ? operands : [])].map((path) => fileKey(dir, path)), ...gitWrites].map((path) => path.replace(/\/+$/, ""));
  if (!paths.some((path) => guard.match.test(path) || holdsGuardFile(path, guard) || couldBeGuardFile(path, guard))) return null;
  return ask("This command writes, moves, or deletes one of the guard's own files (its config, its rule files, its installed package, or the hook config in .claude/settings.json or .cursor/hooks.json): a change to the guard is the user's call, in a reviewed PR.");
};

// "loopback" when every host is this machine, "remote" when any isn't, "unknown" when there are none.
const hostsKind = (hosts) => {
  const named = hosts.map((host) => host.trim()).filter((host) => host !== "");
  if (named.length === 0) return "unknown";
  return named.every((host) => LOOPBACK_HOST.test(host)) ? "loopback" : "remote";
};

// Where one connection string points: "loopback", "remote", or "unknown" (a variable, a bare name,
// no host, or one it can't parse). Never throws: a throw here (`postgres://%zz` is a bad escape)
// would skip the guard for the whole line, a force-push beside it included.
export const targetOf = (value) => {
  try {
    return readTarget(value);
  } catch {
    return "unknown";
  }
};

// targetOf()'s reading, which may throw on a malformed URL.
const readTarget = (value) => {
  const text = (value ?? "").trim();
  // A shell expansion is only known when it runs.
  if (text === "" || /[$`]/.test(text)) return "unknown";
  // A SQLite database is a file on this machine.
  if (/^(sqlite3?|file):/i.test(text)) return "loopback";
  // A URL: libpq lets `?host=` override the authority, so query hosts win; `a,b` is a multi-host list.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) {
    let url = null;
    try {
      url = new URL(text);
    } catch {
      return "unknown";
    }
    // MySQL's (and Prisma's) `?socket=/path/mysqld.sock` connects through that socket, judged by its
    // directory like a postgres `?host=/dir`: `/cloudsql/p:r:i` is the Cloud SQL proxy's, not this machine's.
    const sockets = url.searchParams.getAll("socket").map((path) => (path.trim() === "" ? "" : dirname(path.trim())));
    const queryHosts = [...url.searchParams.getAll("host"), ...url.searchParams.getAll("hostaddr"), ...sockets];
    return hostsKind((queryHosts.length > 0 ? queryHosts : [decodeURIComponent(url.hostname)]).flatMap((host) => host.split(",")));
  }
  // A key=value connection string (`host=… dbname=…`); with no host it is a socket or a default the line doesn't show.
  const pairs = [...text.matchAll(/\bhost(?:addr)?\s*=\s*(?:'([^']*)'|(\S+))/g)];
  return hostsKind(pairs.flatMap((pair) => (pair[1] ?? pair[2] ?? "").split(",")));
};

// The connection strings named on a command line: URL-shaped words, `host=` strings, and URL flags' values.
const explicitTargets = (list) =>
  list.flatMap((word, index) => {
    // `--url=…` carries its value; `--url …` hands it to the next word.
    const [flag = "", attached] = word.split(/=(.*)/s);
    if (URL_FLAGS.has(flag) && attached !== undefined) return [attached];
    if (URL_FLAGS.has(word)) return [list[index + 1] ?? ""];
    return /^[a-z][a-z0-9+.-]*:\/\//i.test(word) || /^(sqlite3?|file):/i.test(word) || /\bhost(addr)?\s*=/.test(word) ? [word] : [];
  });

// The program a word names: its basename, with an npx-style `@version` removed (`./node_modules/.bin/prisma`,
// `prisma@6`); a file inside a package's own directory names the package (`node node_modules/prisma/build/index.js`).
const toolName = (word) => {
  const inPackage = /(?:^|\/)node_modules\/(?:@[^/]+\/)?([^/.][^/]*)\//.exec(word);
  return foldAscii(inPackage?.[1] ?? (word.split("/").pop() ?? "").replace(/(.)@[^@/]*$/, "$1"));
};

// A word that is a flag's value, a count, or a duration (`nice -n 5`, `timeout 600`, `sudo -u postgres`).
const isFlagValue = (list, index) => /^\d+(\.\d+)?[smhd]?$/.test(list[index] ?? "") || /^-\w$/.test(list[index - 1] ?? "");

// What the words in front of a database tool do to it: the variables they set (null = set to
// something unseen, UNSET = removed), whether `env -i` cleared the rest (`cleared`), whether a
// secrets loader runs it, and whether one of them is a wrapper the guard doesn't model (`xargs`,
// `docker exec`, `pnpm --filter`, `$(…)`), so its target can't be trusted.
//
// `env -u X`, `env -i`, and `sudo` matter because the tool then reads X from its .env, not the
// environment the guard sees: a loopback DATABASE_URL in the agent's shell proves nothing. Plain
// `sudo` (and `sudo -u user`) resets the environment the way `env -i` does; `sudo -E` keeps it.
const prefixOf = (list) => {
  const vars = new Map();
  let cleared = false;
  let loaded = false;
  let unmodelled = false;
  // The wrapper whose flags are being read, so `env -u X` and `sudo -u user` aren't confused.
  let wrapper = "";
  // What `sudo` cleared, put back by a later `-E` / `--preserve-env`.
  let beforeSudo = null;
  for (let index = 0; index < list.length; index += 1) {
    tick();
    const word = list[index] ?? "";
    const name = assigned(word);
    // env's short options, as getopt reads a cluster (`-i`, `-iu X`, `-uX`, `-iPATH=/x`): -i clears
    // the environment, -u removes a name, -S splits a string into a command the guard doesn't
    // follow here, and -C/-P/-a take a value (the rest of the cluster, or the next word).
    if (wrapper === "env" && /^-[^-]/.test(word)) {
      for (let k = 1; k < word.length; k += 1) {
        const letter = word[k] ?? "";
        if (letter === "i") {
          cleared = true;
          vars.clear();
        } else if ("uCPaS".includes(letter)) {
          const rest = word.slice(k + 1);
          const value = rest === "" ? (list[(index += 1)] ?? "") : rest;
          if (letter === "u") vars.set(value, UNSET);
          if (letter === "S") unmodelled = true;
          break;
        }
      }
    }
    // `env --unset=X`, `--unset X`: X is removed for the tool.
    else if (wrapper === "env" && /^--unset(=|$)/.test(word)) vars.set(word.includes("=") ? word.slice(word.indexOf("=") + 1) : (list[(index += 1)] ?? ""), UNSET);
    // `env -` / `--ignore-environment`: the tool starts with no environment beyond what follows.
    else if (wrapper === "env" && /^(--ignore-environment|-)$/.test(word)) {
      cleared = true;
      vars.clear();
    }
    // `env --split-string`: a command string, which this prefix reading doesn't follow.
    else if (wrapper === "env" && /^--split-string(=|$)/.test(word)) unmodelled = true;
    // `sudo`: the environment is reset (sudoers' env_reset) unless -E / --preserve-env keeps it.
    else if (foldAscii(word) === "sudo") {
      wrapper = "sudo";
      beforeSudo = { vars: new Map(vars), cleared };
      cleared = true;
      vars.clear();
    } else if (wrapper === "sudo" && beforeSudo !== null && (/^-[A-Za-z]*E[A-Za-z]*$/.test(word) || word === "--preserve-env")) {
      for (const [kept, value] of beforeSudo.vars) if (!vars.has(kept)) vars.set(kept, value);
      cleared = beforeSudo.cleared;
    }
    // `--preserve-env=A,B` keeps only those names: each set on the line is put back. One the line
    // didn't set passes the agent's own value through, which a cleared reading can't express: ask.
    else if (wrapper === "sudo" && beforeSudo !== null && word.startsWith("--preserve-env=")) {
      for (const kept of word.slice("--preserve-env=".length).split(",")) {
        if (beforeSudo.vars.has(kept)) vars.set(kept, beforeSudo.vars.get(kept));
        else if (!beforeSudo.cleared) unmodelled = true;
      }
    }
    // `X=v` sets X for the tool; a value the guard can't read is unseen.
    else if (name !== undefined) vars.set(name, /[$`]/.test(assignedValue(word)) ? null : assignedValue(word));
    // An unquoted `$(…)` or backtick runs something first and splits into words the guard can't follow.
    else if (/[$`]/.test(word)) unmodelled = true;
    // A loader can set or override any variable, so what was set before it no longer counts;
    // `node --env-file=f` is one too.
    else if (LOADERS.test(word) || /^--env-file(-if-exists)?(=|$)/.test(word)) {
      loaded = true;
      vars.clear();
    }
    // A loader's own flags and arguments (`dotenv -e .env.production`, `doppler run --`).
    else if (loaded) continue;
    // `pnpm --filter api …`, `pnpm -C dir …`: another package's directory (`-C`/`--dir` is read through separately).
    else if (MOVING_FLAGS.test(word)) unmodelled = true;
    // Wrappers that pass the variables and directory through, their flags, and those flags' values.
    else if (PLAIN_WRAPPERS.has(foldAscii(word))) wrapper = foldAscii(word);
    else if (word.startsWith("-") || isFlagValue(list, index)) continue;
    else unmodelled = true;
  }
  return { vars, cleared, loaded, unmodelled };
};

// Index of a SQL client's word in a command's words, or -1. Only wrappers may come before it, so
// `which psql` or `grep psql` is not a client.
const clientAt = (list) => {
  let loaded = false;
  for (let index = 0; index < list.length; index += 1) {
    const word = list[index] ?? "";
    const tool = toolName(word);
    if (SQL_CLIENTS.has(tool)) return index;
    if ((tool === "prisma" || tool === "turso") && list[index + 1] === "db" && /^(execute|shell)$/.test(list[index + 2] ?? "")) return index;
    if (LOADERS.test(word)) loaded = true;
    else if (!(loaded || assigned(word) !== undefined || PLAIN_WRAPPERS.has(foldAscii(word)) || word.startsWith("-") || isFlagValue(list, index))) return -1;
  }
  return -1;
};

// Lines a wrapper the guard doesn't model would run: from the first SQL client on (`watch psql …`,
// `kubectl exec p -- psql …`), and, for a REMOTE_RUNNERS program, each word that is a whole command
// line (`ssh h "psql -c '…'"`, `su -c "…"`) and a shell or migration tool too. Each { text, remote, container };
// none when a SQL client already sits in command position (clientAt), or the program only prints
// or searches (NON_RUNNERS), so `grep psql` and `echo psql -c "…"` stay words.
const handedOn = (list) => {
  const start = programStart(list);
  const program = toolName(list[start] ?? "");
  if (clientAt(list) !== -1 || NON_RUNNERS.has(program)) return [];
  const remote = REMOTE_RUNNERS.has(program);
  // A local container (`docker exec`, `docker compose exec|run`), not another machine or user.
  const container = CONTAINER_RUNNERS.has(program);
  const lines = [];
  // The tail from the first tool on is one line; every whole-command word is another.
  let tail = false;
  for (let index = start + 1; index < list.length; index += 1) {
    tick();
    const word = list[index] ?? "";
    if (remote && /\s/.test(word)) lines.push({ text: word, remote, container });
    const tool = toolName(word);
    const sqlTool = SQL_CLIENTS.has(tool) || ((tool === "prisma" || tool === "turso") && list[index + 1] === "db");
    if (!tail && (sqlTool || (remote && (MIGRATE_TOOLS.has(tool) || /^(ba|z|da)?sh$/.test(tool))))) {
      lines.push({ text: shellJoin(list.slice(index)), remote, container });
      tail = true;
    }
  }
  return lines;
};

// Files a command writes, as typed: redirect targets (`> f`, `>>f`, `2> f`), and what cp, mv, ln,
// install, rsync, scp, tee, `sed -i`, `curl -o`, `wget -O`, and `dd of=` write. A directory
// destination also covers each source's name inside it. Over-reading only makes a later read ask.
const writes = (list) => {
  const found = [];
  const args = [];
  for (let index = 0; index < list.length; index += 1) {
    tick();
    const word = list[index] ?? "";
    const arrow = word.lastIndexOf(">");
    if (arrow === -1) {
      args.push(word);
      continue;
    }
    // `> f` takes the next word; `>f`, `2>>f`, `>|f` carry it.
    const target = word.slice(arrow + 1).replace(/^\|/, "");
    if (target !== "") found.push(target);
    else {
      found.push(list[index + 1] ?? "");
      index += 1;
    }
  }
  const start = programStart(args);
  const program = toolName(args[start] ?? "");
  const operands = args.slice(start + 1).filter((word) => !word.startsWith("-"));
  if (/^(cp|mv|ln|install|rsync|scp)$/.test(program) && operands.length >= 2) {
    const destination = operands.at(-1) ?? "";
    found.push(destination);
    for (const source of operands.slice(0, -1)) found.push(join(destination, basename(source)));
  }
  // concat, not push(...): a line with a million operands would overflow the call stack.
  const more = [
    program === "tee" || ((program === "sed" || program === "perl") && args.some((word) => /^-[A-Za-z]*i/.test(word))) ? operands : [],
    program === "curl" || program === "wget" ? flagValues(args, ["-o", "--output", "-O", "--output-document"]) : [],
    args.filter((word) => word.startsWith("of=")).map((word) => word.slice(3)),
  ];
  // `2>&1` duplicates a descriptor; it writes no file.
  return found.concat(...more).filter((path) => path !== "" && !path.startsWith("&"));
};

// SQL with its comments blanked, read the way Postgres reads it: `--` and `/* … */` (nested) are
// comments only outside quoted strings, quoted names, and dollar-quoted bodies, so `'--'` hides
// nothing. One pass over the text.
const withoutComments = (sql) => {
  const kept = [];
  let from = 0;
  let i = 0;
  while (i < sql.length) {
    tick();
    const char = sql[i];
    const next = sql[i + 1];
    if (char === "-" && next === "-") {
      // A line comment, to the end of its line.
      kept.push(sql.slice(from, i), " ");
      const end = sql.indexOf("\n", i);
      i = end === -1 ? sql.length : end;
      from = i;
    } else if (char === "/" && next === "*") {
      // A block comment; Postgres lets them nest.
      kept.push(sql.slice(from, i), " ");
      let depth = 0;
      do {
        if (sql.startsWith("/*", i)) {
          depth += 1;
          i += 2;
        } else if (sql.startsWith("*/", i)) {
          depth -= 1;
          i += 2;
        } else i += 1;
      } while (depth > 0 && i < sql.length);
      from = i;
    } else if (char === "'" || char === '"') {
      // A string or quoted name; a doubled quote is an escaped one.
      let end = i + 1;
      while (end < sql.length && !(sql[end] === char && sql[end + 1] !== char)) end += sql[end] === char ? 2 : 1;
      i = end + 1;
    } else if (char === "$" && !/[A-Za-z0-9_]/.test(sql[i - 1] ?? "")) {
      // `$tag$ … $tag$`, a body with no escapes at all (the tag read from a bounded slice).
      const tag = /^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/.exec(sql.slice(i, i + 64))?.[0];
      const close = tag === undefined ? -1 : sql.indexOf(tag, i + tag.length);
      i = tag === undefined ? i + 1 : close === -1 ? sql.length : close + tag.length;
    } else i += 1;
  }
  kept.push(sql.slice(from));
  return kept.join("");
};

// True when each pattern matches in order, each searched from where the one before it ended.
const inOrder = (text, patterns) => {
  let at = 0;
  for (const pattern of patterns) {
    const found = pattern.exec(at === 0 ? text : text.slice(at));
    if (found === null) return false;
    at += found.index + found[0].length;
  }
  return true;
};

// What SQL texts do: destroy data, build SQL at run time, or hold a `;`-piece too long to judge.
// Each is read twice, as written and with comments blanked, so whichever way a quote or a comment
// is misread, a DROP shows in one of them (`SELECT '--'; DROP …` as written, `DROP/**/TABLE` blanked).
// Linear in the text: no pattern backtracks across a piece.
const readSqlText = (texts) => {
  let destroys = false;
  let dynamic = false;
  let tooLong = false;
  for (const text of texts) {
    if (GEXEC.test(text)) dynamic = true;
    for (const form of [text, withoutComments(text)]) {
      for (const piece of form.toLowerCase().split(";")) {
        tick();
        if (piece.length > MAX_SQL_STATEMENT_CHARS) {
          tooLong = true;
          continue;
        }
        if (!destroys && DESTRUCTIVE_SQL.some((rule) => inOrder(piece, rule))) destroys = true;
        if (DYNAMIC_SQL.test(piece)) dynamic = true;
      }
    }
  }
  return { destroys, dynamic, tooLong };
};

// True when SQL text destroys data (DESTRUCTIVE_SQL, read as written and with comments blanked).
// The infra rules' cloud SQL runners (`bq query`, RDS Data API …) read their SQL through it too.
export const destroysSql = (text) => readSqlText([text]).destroys;

// psql meta-commands that run another file: `\i f` / `\include f` from where psql runs, `\ir f` /
// `\include_relative f` from the including file's directory.
const INCLUDE = /\\(i|ir|include|include_relative)\s+(\S+)/g;

// MySQL's own include: `source f` or `\. f` at a statement's start.
const MYSQL_SOURCE = /(?:^|[;\n])\s*(?:source|\\\.)\s+([^\s;]+)/gi;

// psql variable interpolation (`:t`, `:'t'`, `:"t"`; not a `::type` cast): with `-v` or `\set` in
// play, the SQL that runs isn't the SQL on the line (`-v t=TABLE -c "DROP :t users"`).
const PSQL_VARIABLE = /(?<![:\w]):['"]?[A-Za-z_]/;

// A path with one pair of surrounding quotes removed (`\i 'my file.sql'`).
const unquote = (path) => path.replace(/^(['"])(.*)\1$/, "$2");

// Paths that are a client's stdin, not a file: `-f -` reads the pipe or heredoc like no file at all.
const STDIN_PATH = /^(-|\/dev\/stdin|\/dev\/fd\/0|\/proc\/self\/fd\/0)$/;

// A previous command's output a SQL client reads on stdin: its SQL, or why it can't be read.
// `piped` is that command as evaluateLine() keeps it ({ list: its tokens, expands, heredocs }).
const pipedSql = (piped, readFile) => {
  const { list, expands: typed } = piped;
  const at = list.findIndex((word) => assigned(word) === undefined);
  const tool = toolName(list[at] ?? "");
  const args = list.slice(at + 1);
  // A `$X` or `$(…)` in what it prints is only known when it runs.
  const hidden = typed.slice(at + 1).some(Boolean);
  // `echo "…" | psql`: the SQL is on the line. A printf format or an escape can build words
  // the line doesn't show (`printf 'DR%sP …' O`, `echo -e '\x44…'`), so those can't all be read.
  if (tool === "echo" || tool === "printf") return { sql: [args.join(" ")], unreadable: hidden || args.some((word) => word.includes("\\") || (tool === "printf" && word.includes("%"))), destroys: false };
  if (tool === "cat") {
    // `cat <<EOF | psql` and `cat <<< "…" | psql`: the body; `cat f.sql | psql`: the files it reads.
    const here = args.findIndex((word) => word.startsWith("<<<"));
    const sql = piped.heredocs.map((doc) => doc.body);
    if (here !== -1) sql.push(args[here] === "<<<" ? (args[here + 1] ?? "") : (args[here] ?? "").slice(3));
    const expands = piped.heredocs.some((doc) => doc.expands && /[$`]/.test(doc.body));
    const files = args.filter((word, index) => (here === -1 || (index !== here && !(args[here] === "<<<" && index === here + 1))) && !word.startsWith("-") && !/^(<|<<.*)$/.test(word)).map((word) => word.replace(/^<(?!<)/, ""));
    const texts = [];
    for (const file of files) {
      tick();
      texts.push(readFile(file));
    }
    return { sql: [...sql, ...texts.filter((text) => text !== null)], unreadable: expands || hidden || texts.includes(null), destroys: false };
  }
  // `pg_dump --clean … | psql`: the dump drops each table before re-creating it; mysqldump does by default.
  if (tool === "pg_dump" || tool === "mysqldump") {
    const clean = list.some((word) => word === "--clean" || /^-[A-Za-z]*c[A-Za-z]*$/.test(word) || word === "--add-drop-table" || word === "--add-drop-database");
    return { sql: [], unreadable: false, destroys: clean || (tool === "mysqldump" && !list.includes("--skip-add-drop-table")) };
  }
  return { sql: [], unreadable: true, destroys: false };
};

// Each SQL client's options, as getopt reads a short cluster (`-tAc "…"`, `-Xqc`, `-qf f`,
// `-c"…"`, mysql's `-Be`): the first letter that takes a value takes the rest of the cluster, or
// the next word when it is last. `text` letters carry SQL, `file` a SQL file, `host` the host, `url`
// a connection string or database; `valued` lists every letter that takes a value, and `glued` one
// whose value is only ever glued (mysql's `-ppass`; a bare `-p` prompts). `long` maps
// `--name value` / `--name=value` to the same roles. `info` matches options that only print and
// read no SQL (`psql -l`). pg_restore's `-f` is its output, and its `-c` is --clean (no value).
const CLIENT_OPTIONS = {
  psql: { text: "c", file: "f", host: "h", url: "d", valued: "cdfFhLoPpRTUv", glued: "", long: { "--command": "text", "--file": "file", "--host": "host", "--dbname": "url" }, info: /^(-l|--list|-V|--version|-\?|--help)$/ },
  pgcli: { text: "", file: "", host: "h", url: "dD", valued: "dDhpRU", glued: "", long: { "--host": "host", "--dbname": "url" }, info: /^(--version|--help)$/ },
  mysql: { text: "e", file: "", host: "h", url: "D", valued: "eDhPSu", glued: "p", long: { "--execute": "text", "--host": "host", "--database": "url" }, info: /^(-V|--version|-\?|--help)$/ },
  sqlcmd: { text: "Qq", file: "i", host: "S", url: "d", valued: "QqioSdUPHltshwacmVvyYzZfK", glued: "", long: {}, info: /^(-\?)$/ },
  pg_restore: { text: "", file: "", host: "h", url: "d", valued: "dfFhIjLnNpPStTU", glued: "", long: { "--host": "host", "--dbname": "url" }, info: /^(-l|--list|-V|--version|-\?|--help)$/ },
  prisma: { text: "", file: "", host: "", url: "", valued: "", glued: "", long: { "--file": "file", "--url": "url" }, info: /^(-h|--help)$/ },
  turso: { text: "", file: "", host: "", url: "", valued: "", glued: "", long: {}, info: /^(-h|--help)$/ },
};
CLIENT_OPTIONS.mariadb = CLIENT_OPTIONS.mysql;

// One SQL client's words (from its own), judged: where it connects ("loopback", "remote", or
// "unknown"), whether its SQL destroys data, builds SQL at run time, or can't all be read.
//
// `readFile(path)` gives a file's text, or null when it is missing, not a regular file,
// unreadable, written earlier on the line, or past the line's SQL budget. `heredoc` is the heredoc
// text fed to it, or null (`heredocExpands`: with a `$` the shell expands), `piped` the command
// before it on the line (evaluateLine()'s `previous`, or null: what a pipe would feed it when it has
// no SQL of its own), `pgHost` the kinds that PGHOSTADDR / PGSERVICE give it, `expands` which of its
// words the shell expands (parseLine()'s `expands`).
//
// Fails closed: with no SQL found on the line and stdin not provably empty (no pipe, heredoc,
// `< /dev/null`, or a print-only option like `psql -l`), it reads SQL from wherever the agent's
// stdin points (`stdinOnly`), which judgeSql() asks about against a known remote host.
const sqlClient = (list, { readFile, heredoc, heredocExpands = false, piped, pgHost, pgDefault = [], expands = [] }) => {
  const program = toolName(list[0] ?? "");
  const options = CLIENT_OPTIONS[program] ?? CLIENT_OPTIONS.psql;
  // Which words are SQL text (a flag's value, `--command=…` whole, a glued `-c…`), so a `host=` or
  // a `$` in the SQL isn't read as where it connects (`-c "DROP …; -- host=localhost"`).
  const textAt = new Set();
  const sql = [];
  const files = [];
  const hosts = [];
  const targets = [];
  // Reads stdin by name (`-f -`, `--stdin`); stdin provably holds no SQL (`< /dev/null`, `-l`); pg_restore --clean.
  let stdin = false;
  let quiet = false;
  let clean = false;
  const addFile = (path) => {
    if (STDIN_PATH.test(path)) stdin = true;
    else if (path === "/dev/null") quiet = true;
    else files.push(path);
  };
  // A value the options gave a role, at word `at`.
  const take = (role, value, at) => {
    if (role === "text") {
      textAt.add(at);
      sql.push(value);
    } else if (role === "file") addFile(value);
    else if (role === "host") hosts.push(value);
    else if (role === "url") targets.push(value);
  };
  for (let index = 1; index < list.length; index += 1) {
    tick();
    const word = list[index] ?? "";
    // `<<< "…"` and `<<<"…"` (glued): a here-string is SQL on stdin.
    if (word === "<<<") {
      index += 1;
      take("text", list[index] ?? "", index);
    } else if (word.startsWith("<<<")) take("text", word.slice(3), index);
    else if (word === "<") addFile(list[(index += 1)] ?? "");
    else if (/^<[^<]/.test(word)) addFile(word.slice(1));
    else if (options.info.test(word)) quiet = true;
    else if (word === "--stdin") stdin = true;
    else if (word === "--clean") clean = true;
    else if (word.startsWith("--")) {
      const [flag = "", attached] = word.split(/=(.*)/s);
      const role = options.long[flag];
      if (role === undefined) continue;
      if (attached !== undefined) take(role, attached, index);
      else {
        index += 1;
        take(role, list[index] ?? "", index);
      }
    } else if (/^-[^-]/.test(word)) {
      for (let k = 1; k < word.length; k += 1) {
        const letter = word[k] ?? "";
        if (program === "pg_restore" && letter === "c") clean = true;
        const glued = options.glued.includes(letter);
        if (!glued && !options.valued.includes(letter)) continue;
        const rest = word.slice(k + 1);
        const role = options.text.includes(letter) ? "text" : options.file.includes(letter) ? "file" : options.host.includes(letter) ? "host" : options.url.includes(letter) ? "url" : "other";
        if (rest !== "") take(role, rest, index);
        else if (!glued) {
          index += 1;
          take(role, list[index] ?? "", index);
        }
        break;
      }
    }
  }
  // turso takes its SQL as the argument after the database name.
  if (program === "turso") {
    for (const [index, word] of list.entries()) {
      if (index >= 4 && !word.startsWith("-")) {
        sql.push(word);
        textAt.add(index);
      }
    }
  }
  // SQL the shell builds (`-c "$SQL"`, `-c "$(cat f)"`, `$'\x44…'`) is only known when it runs.
  let unreadable = heredocExpands || [...textAt].some((index) => expands[index] === true);
  // Hosts from -h/--host/-S, any URL or connection string on the line outside the SQL, and -d's value.
  const connection = list.map((word, index) => (textAt.has(index) ? "" : word));
  const kinds = [hostsKind(hosts), ...[...explicitTargets(connection), ...targets].map(targetOf)].filter((kind) => kind !== "unknown");
  // turso's shell is the hosted database unless a URL says otherwise.
  if (program === "turso" && kinds.length === 0) kinds.push("remote");
  // libpq clients with no host on the line connect to PGHOST.
  if (/^(psql|pgcli|pg_restore)$/.test(program) && kinds.length === 0) kinds.push(...pgDefault);
  // PGHOSTADDR overrides -h, and PGSERVICE pulls the host from a file the guard doesn't read.
  kinds.push(...pgHost);
  // A `$VAR` argument outside the SQL text can be a whole connection string, and psql lets one
  // override -h; so it can't be loopback (`psql -h localhost "$PROD_URL"`).
  if (connection.some((word) => /[$`]/.test(word))) kinds.push("unknown");
  if (heredoc !== null) sql.push(heredoc);
  // pg_restore --clean (-c) drops each object before restoring it.
  let destroys = program === "pg_restore" && clean;
  // With no SQL of its own (or `-f -`), it reads whatever the command before it pipes in; with
  // nothing piped either, whatever the agent's stdin holds, unless stdin is provably empty.
  const ownSql = sql.length > 0 || files.length > 0;
  if ((!ownSql || stdin) && program !== "pg_restore") {
    if (piped !== null) {
      const fed = pipedSql(piped, readFile);
      sql.push(...fed.sql);
      unreadable ||= fed.unreadable;
      destroys ||= fed.destroys;
    } else if (heredoc === null && stdin) unreadable = true;
  }
  // No SQL on the line, nothing piped or fed, and stdin not provably empty: it reads whatever the
  // agent's stdin holds (or waits on it). judgeSql() asks about that against a known remote host.
  const stdinOnly = !ownSql && piped === null && !quiet && program !== "pg_restore";
  // The files a text pulls in: `\i` (and MySQL's `source`) from where the client runs, `\ir` from the including file's directory.
  const includes = (text, from) => {
    const found = [];
    for (const match of text.matchAll(INCLUDE)) {
      tick();
      const path = unquote(match[2] ?? "");
      found.push(normalize(/^(ir|include_relative)$/.test(match[1] ?? "") && from !== null && !isAbsolute(path) ? join(dirname(from), path) : path));
      // Past the file cap nothing more is read, so there is no need to collect more.
      if (found.length > MAX_SQL_FILES) break;
    }
    if (program === "mysql" || program === "mariadb") {
      for (const match of text.matchAll(MYSQL_SOURCE)) {
        tick();
        found.push(normalize(unquote(match[1] ?? "")));
        if (found.length > 2 * MAX_SQL_FILES) break;
      }
    }
    return found;
  };
  // Read each file and each file they pull in, once each. Past MAX_SQL_FILES files, or the line's
  // budget (readFile), the rest can't be read: a cap that quietly stopped reading would pass it.
  const queue = [];
  const enqueue = (paths) => {
    for (const path of paths) {
      tick();
      if (queue.includes(path)) continue;
      if (queue.length >= MAX_SQL_FILES) {
        unreadable = true;
        return;
      }
      queue.push(path);
    }
  };
  enqueue(files.map((path) => normalize(path)));
  for (const text of sql) enqueue(includes(text, null));
  for (const path of queue) {
    tick();
    const text = readFile(path);
    if (text === null) {
      unreadable = true;
      continue;
    }
    sql.push(text);
    enqueue(includes(text, path));
  }
  // `-v t=TABLE` or `\set`, and a `:t` in the SQL: what runs isn't what is written.
  const setsVariables = list.some((word) => /^(-v|--set|--variable)(=|$)|^-v./.test(word)) || sql.some((text) => /\\g?set\b/.test(text));
  if (program === "psql" && setsVariables && sql.some((text) => PSQL_VARIABLE.test(text))) unreadable = true;
  const text = readSqlText(sql);
  const kind = kinds.includes("remote") ? "remote" : kinds.length > 0 && kinds.every((each) => each === "loopback") ? "loopback" : "unknown";
  return { kind, destroys: destroys || text.destroys, dynamic: text.dynamic, unreadable: unreadable || text.tooLong, stdinOnly };
};

// A SQL client's verdict. Destructive SQL against a known remote host is refused; against a host the
// guard can't read (none on the line, a `$VAR`, PGSERVICE, a remote runner's own "localhost") the
// user decides, since it may well be this machine's. SQL the guard can't read, or SQL built at run
// time, is asked about. (evaluateLine()'s floor still refuses what the original whole-line rule did.)
const judgeSql = (client) => {
  if (client.kind === "loopback") return null;
  if (client.destroys && client.kind === "remote") return deny("Destructive SQL against a non-loopback database is a human action. Write it, test it on localhost, and hand the user the command.");
  if (client.destroys) return ask("This SQL deletes data, and the guard can't tell which database the client connects to (no host it can read, a `$VAR`, PGSERVICE, or a remote runner): fine on loopback or a throwaway only. Confirm the target.");
  if (client.unreadable || (client.stdinOnly && client.kind === "remote")) return ask("This SQL client runs SQL the guard can't read (piped in, `\\i`, a `$` the shell expands, `-v` variables, none on the line so stdin decides, a file that is missing, written earlier on the line, or over the line's 1 MB / 20-file budget, or a statement too long to read) against a non-loopback database: confirm it deletes nothing.");
  if (client.dynamic) return ask("This SQL builds SQL at run time (DO / EXECUTE / \\gexec) against a non-loopback database, so the guard can't read what it runs: confirm it deletes nothing.");
  return null;
};

// What PGHOSTADDR and PGSERVICE make of a client's host: a visible PGHOSTADDR by its address,
// anything unseen (or any PGSERVICE) as unknown. `lookup(name)` gives the value, null when set to
// something unseen, or undefined when unset.
const pgHostKinds = (lookup) => {
  const kinds = [];
  const address = lookup("PGHOSTADDR");
  if (address !== undefined) kinds.push(address === null ? "unknown" : hostsKind(address.split(",")));
  if (lookup("PGSERVICE") !== undefined) kinds.push("unknown");
  return kinds;
};

// What PGHOST makes of a client's host when the line names none: its address, or unknown when it is
// set to something unseen; nothing when unset (the default socket, which may be this machine's).
const pgDefaultKinds = (lookup) => {
  const host = lookup(PG_HOST_DEFAULT);
  if (host === undefined) return [];
  return [host === null ? "unknown" : hostsKind(host.split(","))];
};

// `pnpm -C dir …`, `npm --prefix dir run x`, `pnpm --filter api …`: a package-manager line with
// flags that move it. { name, rest } for a script, { line } for `exec`/`dlx`, plus `dir` (null
// when it stays put) and `wrapped` (it runs in packages the guard can't see); null when no such flag.
const packageScript = (list) => {
  let index = 0;
  while (assigned(list[index] ?? "") !== undefined) index += 1;
  const manager = list[index] ?? "";
  if (!/^(pnpm|npm|yarn|bun)$/.test(manager)) return null;
  let dir = null;
  let wrapped = false;
  for (index += 1; index < list.length; index += 1) {
    const word = list[index] ?? "";
    const [flag = "", attached] = word.split(/=(.*)/s);
    // A flag that takes a value takes the next word when none is attached.
    const value = () => attached ?? list[(index += 1)] ?? "";
    if (/^(-C|--dir|--prefix|--cwd)$/.test(flag)) dir = value();
    else if (/^(--filter|-F|--workspace)$/.test(flag) || (manager === "npm" && flag === "-w")) {
      value();
      wrapped = true;
    } else if (/^(-r|--recursive|-w|--workspace-root|--workspaces|-ws)$/.test(flag)) wrapped = true;
    else if (!word.startsWith("-")) break;
  }
  if (dir === null && !wrapped) return null;
  if (list[index] === "run" || list[index] === "run-script") index += 1;
  if (/^(exec|dlx|x)$/.test(list[index] ?? "")) return { line: shellJoin(list.slice(index + 1)), dir, wrapped };
  return { name: list[index] ?? "", rest: list.slice(index + 1).map((word) => ` ${shellQuote(word)}`).join(""), dir, wrapped };
};

// `npm run x`, `bun run x`, `run x`, or a bare script name after pnpm/yarn (which programStart drops): { name, rest }.
const scriptCall = (text) => {
  const script = text.match(/^(?:(?:npm|bun)\s+(?:run|run-script)\s+|run\s+)?(\S+)(.*)$/);
  return script ? { name: script[1] ?? "", rest: script[2] ?? "" } : null;
};

// One word quoted for the shell again, so a rebuilt line splits the same way (`-c "DROP TABLE t"`).
const shellQuote = (word) => (/^[\w@%+=:,./-]+$/.test(word) ? word : `'${word.replaceAll("'", `'\\''`)}'`);
const shellJoin = (list) => list.map(shellQuote).join(" ");

// The migration tool in a command's words: the first word whose program (basename, `@version`
// removed) starts a MIGRATE_COMMANDS match from there on; { command, at } or null.
const migrateTool = (list) => {
  for (const [at, word] of list.entries()) {
    const tool = toolName(word);
    if (!MIGRATE_TOOLS.has(tool)) continue;
    const text = [tool, ...list.slice(at + 1)].join(" ");
    const command = MIGRATE_COMMANDS.find((candidate) => candidate.match.test(text));
    if (command !== undefined) return { command, at };
  }
  return null;
};

// The values a command's words give `flags` (`--schema x`, `--schema=x`, `-u x`).
const flagValues = (list, flags) =>
  list.flatMap((word, index) => {
    const [flag = "", attached] = word.split(/=(.*)/s);
    if (flags.includes(flag) && attached !== undefined) return [attached];
    return flags.includes(word) ? [list[index + 1] ?? ""] : [];
  });

// The worst of several targets: remote beats unseen beats unknown beats loopback.
const worstKind = (kinds) => ["remote", "unseen", "unknown", "loopback"].find((kind) => kinds.includes(kind)) ?? "unknown";

// A Prisma schema's or config's text with `//` comments blanked, outside strings (a URL's `//`
// stays), so a commented-out `// url = "postgres://localhost…"` isn't read as the datasource.
const withoutLineComments = (text) =>
  text
    .split("\n")
    .map((line) => {
      let quote = "";
      for (let i = 0; i < line.length; i += 1) {
        tick();
        const char = line[i];
        if (quote !== "") {
          if (char === "\\") i += 1;
          else if (char === quote) quote = "";
        } else if (char === '"' || char === "'" || char === "`") quote = char;
        else if (char === "/" && line[i + 1] === "/") return line.slice(0, i);
      }
      return line;
    })
    .join("\n");

// What a Prisma `url` / `directUrl` value is: { literal } for a quoted URL, { name } for
// `env("NAME")` / `process.env.NAME` / `process.env["NAME"]`, {} for anything else (a variable the
// config computes), which the guard can't read.
const prismaUrl = (raw) => {
  const value = raw.trim();
  const literal = /^["'`]([^"'`]*)["'`]/.exec(value);
  if (literal) return { literal: literal[1] };
  const name = /^env\(\s*["'`](\w+)["'`]\s*\)/.exec(value) ?? /^process\.env\.(\w+)/.exec(value) ?? /^process\.env\[\s*["'`](\w+)["'`]\s*\]/.exec(value);
  return name ? { name: name[1] } : {};
};

// The Prisma schema and config texts at `paths` (`//` comments blanked): { texts: [{ path, text }],
// unseen: [path] }. A path that is a folder (a multi-file schema) gives each `.prisma` file in it,
// nested folders too, within MAX_PRISMA_FILES / MAX_PRISMA_DEPTH / MAX_SQL_FILE_BYTES. Unseen: a
// folder past those bounds or written to earlier on the line, or something there that can't be
// read (too big, not a regular file). A path where nothing is says nothing.
const prismaTexts = (paths, readIn, listIn) => {
  const texts = [];
  const unseen = [];
  let files = 0;
  let bytes = 0;
  const visit = (path, depth) => {
    tick();
    const text = readIn(path);
    if (text !== null) {
      bytes += text.length;
      texts.push({ path, text: withoutLineComments(text) });
      return;
    }
    const listed = listIn(path);
    if (listed === null || listed === undefined) return;
    if (listed.dir !== true || listed.more === true || depth >= MAX_PRISMA_DEPTH) {
      unseen.push(path);
      return;
    }
    for (const name of listed.files.filter((each) => each.endsWith(".prisma"))) {
      tick();
      files += 1;
      const inner = files > MAX_PRISMA_FILES || bytes > MAX_SQL_FILE_BYTES ? null : readIn(join(path, name));
      if (inner === null) {
        unseen.push(join(path, name));
        continue;
      }
      bytes += inner.length;
      texts.push({ path: join(path, name), text: withoutLineComments(inner) });
    }
    for (const name of listed.dirs) visit(join(path, name), depth + 1);
  };
  for (const path of new Set(paths)) visit(path, 0);
  return { texts, unseen };
};

// Where package.json's `"prisma": { "schema": … }` and a config's `schema: "…"` move the schema;
// [] when they say nothing. Read loosely: a wrong guess only adds a path that reads as nothing.
const prismaSchemaPaths = (readIn, configs) => {
  const paths = [];
  try {
    const pkg = JSON.parse(readIn("package.json") ?? "null")?.prisma?.schema;
    if (typeof pkg === "string" && pkg.trim() !== "") paths.push(pkg.trim());
  } catch {
    // A package.json that doesn't parse names no schema; Prisma would fail to start.
  }
  for (const config of configs) {
    for (const match of config.text.matchAll(/\bschema\s*:\s*["'`]([^"'`\n]+)["'`]/g)) {
      tick();
      // Relative to the project root, or to the config's own folder (`.config/prisma.ts`): both are read.
      paths.push(match[1] ?? "", join(dirname(config.path), match[1] ?? ""));
    }
  }
  return paths.filter((path) => path !== "");
};

// A migration tool's verdict: what it does (MIGRATE_COMMANDS) against where it points.
//
// Where it points, first match wins: a connection string on the command line; the tool's variable
// set in front of it (`DATABASE_URL=… prisma …`, `cross-env`); set earlier on the line (`export`);
// the environment or the dotenv files it loads (`targetIn(name, file)`). "unseen" means set to
// something the guard can't read (`$VAR`, a secrets loader, `source`, `eval`, `--schema` elsewhere):
// every effect asks. `wrapped` says the line runs behind a wrapper the guard doesn't model.
const evaluateMigrate = (list, lineEnv, { wrapped, targetIn, readIn, listIn = () => null }) => {
  // `echo run prisma migrate reset`: a word in a printout or a search, not a command.
  if (NON_RUNNERS.has(toolName(list[programStart(list)] ?? ""))) return null;
  const found = migrateTool(list);
  if (found === null) return null;
  const { command, at } = found;
  const after = list.slice(at + 1);
  const prefix = prefixOf(list.slice(0, at));
  // A Prisma config file present: the URL may come from it (and Prisma loads no .env itself then).
  let configured = false;
  // Resolve the target and say where it came from, for the reason.
  const resolveTarget = () => {
    if (command.remoteFlag !== undefined && after.includes(command.remoteFlag)) return { kind: "remote", from: command.remoteFlag };
    const onLine = [...explicitTargets(after), ...flagValues(after, command.urlFlags ?? [])];
    if (onLine.length > 0) return { kind: worstKind(onLine.map(targetOf)), from: "the command line", trusted: true };
    const hidden = (command.hiddenFlags ?? []).find((flag) => flagValues(after, [flag]).length > 0);
    if (hidden !== undefined) return { kind: "unseen", from: `${hidden} loads another env file` };
    // A schema or config somewhere else loads that directory's .env, which the guard doesn't read.
    const [schema] = flagValues(after, command.schemaFlags ?? []);
    if (schema !== undefined && !/^(\.\/)?(prisma\/)?[^/]*$/.test(schema)) return { kind: "unseen", from: `the .env beside ${schema}` };
    if (prefix.loaded) return { kind: "unseen", from: "a secrets loader" };
    // The dotenv files the tool loads: its own, plus the .env beside a schema that package.json or
    // a Prisma config moved (Prisma loads that one too).
    let envFiles = command.envFiles ?? [".env"];
    // A variable as the tool sees it: set in front of it, else earlier on the line (`env -i` and
    // plain `sudo` clear the rest), else the environment and the dotenv files it loads. Null when
    // it is set nowhere.
    const resolveVar = (name) => {
      const inFront = prefix.vars.has(name);
      const own = inFront ? prefix.vars.get(name) : prefix.cleared ? UNSET : lineEnv.has(name) ? lineEnv.get(name) : undefined;
      if (own === null) return { kind: "unseen", from: inFront ? `${name} set on this line` : `${name} after \`source\`, \`eval\`, or a loader` };
      if (typeof own === "string") return { kind: targetOf(own), from: `${name} set on this line` };
      // Not set on the line: the environment, then the dotenv files the tool loads. Removed
      // (`unset`, `env -u`, `env -i`): only the files, since the tool no longer sees the environment.
      const files = envFiles.map((file) => targetIn(name, file, own !== UNSET)).filter((each) => each !== null && each !== undefined);
      if (files.length > 0) return { kind: worstKind(files.map((each) => targetOf(each.value))), from: `${name} from ${[...new Set(files.map((each) => each.from))].join(" and ")}` };
      return null;
    };
    // Prisma: the datasource's `url` and `directUrl` in the schema and config files (`//` comments
    // blanked), each a literal or a variable it names (any name: PROD_URL, POSTGRES_PRISMA_URL);
    // the worst of them is the target. A config file present means a loopback .env reading isn't
    // trusted (below): the config decides what Prisma loads. Read from the default places, `--schema`,
    // package.json's `prisma.schema`, and a config's `schema:`; a folder gives each `.prisma` in it.
    //
    // A reset runs on loopback only on positive evidence: a datasource block the guard read, every
    // `url` / `directUrl` in it loopback. With none read (a schema somewhere it doesn't look, a folder
    // past its bounds) it asks, rather than trusting DATABASE_URL, which the schema may never name.
    if (command.prisma === true) {
      const configs = prismaTexts(PRISMA_CONFIGS, readIn, () => null);
      const moved = prismaSchemaPaths(readIn, configs.texts);
      envFiles = [...new Set([...envFiles, ...moved.flatMap((path) => [join(dirname(path), ".env"), join(path, ".env")])])];
      const schemas = prismaTexts([...PRISMA_SCHEMAS, ...(schema === undefined ? [] : [schema]), ...moved], readIn, listIn);
      const texts = [...configs.texts, ...schemas.texts].filter((each) => each.text.trim() !== "");
      configured = texts.some((each) => PRISMA_CONFIGS.includes(each.path));
      const urls = texts.flatMap((each) =>
        [...each.text.matchAll(PRISMA_URL_KEY)].map((match) => {
          const value = prismaUrl(match[2] ?? "");
          if (value.literal !== undefined) return { kind: targetOf(value.literal), from: `the URL written in ${each.path}`, trusted: true };
          if (value.name !== undefined) return resolveVar(value.name) ?? { kind: "unknown", from: `${value.name} (named in ${each.path}, set nowhere the guard reads)` };
          return { kind: "unseen", from: `the ${match[1] ?? "url"} in ${each.path}` };
        }),
      );
      const entries = [...urls, ...[...configs.unseen, ...schemas.unseen].map((path) => ({ kind: "unseen", from: `${path}, a schema the guard can't read in full` }))];
      const worst = worstKind(entries.map((each) => each.kind));
      const read = urls.length > 0 && texts.some((each) => /\bdatasource\b/.test(each.text));
      if (entries.length > 0 && (worst !== "loopback" || read || command.effect !== "destroys")) return entries.find((each) => each.kind === worst) ?? { kind: worst, from: "" };
      if (command.effect === "destroys") {
        // No datasource read: a remote DATABASE_URL still refuses; anything else asks.
        const fallback = command.vars.map(resolveVar).find((each) => each !== null);
        if (fallback?.kind === "remote") return fallback;
        return { kind: "unseen", from: "no Prisma datasource the guard could read: a schema in a place it doesn't look, or none with a url" };
      }
    }
    for (const name of command.vars) {
      const resolved = resolveVar(name);
      if (resolved !== null) return resolved;
    }
    return { kind: command.unset ?? "unknown", from: "" };
  };
  const target = resolveTarget();
  // A value that is set but names no host the guard can read is unseen, not merely absent.
  const trustsLoopback = command.config !== true && !configured;
  const kind = target.kind === "unknown" && target.from !== "" ? "unseen" : target.kind === "loopback" && !trustsLoopback && target.trusted !== true ? "unknown" : target.kind;
  const from = target.from;
  // Points at a real database (the URL itself is never echoed: it can hold a password).
  if (kind === "remote") {
    if (command.effect === "destroys") return deny(`${command.what}, and it points at a non-loopback database (${from}). Resetting, dropping, or rolling back a real database is a human action: hand the user the exact command and what it destroys.`);
    if (command.effect === "dev") return deny(`${command.what}, and it points at a non-loopback database (${from}). A real database gets deploy-only migrations, run by the user or CI.`);
    return ask(`${command.what} against a non-loopback database (${from}): applying migrations to a real environment is the user's or CI's job; writing them is yours.`);
  }
  // Behind a wrapper the guard doesn't model, a loopback reading proves nothing.
  if (wrapped || prefix.unmodelled) return ask(`${command.what}, behind a wrapper the guard doesn't model, so it can't tell which database it points at. Fine on a loopback or throwaway database only: confirm it.`);
  if (kind === "loopback") return null;
  // Set to something the guard can't read: every effect needs the user to confirm the target.
  if (kind === "unseen") return ask(`${command.what}, and the guard can't read which database it points at (${from}). Fine on a loopback or throwaway database only: confirm it.`);
  // Nothing set: a destructive command needs the user to confirm it's local or throwaway.
  if (command.effect === "destroys") return ask(`${command.what}, and the guard can't see which database it points at${trustsLoopback ? "" : " (its config file decides)"}. Fine on a loopback or throwaway database only: confirm it.`);
  return null;
};

// A variable's value in a dotenv file's text, or undefined, read as the dotenv package reads it:
// `KEY=value` or `KEY: value`, optional `export`, the last one wins, an unquoted value ends at `#`,
// and a quoted value may run over several lines (a `KEY=` line inside one is part of the value, not a key).
export const dotenvValue = (text, name) => {
  // A byte-order mark (an editor's UTF-8 BOM) isn't part of the first key, as dotenv reads it.
  const source = text.replace(/^﻿/, "").replace(/\r\n?/g, "\n");
  let value;
  let at = 0;
  while (at < source.length) {
    tick();
    const lineEnd = source.indexOf("\n", at);
    const end = lineEnd === -1 ? source.length : lineEnd;
    const key = /^[ \t]*(?:export[ \t]+)?([\w.-]+)(?:[ \t]*=|:[ \t])[ \t]*/.exec(source.slice(at, end));
    if (key === null) {
      at = end + 1;
      continue;
    }
    const start = at + key[0].length;
    const quote = source[start] ?? "";
    let found;
    if (quote === "'" || quote === '"' || quote === "`") {
      // To the matching quote, which may be lines away; a backslash escapes one.
      let close = start + 1;
      while (close < source.length && source[close] !== quote) close += source[close] === "\\" ? 2 : 1;
      if (close < source.length) {
        found = source.slice(start + 1, close);
        const after = source.indexOf("\n", close);
        at = after === -1 ? source.length : after + 1;
      }
    }
    // Unquoted (or a quote that never closes): the rest of the line, up to a comment.
    if (found === undefined) {
      found = source.slice(start, end).replace(/#.*$/, "").trim();
      at = end + 1;
    }
    if (key[1] === name) value = found;
  }
  return value;
};

// ── Infrastructure rules, read by evaluate() once for the whole line ──
//
// An apply has many spellings (quotes glued to bare text, `\` escapes, `$'…'`, line continuations,
// wrappers, substitutions, a shell fed on stdin), and text the shell never runs (a single-quoted
// argument, a `<<'EOF'` body, a commit message) must not read as a command either. Each wrapper is
// read the way it runs its command (runs()): env/sudo/timeout/xargs run the program word after their
// own options; ssh, eval, and `sh -c` take a command string. What a command is fed on stdin (a
// heredoc, a here-string, a pipe, `< <(…)`) goes with it into a shell, and into a command string a
// wrapper runs (`ssh host bash <<<'…'`).

// Deepest nesting followed (a substitution, a wrapper's command string, a shell's stdin); deeper asks.
const MAX_DEPTH = 8;

// Most wrappers stacked in front of one program (`nohup nice sudo …`); more asks rather than recursing on.
const MAX_WRAPPERS = 32;

// Words read after an IaC or cloud CLI word printed into a shell: enough for any verb, bounded so a huge line stays linear.
const PRINTED_WINDOW = 64;

// The line mentions an IaC CLI or its verbs: xargs could hand one of these CLIs its verb.
const MENTIONS_IAC = /\b(terraform|tofu|terragrunt|apply|destroy)\b/i;

// The line names an IaC CLI: a program held in a variable could be one an earlier command stored
// (`T=terraform; $T $V`). A verb alone doesn't count, so `git apply x && $HOME/bin/check` runs.
const NAMES_IAC = /\b(terraform|tofu|terragrunt)\b/i;

// Cloud CLI verbs that delete: `delete-*`, `terminate-*`, `purge-*`, `deregister-*`, `destroy`, and their batch forms.
const DELETE_VERB = /^(batch-)?(delete|terminate|purge|deregister|destroy)(-|$)/;

// Words that ask any of these CLIs for help instead of running the verb (gsutil's -h is a header, handled there).
const HELP_FLAGS = new Set(["-h", "-help", "--help"]);

// A `VAR=value` (or `arr[i]=`, `VAR+=`) word before the program.
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=/;

// Shell keywords that stand in front of a command (`if X; then Y; fi`): the program is the next word.
const KEYWORDS = new Set(["if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "{", "}"]);

// Keywords whose words are not a command (`for d in a b`, `case x in`); a case body follows a `)`, which ends the command.
const NOT_A_COMMAND = new Set(["for", "case", "esac", "select", "in", "[[", "]]"]);

// Files that are the shell's own stdin, so `bash /dev/stdin <<<…` or `source /dev/stdin` runs what it is fed.
const STDIN_FILES = new Set(["/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"]);

// CDK CLIs (AWS CDK and CDK for Terraform), whose deploy is an apply.
const CDK_CLI = /^cdk(tf)?(\.cmd|\.exe)?$/i;



// True for a word that names an IaC, CDK, or cloud CLI.
const isInfraCli = (value) => {
  const name = programName(value);
  return IAC_CLI.test(name) || CDK_CLI.test(name) || CLOUD_CLI.test(name);
};

// The stronger of some verdicts (deny, then ask), or null.
const strongest = (verdicts) => verdicts.find((verdict) => verdict?.decision === "deny") ?? verdicts.find(Boolean) ?? null;

// Index of the first word at or after k that isn't an option. `--` ends options; a long option in
// `long` takes the next word; in a short cluster, the first letter in `short` takes the rest of
// the cluster or, when it is last, the next word (getopt's reading: `-iu bob`, `-ubob`).
const pastOptions = (list, k, { short = "", long = [] } = {}) => {
  let i = k;
  while (i < list.length) {
    const value = list[i]?.value ?? "";
    if (value === "--") return i + 1;
    if (!value.startsWith("-") || value === "-") return i;
    i += 1;
    if (value.startsWith("--")) {
      if (long.includes(value)) i += 1;
      continue;
    }
    const at = short === "" ? -1 : value.slice(1).search(new RegExp(`[${short}]`));
    if (at !== -1 && at === value.length - 2) i += 1;
  }
  return i;
};

// A command string made of some list, as the wrapper joins them; none when there are no list.
const commandString = (list) => (list.length === 0 ? [] : [{ line: list.map((word) => word.value).join(" ") }]);

// A shell's arguments: `-c` (fish: `--command`, `-C`) takes a command string; no script, `-s`,
// `-`, or /dev/stdin reads stdin; `<(X)` runs what X prints; any other script file is opaque.
// Under xargs, `-c` with no string (or one holding the placeholder) gets its command from stdin too.
const shellRuns = (list, k, xargs, name) => {
  let i = k;
  let string = false;
  let stdin = false;
  while (i < list.length) {
    const value = list[i]?.value ?? "";
    if (value === "--" || value === "-") {
      i += 1;
      break;
    }
    if (/^[-+][oO]$/.test(value) || value === "--rcfile" || value === "--init-file") {
      i += 2;
      continue;
    }
    if (value === "--command" || value === "--init-command") {
      string = true;
      i += 1;
      break;
    }
    const glued = /^--(?:init-)?command=(.*)$/s.exec(value);
    if (glued) return [...(xargs ? [{ stdin: true }] : []), { line: glued[1], xargs }];
    if (/^-[A-Za-z]+$/.test(value)) {
      string ||= value.includes("c") || (name === "fish" && value.includes("C"));
      stdin ||= value.includes("s");
      i += 1;
      continue;
    }
    if (/^\+[A-Za-z]+$/.test(value) || value.startsWith("--")) {
      i += 1;
      continue;
    }
    break;
  }
  if (string) return [...(xargs ? [{ stdin: true }] : []), ...commandString(list.slice(i, i + 1)).map((target) => ({ ...target, xargs }))];
  const script = list[i];
  if (script !== undefined && STDIN_FILES.has(script.value)) return [{ stdin: true }];
  if (script?.proc?.dir === "<") return [{ printed: script.proc.text }];
  return stdin || i >= list.length ? [{ stdin: true }] : [];
};

// Credential and environment loaders (`aws-vault exec prod -- X`, `op run -- X`, `nix-shell --run 'X'`):
// the program after `--`, else a command-string option's value, else the first IaC or cloud CLI word.
const loaderRuns = (list, k, xargs, hops) => {
  const dashes = list.findIndex((word, j) => j >= k && word.value === "--");
  if (dashes !== -1) return runs(list.slice(dashes + 1), xargs, hops);
  const string = list.findIndex((word, j) => j >= k && ["--run", "--command", "--exec", "-c"].includes(word.value));
  if (string !== -1) return commandString(list.slice(string + 1));
  const program = list.findIndex((word, j) => j >= k && isInfraCli(word.value));
  return program === -1 ? [] : runs(list.slice(program), xargs, hops);
};

// A wrapper that runs the program word after its own options.
const programAfter = (options) => (list, k, xargs, hops) => runs(list.slice(pastOptions(list, k, options)), xargs, hops);

// A wrapper whose first operand isn't the program (timeout's duration, envchain's namespace): the program follows it.
const programAfterOperand = (options) => (list, k, xargs, hops) => runs(list.slice(pastOptions(list, k, options) + 1), xargs, hops);

// sudo and doas: the program after their options; with -s / -i and no program, a shell reading stdin.
const sudoRuns = (list, k, xargs, hops) => {
  const i = pastOptions(list, k, { short: "ugpCUrtThDRc", long: ["--user", "--group", "--host", "--prompt", "--close-from", "--other-user", "--role", "--type", "--command-timeout", "--chdir", "--chroot", "--login-class"] });
  if (i < list.length) return runs(list.slice(i), xargs, hops);
  const shell = list.slice(k, i).some((word) => /^-[^-]*[si]/.test(word.value) || word.value === "--shell" || word.value === "--login");
  return shell ? [{ stdin: true }] : [];
};

// `source X` / `. X`: X runs in this shell, so /dev/stdin runs what is fed and `<(Y)` runs what Y prints.
const sourceRuns = (list, k) => {
  const file = list[pastOptions(list, k)];
  if (file === undefined) return [];
  if (STDIN_FILES.has(file.value)) return [{ stdin: true }];
  return file.proc?.dir === "<" ? [{ printed: file.proc.text }] : [];
};

// pnpm, yarn, and npm: `exec`/`dlx` run the program after their options; `-c`/`--shell-mode` (pnpm) and `-c`/`--call` (npm) make what follows a command string, wherever the option sits (`pnpm -c exec '…'`, `npm exec --call='…'`); a bare word runs that bin.
const SHELL_FLAGS = new Set(["-c", "--shell-mode", "--call"]);
const packageRunnerRuns = (list, k, xargs, hops) => {
  const i = pastOptions(list, k, { short: "CF", long: ["--dir", "--filter", "--reporter", "--loglevel", "--workspace-concurrency"] });
  const before = list.slice(k, i);
  if (!["exec", "dlx", "x"].includes(list[i]?.value ?? "")) return before.some((word) => word.value === "-c" || word.value === "--shell-mode") ? commandString(list.slice(i)) : runs(list.slice(i), xargs, hops);
  const j = pastOptions(list, i + 1, { short: "p", long: ["--package"] });
  const flags = [...before, ...list.slice(i + 1, j)];
  // `--call='…'` carries the string in the option itself.
  const glued = flags.map((word) => ({ word, text: /^--call=(.*)$/s.exec(word.value)?.[1] })).find((entry) => entry.text !== undefined);
  if (glued?.text !== undefined) return commandString([{ ...glued.word, value: glued.text }]);
  if (flags.some((word) => SHELL_FLAGS.has(word.value))) return commandString(list.slice(j));
  return runs(list.slice(j), xargs, hops);
};

// The replace string an xargs call puts its input in for (`-I {}`, `-I%`, `-i`, `--replace`), or "".
const xargsReplace = (list, k, end) => {
  let replace = "";
  for (let j = k; j < end; j += 1) {
    const value = list[j]?.value ?? "";
    if (value === "--replace" || value === "-i") replace = "{}";
    else if (value.startsWith("--replace=")) replace = value.slice(10);
    else if (/^-i./.test(value)) replace = value.slice(2);
    else if (/^-[^-]*I/.test(value)) {
      const rest = value.slice(value.indexOf("I") + 1);
      replace = rest === "" ? (list[j + 1]?.value ?? "") : rest;
    }
  }
  return replace;
};

// `docker`/`podman` `exec` runs the program after the container, and `compose exec|run` after the
// service (`docker-compose` starts at compose); the image's own entrypoint is the fallback's (judge()).
const CONTAINER_VALUED = { short: "euwpvl", long: ["--env", "--env-file", "--user", "--workdir", "--detach-keys", "--entrypoint", "--name", "--publish", "--volume", "--label", "--index", "--network", "--pull", "--platform"] };
const containerRuns = (compose) => (list, k, xargs, hops) => {
  let i = k;
  let composed = compose;
  if (!compose) {
    i = pastOptions(list, k, { short: "Hcl", long: ["--host", "--context", "--config", "--log-level"] });
    composed = list[i]?.value === "compose";
    if (composed) i += 1;
  }
  if (composed) i = pastOptions(list, i, { short: "fp", long: ["--file", "--project-name", "--profile", "--env-file", "--project-directory", "--ansi", "--progress", "--parallel"] });
  const sub = list[i]?.value ?? "";
  if (sub !== "exec" && !(composed && sub === "run")) return [];
  const service = pastOptions(list, i + 1, CONTAINER_VALUED);
  const inside = runs(list.slice(service + 1), xargs, hops);
  // A compose service named for its image (`compose run --rm terraform apply`): the service's
  // entrypoint runs the rest, so the service word and what follows also go to the fallback.
  return composed ? [...inside, { argv: [list[k - 1], ...list.slice(service)], xargs }] : inside;
};

// A wrapper that, when it finds nothing it runs, is judged as a program itself (`docker run IMAGE
// apply`, `kubectl run … -- destroy`), so judge()'s fallback still reads its words.
const orOwnRun = (wrapper) => (list, k, xargs, hops) => {
  const found = wrapper(list, k, xargs, hops);
  return found.length > 0 ? found : [{ argv: list.slice(k - 1), xargs }];
};

// A loader that is also a cloud CLI (`heroku run -- X`, `fly …`): judged as itself, and what it runs.
const ownAndLoader = (list, k, xargs, hops) => [{ argv: list.slice(k - 1), xargs }, ...loaderRuns(list, k, xargs, hops)];

// su's -c string (a bare `su user` is an interactive shell).
const suRuns = (list, k) => {
  for (let i = k; i < list.length; i += 1) {
    const value = list[i]?.value ?? "";
    if (/^-[A-Za-z]*c$/.test(value) || value === "--command" || value === "--session-command") return commandString(list.slice(i + 1, i + 2));
    const glued = /^--(?:session-)?command=(.*)$/s.exec(value);
    if (glued) return commandString([{ value: glued[1] }]);
  }
  return [];
};

// PowerShell options that take a value (any case), so the value isn't read as a command.
const PWSH_VALUED = /^-(ex|ep|executionpolicy|wd|workingdirectory|config|configurationname|configurationfile|of|outputformat|if|inputformat|settingsfile|windowstyle|w|custompipename|version|v)$/i;

// PowerShell: `-Command` (any prefix, any case) runs the rest as a command line and `-Command -`
// reads stdin; `-EncodedCommand` is base64 the guard can't read, so it asks; `-File -` reads stdin.
// powershell.exe, unlike pwsh, reads a bare first argument as a command too.
const powershellRuns = (bareIsCommand) => (list, k) => {
  for (let i = k; i < list.length; i += 1) {
    const value = list[i]?.value ?? "";
    if (/^-c(o(m(m(a(n(d)?)?)?)?)?)?$/i.test(value)) return list[i + 1]?.value === "-" ? [{ stdin: true }] : commandString(list.slice(i + 1));
    if (/^-e(c|n(c(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?)?)?)?)?)?)?)?$/i.test(value)) return [{ ask: "PowerShell's -EncodedCommand is base64 the guard can't read; the user confirms it changes no infrastructure." }];
    if (/^-(f|file)$/i.test(value)) return list[i + 1]?.value === "-" ? [{ stdin: true }] : [];
    if (value.startsWith("-")) {
      if (PWSH_VALUED.test(value)) i += 1;
      continue;
    }
    return bareIsCommand ? commandString(list.slice(i)) : [];
  }
  return [];
};

// git itself, plus what it runs: a `-c core.sshCommand=…` value (through sh, when it connects),
// `submodule foreach`'s and `rebase --exec`'s strings, and `bisect run`'s program.
const gitRuns = (list, k, xargs, hops) => {
  const i = pastOptions(list, k, { short: "Cc", long: ["--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"] });
  const found = [{ argv: list.slice(k - 1), xargs }];
  for (let j = k + 1; j < i; j += 1) {
    const set = list[j - 1]?.value === "-c" ? /^core\.sshcommand=(.*)$/is.exec(list[j]?.value ?? "") : null;
    if (set) found.push(...commandString([{ value: set[1] }]));
  }
  const sub = list[i]?.value ?? "";
  if (sub === "submodule") {
    const at = list.findIndex((word, j) => j > i && word.value === "foreach");
    if (at !== -1) found.push(...commandString(list.slice(pastOptions(list, at + 1))));
  } else if (sub === "rebase") {
    for (let j = i + 1; j < list.length; j += 1) {
      const value = list[j]?.value ?? "";
      const glued = /^(?:--exec=|-x)(.+)$/s.exec(value);
      if (value === "-x" || value === "--exec") found.push(...commandString(list.slice(j + 1, j + 2)));
      else if (glued) found.push(...commandString([{ value: glued[1] }]));
    }
  } else if (sub === "bisect" && list[i + 1]?.value === "run") found.push(...runs(list.slice(i + 2), xargs, hops));
  return found;
};

// What each wrapper runs: [{ argv, xargs }] for a program, [{ line }] for a command string,
// [{ stdin }] for a shell reading stdin, [{ printed }] for one running what a command prints.
// The catalog is kept to wrappers an agent reaches for; behind any other program, judge()'s
// fallback asks when the words after it are an apply or a cloud delete.
const WRAPPERS = {
  env: (list, k, xargs, hops) => {
    let i = k;
    while (i < list.length) {
      const value = list[i]?.value ?? "";
      if (value === "--") {
        i += 1;
        break;
      }
      // A lone `-` is `-i`.
      if (value === "-") {
        i += 1;
        continue;
      }
      if (!value.startsWith("-")) break;
      // `env -S 'X …'` / `--split-string`: env splits the string into a command line; the words
      // after it stay whole, so they are quoted back in.
      const splitString = /^--split-string(?:=(.*))?$/s.exec(value);
      const at = value.startsWith("--") ? -1 : value.slice(1).search(/[SuCaP]/);
      if (splitString || value[at + 1] === "S") {
        const glued = splitString ? splitString[1] : value.slice(at + 2);
        const string = glued ? glued : (list[i + 1]?.value ?? "");
        const rest = list.slice(glued ? i + 1 : i + 2).map((word) => shellQuote(word.value));
        return [{ line: [string, ...rest].join(" ") }];
      }
      if (value.startsWith("--")) {
        i += ["--unset", "--chdir", "--argv0"].includes(value) ? 2 : 1;
        continue;
      }
      // A short cluster (`-iu X`): -u, -C, -a, -P take the rest of the cluster, or the next word.
      if (at === -1) i += 1;
      else i += value.slice(at + 2) ? 1 : 2;
    }
    return runs(list.slice(i), xargs, hops);
  },
  sudo: sudoRuns,
  doas: sudoRuns,
  nice: programAfter({ short: "n", long: ["--adjustment"] }),
  nohup: programAfter(),
  time: programAfter({ short: "fo", long: ["--format", "--output"] }),
  // timeout's first operand is the duration; the program follows it.
  timeout: programAfterOperand({ short: "sk", long: ["--signal", "--kill-after"] }),
  // The shell's own: `command -v X` only looks X up.
  command: (list, k, xargs, hops) => (list.slice(k).some((word) => /^-[A-Za-z]*[vV]/.test(word.value)) ? [] : programAfter()(list, k, xargs, hops)),
  builtin: programAfter(),
  exec: programAfter({ short: "a" }),
  eval: (list, k) => commandString(list.slice(k)),
  source: sourceRuns,
  ".": sourceRuns,
  // xargs appends what it reads from stdin, or puts it in for its replace string, so its program's
  // verb may not be on the line at all; a placeholder or a missing verb is judged by iacVerdict().
  xargs: (list, k, _xargs, hops) => {
    const i = pastOptions(list, k, { short: "ILnPsdEa", long: ["--arg-file", "--delimiter", "--max-args", "--max-lines", "--max-procs", "--max-chars"] });
    const replace = xargsReplace(list, k, i);
    return runs(list.slice(i), { placeholder: (value) => replace !== "" && value.includes(replace) }, hops);
  },
  // npx runs the program after its options, or its own `-c` / `--call` string (not the program's `-c`).
  npx: (list, k, xargs, hops) => {
    const i = pastOptions(list, k, { short: "pc", long: ["--package", "--call"] });
    const call = list.findIndex((word, j) => j >= k && j < i && (word.value === "-c" || word.value === "--call"));
    return call === -1 ? runs(list.slice(i), xargs, hops) : commandString(list.slice(call + 1, call + 2));
  },
  bunx: programAfter({ short: "p", long: ["--package"] }),
  dlx: programAfter(),
  pnpm: packageRunnerRuns,
  yarn: packageRunnerRuns,
  npm: (list, k, xargs, hops) => (["exec", "x"].includes(list[pastOptions(list, k)]?.value ?? "") ? packageRunnerRuns(list, k, xargs, hops) : []),
  // corepack runs the package manager it names (`corepack pnpm@9 exec …`); its own subcommands run nothing.
  corepack: (list, k, xargs, hops) => {
    const i = pastOptions(list, k);
    const name = (list[i]?.value ?? "").replace(/@.*$/, "");
    return /^(pnpm|yarn|npm|npx)$/.test(name) ? runs([{ ...list[i], value: name }, ...list.slice(i + 1)], xargs, hops) : [];
  },
  // ssh sends everything after the host as one command string; with none, the remote shell reads stdin.
  su: suRuns,
  busybox: programAfter(),
  pwsh: powershellRuns(false),
  "pwsh.exe": powershellRuns(false),
  powershell: powershellRuns(true),
  "powershell.exe": powershellRuns(true),
  git: gitRuns,
  // hyperfine benchmarks each argument as a shell command, and runs --prepare/--setup/--cleanup/--conclude strings.
  hyperfine: (list, k) =>
    list.slice(k).flatMap((word) => {
      const glued = /^--(prepare|setup|cleanup|conclude)=(.*)$/s.exec(word.value);
      if (glued) return commandString([{ value: glued[2] }]);
      return word.value.startsWith("-") ? [] : commandString([word]);
    }),
  // tfenv/tofuenv `exec` runs the managed terraform/tofu with the rest as its arguments.
  tfenv: (list, k, xargs) => (list[k]?.value === "exec" ? [{ argv: [{ value: "terraform", dynamic: false }, ...list.slice(k + 1)], xargs }] : []),
  tofuenv: (list, k, xargs) => (list[k]?.value === "exec" ? [{ argv: [{ value: "tofu", dynamic: false }, ...list.slice(k + 1)], xargs }] : []),
  ssh: (list, k) => {
    const rest = list.slice(pastOptions(list, k, { short: "bcDEeFIiJLlmOopQRSWwBP" }) + 1);
    return rest.length === 0 ? [{ stdin: true }] : commandString(rest);
  },
  docker: orOwnRun(containerRuns(false)),
  podman: orOwnRun(containerRuns(false)),
  "docker-compose": orOwnRun(containerRuns(true)),
  "podman-compose": orOwnRun(containerRuns(true)),
  // `kubectl exec pod -- X` runs X in the pod (with no `--`, from each IaC or cloud CLI word);
  // nothing else kubectl does runs a local program.
  kubectl: orOwnRun((list, k, xargs, hops) => {
    if (!list.some((word, j) => j >= k && word.value === "exec")) return [];
    const dashes = list.findIndex((word, j) => j >= k && word.value === "--");
    if (dashes !== -1) return runs(list.slice(dashes + 1), xargs, hops);
    return list.flatMap((word, j) => (j >= k && isInfraCli(word.value) ? runs(list.slice(j, j + PRINTED_WINDOW), xargs, hops) : []));
  }),
  // envchain's first operand is the namespace list; the program follows it.
  envchain: programAfterOperand(),
  // `sops exec-env FILE 'X'` / `exec-file FILE 'X'` run X through a shell with the secrets decrypted.
  sops: orOwnRun((list, k, xargs, hops) => {
    const at = list.findIndex((word, j) => j >= k && (word.value === "exec-env" || word.value === "exec-file"));
    if (at === -1) return list.some((word, j) => j >= k && word.value === "--") ? loaderRuns(list, k, xargs, hops) : [];
    const file = pastOptions(list, at + 1, { long: ["--user", "--filename", "--input-type", "--output-type"] });
    return commandString(list.slice(file + 1, file + 2));
  }),
  heroku: ownAndLoader,
  fly: ownAndLoader,
  flyctl: ownAndLoader,
  ...Object.fromEntries(["aws-vault", "op", "doppler", "direnv", "dotenv", "dotenvx", "mise", "asdf", "rtx", "nix", "nix-shell", "devbox", "granted", "assume", "saml2aws", "infisical", "chamber", "env-cmd", "railway", "vercel", "teller"].map((name) => [name, loaderRuns])),
};

// Each line or stdin a wrapper runs, marked with the wrapper (`via`) unless an inner one already is.
const via = (targets, name) => targets.map((target) => (target.argv === undefined && target.via === undefined ? { ...target, via: name } : target));

// What one simple command runs, past assignments, keywords, and wrappers (WRAPPERS above).
// `xargs` is false, or { placeholder } for a program xargs runs; `hops` counts wrappers, so a
// pathological stack asks instead of recursing on.
const runs = (list, xargs = false, hops = 0) => {
  if (hops > MAX_WRAPPERS) return [{ deep: true }];
  // `GIT_SSH_COMMAND='X' git fetch`: git runs X through sh when it connects, so X is a command string.
  const ssh = [];
  const withSsh = (targets) => (ssh.length === 0 ? targets : [...via(ssh, "git"), ...targets]);
  for (let i = 0; i < list.length; i += 1) {
    tick();
    const word = list[i] ?? { value: "", dynamic: false };
    const set = /^GIT_SSH_COMMAND=(.*)$/s.exec(word.value);
    if (set) ssh.push({ line: set[1] });
    // A wrapper's own `--` before the program (`envchain ns -- X`).
    if (ASSIGNMENT.test(word.value) || KEYWORDS.has(word.value) || (i === 0 && word.value === "--")) continue;
    // `function f { …; }`: the name isn't a command, the body after it is (it runs when called).
    if (word.value === "function") {
      i += 1;
      continue;
    }
    // `coproc X …` runs X; `coproc NAME { …; }` names the coprocess first.
    if (word.value === "coproc") {
      if (list[i + 2]?.value === "{") i += 1;
      continue;
    }
    if (NOT_A_COMMAND.has(word.value)) return withSsh([]);
    const name = programName(word.value);
    // A program word that expands at run time is judged as a program, never as a wrapper.
    if (!word.dynamic && SHELL.test(name)) return withSsh(via(shellRuns(list, i + 1, xargs, name), name));
    if (!word.dynamic && Object.hasOwn(WRAPPERS, name)) return withSsh(via(WRAPPERS[name](list, i + 1, xargs, hops + 1), name));
    return withSsh([{ argv: list.slice(i), xargs }]);
  }
  return withSsh([]);
};

// Terragrunt options that take the next word as their value (old `--terragrunt-*` and new names);
// only ones known to, so a boolean flag never swallows the verb after it.
const GRUNT_VALUED = /^--(terragrunt-)?(working-dir|config|tfpath|tf-path|download-dir|source|source-map|iam-role|iam-assume-role|iam-assume-role-duration|iam-assume-role-session-name|exclude-dir|include-dir|queue-exclude-dir|queue-include-dir|parallelism|log-level)$/;

// Verdict for one IaC CLI run: `name` lowercased, `rest` its argument words; `ctx` the line's lineContext().
const iacVerdict = (name, rest, xargs, ctx) => {
  if (rest.some((word) => HELP_FLAGS.has(word.value))) return null;
  const grunt = name.startsWith("terragrunt");
  // Positional words, past options; `-chdir dir` and terragrunt's valued options skip their value too.
  const args = [];
  for (let i = 0; i < rest.length; i += 1) {
    const value = rest[i]?.value ?? "";
    if (value === "" || value === "--") continue;
    if (value.startsWith("-")) {
      if (/^--?chdir$/.test(value) || (grunt && GRUNT_VALUED.test(value))) i += 1;
      continue;
    }
    args.push(rest[i]);
  }
  // terragrunt nests the verb (`run-all apply`, `run --all -- destroy`), so any position counts there.
  if (grunt && args.some((word) => ["apply", "destroy", "apply-all", "destroy-all"].includes(word?.value ?? ""))) return applyRefused(name);
  if (grunt) while (["run-all", "run", "exec"].includes(args[0]?.value ?? "")) args.shift();
  const [verbWord, subWord] = args;
  const verb = verbWord?.value ?? "";
  const sub = subWord?.value ?? "";
  if (verb === "help") return null;
  // A verb from a variable, a substitution, or a brace expansion could be apply.
  if (verbWord?.dynamic === true) return ask(`The \`${name}\` verb here comes from a variable or a substitution, so the guard can't tell an apply from a plan; the user confirms.`);
  // `xargs -I{} terraform {}`, `parallel terraform {} ::: …`: the verb is filled in from the input.
  if (xargs && verbWord !== undefined && xargs.placeholder(verb)) return ask(`xargs or parallel fills in \`${name}\`'s verb from its input, so the guard can't tell an apply from a plan; the user confirms.`);
  if (verb === "apply" || verb === "destroy") return applyRefused(name);
  // State is the record of what exists; dropping or overwriting it orphans or re-creates real resources.
  //
  // `init -migrate-state` / `-force-copy` copy state over the destination backend's, so they are
  // refused like `state push`, not asked: -force-copy answers the overwrite prompt itself, and a
  // non-interactive agent run answers it for -migrate-state, so an ask would guard nothing the
  // deny doesn't, and an overwritten remote state can't be undone from the shell.
  if ((verb === "state" && (sub === "rm" || sub === "push")) || (verb === "workspace" && sub === "delete") || (verb === "init" && rest.some((word) => /^--?(migrate-state|force-copy)(=|$)/.test(word.value)))) {
    return liftable(deny("Removing or overwriting Terraform state (state rm/push, workspace delete, init -migrate-state/-force-copy) is a human action. Hand the user the exact command."));
  }
  // `terraform test` runs apply against real providers for every run block, then destroys what it made.
  if (verb === "test") return ask(`\`${name} test\` creates real infrastructure from the test files and destroys it afterwards; the user confirms which account it runs in.`);
  if ((verb === "state" && (sub === "mv" || sub === "replace-provider")) || ["force-unlock", "import", "taint", "untaint", "refresh"].includes(verb)) {
    return ask("This rewrites shared Terraform state, which the next apply acts on; the user confirms.");
  }
  // `echo apply | xargs terraform`: the verb arrives on stdin.
  if (xargs && verb === "" && ctx.mentions()) return ask(`xargs supplies \`${name}\`'s verb from stdin, so the guard can't tell an apply from a plan; the user confirms.`);
  return null;
};

// The refusal for an apply or destroy.
const applyRefused = (name) => liftable(deny(`\`${name} apply/destroy\` changes or deletes real infrastructure; a human runs it. Run \`plan\`, put its summary and the exact command in the PR, and hand it to the user.`));

// CDK commands, so the first one decides (an option's value can't pass for the verb).
const CDK_COMMANDS = new Set(["list", "ls", "synth", "synthesize", "bootstrap", "gc", "deploy", "rollback", "import", "watch", "destroy", "diff", "metadata", "acknowledge", "ack", "notices", "init", "migrate", "context", "docs", "doc", "doctor", "refactor", "drift", "flags", "get", "output", "outputs", "provider", "providers", "debug", "completion", "login", "logout", "publish", "convert", "telemetry", "help"]);

// Verdict for one `cdk` / `cdktf` run: deploy, destroy, watch (deploys on each change), rollback,
// and gc (deletes assets) are refused; bootstrap (creates a stack) and import (rewrites one) ask.
const cdkVerdict = (name, rest) => {
  if (rest.some((word) => HELP_FLAGS.has(word.value))) return null;
  const verbWord = rest.find((word) => word.dynamic || CDK_COMMANDS.has(word.value));
  if (verbWord?.dynamic === true) return ask(`The \`${name}\` command here comes from a variable or a substitution, so the guard can't tell a deploy from a synth; the user confirms.`);
  const verb = verbWord?.value ?? "";
  if (["deploy", "destroy", "watch", "rollback", "gc"].includes(verb)) return liftable(deny(`\`${name} ${verb}\` changes or deletes real infrastructure; a human runs it. Run \`${name} diff\`, put it and the exact command in the PR, and hand it to the user.`));
  if (verb === "bootstrap" || verb === "import") return ask(`\`${name} ${verb}\` creates or rewrites real infrastructure; the user confirms which account it runs in.`);
  return null;
};

// Positional words of a cloud CLI call: options skipped, and the value of each option in `valued` with it.
const positionalsOf = (values, valued) => {
  const found = [];
  for (let i = 0; i < values.length; i += 1) {
    const value = values[i] ?? "";
    if (value === "--") continue;
    if (value.startsWith("-") && value !== "-") {
      if (!value.includes("=") && valued.has(value)) i += 1;
      continue;
    }
    found.push(value);
  }
  return found;
};

// aws global options that take a value, and `aws s3` transfer options that do (so a value isn't read as a path).
const AWS_VALUED = new Set(["--profile", "--region", "--output", "--endpoint-url", "--query", "--color", "--ca-bundle", "--cli-read-timeout", "--cli-connect-timeout", "--cli-binary-format"]);
const S3_VALUED = new Set([...AWS_VALUED, "--exclude", "--include", "--acl", "--grants", "--storage-class", "--content-type", "--cache-control", "--content-disposition", "--content-encoding", "--content-language", "--expires", "--metadata", "--metadata-directive", "--sse", "--sse-c", "--sse-c-key", "--sse-kms-key-id", "--sse-c-copy-source", "--sse-c-copy-source-key", "--website-redirect", "--source-region", "--request-payer", "--expected-size", "--copy-props", "--checksum-algorithm", "--page-size"]);

// aws: the operation is the second positional, after the service; `s3` has its own verbs.
const awsDeletes = (values) => {
  const positionals = positionalsOf(values, S3_VALUED);
  if (positionals.at(-1) === "help") return false;
  const [service = "", operation = ""] = positionals;
  if (DELETE_VERB.test(operation)) return true;
  if (service === "kms" && (operation === "schedule-key-deletion" || operation === "disable-key")) return true;
  if (service !== "s3") return false;
  // `s3 mv` from a bucket deletes the source; the destination is always the last path.
  return operation === "rm" || operation === "rb" || (operation === "sync" && values.includes("--delete")) || (operation === "mv" && positionals.slice(2, -1).some((path) => /^s3:\/\//i.test(path)));
};

// gcloud global options that take a value.
const GCLOUD_VALUED = new Set(["--project", "--account", "--configuration", "--format", "--verbosity", "--impersonate-service-account", "--billing-project", "--flags-file", "--flatten", "--trace-token", "--access-token-file"]);

// gcloud verbs that end a command path without deleting: the verb is the first word after the
// group that is one of these or a delete, so a resource named `delete-me` after `describe` is a
// name, not a verb. The group itself is never a verb: `gcloud deploy …` is the Cloud Deploy group.
const GCLOUD_LEAF = /^(describe|list|call|create|update|ssh|scp|deploy|read|tail|ls|cp|cat|access|connect|login|activate|get|set|unset|add|remove|show|print|submit|execute|start|stop|restart|resize|reset|patch|enable|disable|wait|browse|tag|sign|verify|encrypt|decrypt|import|export|copy|clone|promote|(describe|list|get|set|add|remove|update|create|print)-[a-z-]+)$/;

// gcloud: the first verb in the command path; `kms … disable` too, since a disabled key version is
// crypto-shredding; `storage mv` from a bucket and `storage rsync --delete-unmatched-destination-objects` delete too.
const gcloudDeletes = (values) => {
  const positionals = positionalsOf(values, GCLOUD_VALUED);
  if (positionals[0] === "help") return false;
  // Release tracks come before the group.
  let group = 0;
  while (["alpha", "beta", "preview"].includes(positionals[group] ?? "")) group += 1;
  if (positionals[group] === "storage") {
    const verb = positionals[group + 1];
    if (verb === "mv") return positionals.slice(group + 2, -1).some((path) => /^gs:\/\//i.test(path));
    if (verb === "rsync") return values.some((value) => /^--delete-unmatched-destination-objects(=|$)/.test(value));
  }
  for (let index = group; index < positionals.length; index += 1) {
    const word = positionals[index] ?? "";
    if (DELETE_VERB.test(word) || word === "rm") return true;
    if (word === "disable" && positionals.slice(group, index).includes("kms")) return true;
    if (index > group && GCLOUD_LEAF.test(word)) return false;
  }
  return false;
};

// az: the last command word before the first option (`az keyvault key purge --name …`); `storage
// remove` deletes files. Returns true, false, or "ask" for a storage sync that may delete.
const azDeletes = (values) => {
  let i = 0;
  while (i < values.length && (values[i] ?? "").startsWith("-")) i += 1;
  const path = [];
  for (; i < values.length && !(values[i] ?? "").startsWith("-"); i += 1) path.push(values[i] ?? "");
  const last = path.at(-1) ?? "";
  if (DELETE_VERB.test(last)) return true;
  // `az rest --method delete` sends a raw DELETE to the Azure API.
  if (path[0] === "rest") return /^delete$/i.test(optionValue(values, ["--method", "-m"]) ?? "");
  if (!path.includes("storage")) return false;
  if (last === "remove") return true;
  if (last !== "sync") return false;
  // `storage … sync --delete-destination true|prompt` deletes what the source lacks; with no flag,
  // the guard can't vouch for the CLI version's default, so the user confirms.
  const at = values.findIndex((value) => value === "--delete-destination" || value.startsWith("--delete-destination="));
  if (at === -1) return "ask";
  const setting = (values[at] ?? "").includes("=") ? (values[at] ?? "").split("=")[1] : values[at + 1];
  return (setting ?? "").toLowerCase() !== "false";
};

// gsutil: the command is the first positional, after top-level options (-h, -o, -u, -i take a value).
const gsutilDeletes = (values) => {
  let i = 0;
  while (i < values.length && (values[i] ?? "").startsWith("-")) i += /^-[houi]$/.test(values[i] ?? "") ? 2 : 1;
  const [command = "", ...rest] = values.slice(i);
  if (command === "rm" || command === "rb") return true;
  // `mv` from a bucket deletes the source; `rsync -d` deletes what the source lacks.
  if (command === "mv") return positionalsOf(rest, new Set()).slice(0, -1).some((path) => /^gs:\/\//i.test(path));
  if (command === "rsync") return rest.some((word) => /^-[A-Za-z]*d[A-Za-z]*$/.test(word));
  return false;
};

// bq commands: the first positional that is one decides, so a global flag's value (`--service_account x@y`) can't shift it.
const BQ_COMMANDS = new Set(["add-iam-policy-binding", "cancel", "cp", "extract", "get-iam-policy", "head", "help", "init", "insert", "load", "ls", "mk", "mkdef", "partition", "query", "remove-iam-policy-binding", "rm", "set-iam-policy", "shell", "show", "undelete", "update", "version", "wait"]);
const bqCommand = (values) => positionalsOf(values, new Set(["--project_id", "--dataset_id", "--location", "--format", "--api", "--apilog", "--job_id"])).find((word) => BQ_COMMANDS.has(word)) ?? "";

// bq: `bq rm` deletes a dataset, table, or model.
const bqDeletes = (values) => bqCommand(values) === "rm";

// The value of the first option in `names`, given as `--name value` or `--name=value`; undefined when absent.
const optionValue = (values, names) => {
  const at = values.findIndex((value) => names.includes(value) || names.some((name) => value.startsWith(`${name}=`)));
  if (at === -1) return undefined;
  const value = values[at] ?? "";
  return value.includes("=") ? value.slice(value.indexOf("=") + 1) : values[at + 1];
};

// True when a path names a remote (`r:bucket`, `s3://b`), not a local file (`./x`, a Windows `C:\x`).
const isRemote = (path) => /^[\w.-]+:/.test(path) && !/^[A-Za-z]:[\\/]/.test(path);

// azcopy: `rm`/`remove` delete; `sync --delete-destination true|prompt` deletes what the source lacks (the default is false).
const azcopyDeletes = (values) => {
  const [command = ""] = positionalsOf(values, new Set(["--delete-destination", "--include-pattern", "--exclude-pattern", "--log-level", "--include-path", "--exclude-path"]));
  if (command === "rm" || command === "remove") return true;
  return command === "sync" && ["true", "prompt"].includes((optionValue(values, ["--delete-destination"]) ?? "false").toLowerCase());
};

// rclone: purge, delete, deletefile, and cleanup (empties the trash) delete; sync deletes what the
// source lacks by design; move/moveto delete a remote source.
const RCLONE_VALUED = new Set(["--config", "--log-file", "--log-level", "--transfers", "--checkers", "--bwlimit", "--include", "--exclude", "--filter", "--include-from", "--exclude-from", "--filter-from", "--backup-dir", "--suffix", "--max-age", "--min-age", "--max-size", "--min-size"]);
const rcloneDeletes = (values) => {
  const [command = "", source = ""] = positionalsOf(values, RCLONE_VALUED);
  if (["purge", "delete", "deletefile", "cleanup", "sync"].includes(command)) return true;
  return (command === "move" || command === "moveto") && isRemote(source);
};

// s5cmd and s3cmd: rm/rb (s3cmd del too); sync with --delete (s3cmd --delete-removed); mv from a bucket.
const s5cmdDeletes = (values) => {
  const positionals = positionalsOf(values, new Set(["--endpoint-url", "--profile", "--credentials-file", "--numworkers", "--retry-count", "--log", "--request-payer"]));
  const [command = "", ...paths] = positionals;
  if (command === "rm" || command === "rb") return true;
  if (command === "sync") return values.includes("--delete");
  return command === "mv" && paths.slice(0, -1).some((path) => /^s3:\/\//i.test(path));
};
const s3cmdDeletes = (values) => {
  const [command = "", ...paths] = positionalsOf(values, new Set(["-c", "--config", "--access_key", "--secret_key", "--region", "--host", "--host-bucket", "--exclude", "--include"]));
  if (["del", "rm", "rb", "deleteall"].includes(command)) return true;
  if (command === "sync") return values.includes("--delete-removed") || values.includes("--delete-after");
  return command === "mv" && paths.slice(0, -1).some((path) => /^s3:\/\//i.test(path));
};

// mc (MinIO client): rb and rm delete; mirror --remove deletes what the source lacks.
const mcDeletes = (values) => {
  const [command = ""] = positionalsOf(values, new Set(["--config-dir", "-C"]));
  if (command === "rb" || command === "rm") return true;
  return command === "mirror" && values.some((value) => value === "--remove" || value === "--overwrite-remove");
};

// doctl and fly: a delete or destroy verb anywhere in the command path (`doctl databases delete`,
// `fly apps destroy`); heroku: a topic command ending in destroy/delete/reset (`apps:destroy`, `pg:reset`).
const PAAS_VALUED = new Set(["--context", "-t", "--access-token", "-o", "--output", "--config", "-c", "-u", "--api-url", "-a", "--app"]);
const paasDeletes = (values) => {
  const positionals = positionalsOf(values, PAAS_VALUED);
  return !positionals.includes("help") && positionals.some((word) => ["delete", "destroy", "rm", "remove"].includes(word));
};
const herokuDeletes = (values) => /(^|:)(destroy|delete|reset)$/.test(positionalsOf(values, PAAS_VALUED)[0] ?? "");

// Cloud CLI calls that run SQL against a real database: `bq query`, Spanner's execute-sql, the
// RDS and Redshift Data APIs, and Athena. Destructive SQL in their arguments is refused like psql's.
const SQL_RUNNERS = {
  aws: (values) => {
    const [service = "", operation = ""] = positionalsOf(values, S3_VALUED);
    return (/^(rds|redshift)-data$/.test(service) && operation.endsWith("execute-statement")) || (service === "athena" && operation === "start-query-execution");
  },
  gcloud: (values) => positionalsOf(values, GCLOUD_VALUED).includes("execute-sql"),
  bq: (values) => bqCommand(values) === "query",
};

// Verdict for one cloud CLI run: `name` lowercased without .exe, `list` its argument words.
const cloudVerdict = (name, list) => {
  const values = list.map((word) => word.value);
  if (values.some((value) => value === "-help" || value === "--help" || (value === "-h" && name !== "gsutil"))) return null;
  if (name === "gsutil" && values.find((value) => !value.startsWith("-")) === "help") return null;
  // `aws s3 r{m,b} …`: one word becomes several at run time, so the verb can't be read.
  if (list.some((word) => word.brace === true)) return ask(`A brace expansion in this \`${name}\` call makes its words at run time, so the guard can't read the verb; the user confirms.`);
  if ((SQL_RUNNERS[name]?.(values) ?? false) && values.some((value) => destroysSql(value))) {
    return deny(`Destructive SQL through \`${name}\` runs against a real database: a human action. Write it, test it on localhost, and hand the user the command.`);
  }
  const readers = { aws: awsDeletes, gcloud: gcloudDeletes, az: azDeletes, gsutil: gsutilDeletes, bq: bqDeletes, azcopy: azcopyDeletes, rclone: rcloneDeletes, s5cmd: s5cmdDeletes, s3cmd: s3cmdDeletes, mc: mcDeletes, doctl: paasDeletes, fly: paasDeletes, flyctl: paasDeletes, heroku: herokuDeletes };
  const deletes = readers[name]?.(values) ?? false;
  if (deletes === "ask") return ask(`\`${name} storage … sync\` deletes what the source lacks unless \`--delete-destination false\`; the user confirms.`);
  return deletes ? liftable(deny(`Deleting cloud resources or their data with \`${name}\` is a human action. Hand the user the exact command and what it destroys.`)) : null;
};

// What the IaC checks need from the top-level line, each read once however many commands ask
// (a per-command regex over the whole line is quadratic on a line of 50k `$x;`).
const lineContext = (line) => {
  let mentions;
  let names;
  return { mentions: () => (mentions ??= MENTIONS_IAC.test(line)), names: () => (names ??= NAMES_IAC.test(line)) };
};

// Verdict for one program run (argv[0] the program); `ctx` is the line's lineContext().
const judge = ({ argv, xargs }, ctx) => {
  const [program, ...rest] = argv;
  const name = programName(program?.value ?? "");
  // A file system that folds Unicode case runs `pſql` as psql; the rules read ASCII names only.
  if (/[^ -~]/.test(name)) return ask(`The program \`${program?.value ?? ""}\` has a non-ASCII character, which the guard can't match to a program by name (a case-folding file system may run it as another); the user confirms.`);
  if (IAC_CLI.test(name)) return iacVerdict(name.toLowerCase(), rest, xargs, ctx);
  if (CDK_CLI.test(name)) return cdkVerdict(name.toLowerCase(), rest);
  if (CLOUD_CLI.test(name)) return cloudVerdict(name.toLowerCase().replace(/\.exe$/, ""), rest);
  // `"$TF" apply`, `$(which terraform) apply`, `{terraform,apply}`: the program can't be read, and
  // its own words point at IaC, or the line names an IaC CLI an earlier command could have stored.
  if (program?.dynamic === true && (argv.some((word) => MENTIONS_IAC.test(word.value)) || ctx.names())) {
    return ask("The program here comes from a variable, a substitution, or a brace expansion, on a line about terraform or an apply/destroy; the guard can't read which program runs, so the user confirms.");
  }
  return NON_RUNNERS.has(name) ? null : unknownRunner(name, argv, ctx);
};

// Programs that print, search, or store their arguments instead of running them, so the fallback
// below leaves `grep -rn terraform apply.log`-style words alone. git runs commands only where its
// wrapper reads them (WRAPPERS.git).
const NON_RUNNERS = new Set(["echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "ack", "git", "gh", "cat", "less", "more", "head", "tail", "man", "info", "tldr", "which", "whereis", "type", "whatis", "apropos", "wc", "sort", "uniq", "tee", "diff", "sed", "awk", "jq", "yq", "ls", "cd", "pushd", "touch", "mkdir", "rm", "cp", "mv", "ln", "stat", "file", "basename", "dirname", "realpath", "readlink", "export", "declare", "local", "readonly", "test", "[", "true", "false", ":", "read", "printenv"]);

// Fallback for a program the guard doesn't know (`strace terraform apply`, `docker run
// hashicorp/terraform destroy`, `firejail aws s3 rb s3://b`): an IaC or cloud CLI as its own
// word, followed by what iacVerdict(), cdkVerdict(), or cloudVerdict() would refuse or ask about, asks, since the
// guard can't tell whether the program runs its arguments. A word with blanks in it is read as the
// command line it may be (`su -c 'terraform destroy'`), unless a program from NON_RUNNERS comes
// before it (`find -exec grep 'terraform destroy'`). Each CLI word reads at most PRINTED_WINDOW
// words after it, so a long line stays linear.
const unknownRunner = (name, argv, ctx) => {
  let printer = false;
  for (let i = 1; i < argv.length; i += 1) {
    tick();
    const word = argv[i];
    if (word?.dynamic === true) continue;
    printer ||= NON_RUNNERS.has(programName(word?.value ?? ""));
    if (/\s/.test(word?.value ?? "")) {
      if (printer) continue;
      const verdict = unknownRunner(name, [argv[0], ...printedWords({ words: [word], heredocs: [], herestrings: [] })], ctx);
      if (verdict !== null) return verdict;
      continue;
    }
    // An image reference names the CLI too: `hashicorp/terraform:1.9`, `…@sha256:…`, `opentofu/opentofu`.
    const image = programName(word?.value ?? "").replace(/[:@].*$/, "");
    const cli = /^opentofu$/i.test(image) ? "tofu" : image;
    const after = argv.slice(i + 1, i + 1 + PRINTED_WINDOW);
    // A `{}` or `:::` where the verb goes is filled in at run time (`parallel terraform ::: apply`, `fd -X terraform {}`).
    const verb = after.find((each) => !each.value.startsWith("-"))?.value ?? "";
    if (IAC_CLI.test(cli) && (verb === ":::" || verb.includes("{}") || iacVerdict(cli.toLowerCase(), after, false, ctx))) {
      return ask(`\`${name}\` is given \`${cli}\` with an apply, destroy, state change, or placeholder verb after it, and the guard doesn't know whether \`${name}\` runs its arguments; the user confirms.`);
    }
    if (CDK_CLI.test(cli) && cdkVerdict(cli.toLowerCase(), after)) {
      return ask(`\`${name}\` is given \`${cli}\` with a deploy, destroy, or import after it, and the guard doesn't know whether \`${name}\` runs its arguments; the user confirms.`);
    }
    if (CLOUD_CLI.test(cli) && cloudVerdict(cli.toLowerCase().replace(/\.exe$/, ""), after)) {
      return ask(`\`${name}\` is given \`${cli}\` with a delete after it, and the guard doesn't know whether \`${name}\` runs its arguments; the user confirms.`);
    }
  }
  return null;
};

// The words a command prints into a shell, as a shell would read them: every word it holds,
// heredoc and here-string text too, split on blanks and `| ; &`.
const printedWords = (command) =>
  [...command.words.map((word) => word.value), ...command.heredocs.map((doc) => doc.body), ...command.herestrings.map((word) => word.value)]
    .join("\n")
    .split(/[\s|;&]+/)
    .filter(Boolean)
    .map((value) => ({ value, dynamic: false }));

// Judges printed words at `starts` (indexes of IaC or cloud CLI words), each with the words after it, up to PRINTED_WINDOW.
const judgePrinted = (printed, starts, ctx) => strongest(starts.map((i) => judge({ argv: printed.slice(i, i + PRINTED_WINDOW), xargs: false }, ctx)));

// Indexes of the IaC or cloud CLI words in some printed words.
const infraStarts = (printed) => printed.flatMap((word, i) => (isInfraCli(word.value) ? [i] : []));

// Verdict for what some commands print into a shell (`bash <(echo …)`, `bash < <(echo …)`).
const printedVerdict = (commands, ctx) => {
  const printed = commands.flatMap(printedWords);
  return judgePrinted(printed, infraStarts(printed), ctx);
};

// Verdict for a command line: every simple command, what each wrapper runs, every substitution,
// and every shell fed on stdin. `allow` holds exemption keys; one lifts only a data-delete deny of
// exactly a command typed at the top level, before any `cd`. `ctx` is the top-level line's
// lineContext(); `feed` gives the verdicts for what the line itself is fed on stdin (a command
// string a wrapper runs: `ssh host bash <<<'…'`), and `xargs` marks a command string xargs or parallel fills in.
const evaluateInfra = (line, { allow = new Set(), depth = 0, ctx = lineContext(line), feed = null, xargs = false, parsed = /** @type {ReturnType<typeof parseLine> | null} */ (null) } = {}) => {
  if (depth > MAX_DEPTH) return ask("This line nests substitutions, wrappers, or shells deeper than the guard reads; the user confirms it changes no infrastructure.");
  const { commands, nested } = parsed ?? parseLine(line);
  const inner = (text, options = {}) => evaluateInfra(text, { depth: depth + 1, ctx, ...options });
  const verdicts = nested.map((text) => inner(text));

  // What the current pipeline prints, built once, so a pipeline of 20k shells (`echo hi|sh|sh|…`)
  // stays linear: `printed` holds the words of its commands before `built`, `starts` the indexes
  // of its IaC or cloud CLI words, and those before `judged` already had their full window read.
  let printed = [];
  let starts = [];
  let built = 0;
  let judged = 0;
  let printedSoFar = null;
  // Verdict for what the pipeline's commands before `end` print (into a shell at `end`, or a `>(…)` of command end - 1).
  const printedThrough = (end) => {
    for (; built < end; built += 1) {
      for (const word of printedWords(commands[built] ?? newCommand(false))) {
        tick();
        if (isInfraCli(word.value)) starts.push(printed.length);
        printed.push(word);
      }
    }
    // Only the CLI words whose window wasn't complete last time; drop the rest from the front.
    let first = 0;
    while (first < starts.length && (starts[first] ?? 0) < judged) first += 1;
    starts = starts.slice(first);
    printedSoFar = strongest([printedSoFar, judgePrinted(printed, starts, ctx)]);
    // A word whose window ran past the end is read again when more words arrive.
    judged = Math.max(judged, printed.length - PRINTED_WINDOW);
    return printedSoFar;
  };

  // Names `alias x=…` defined on this line, so a later `x apply` reads as what it expands to.
  const aliases = new Map();
  // True once a `cd`, `pushd`, or `popd` has run: an exemption names a command in the hook's cwd.
  let moved = false;
  commands.forEach((command, index) => {
    tick();
    if (!command.piped) {
      printed = [];
      starts = [];
      built = index;
      judged = 0;
      printedSoFar = null;
    }
    const found = [];
    // What this command is fed on stdin, read once and only if a shell runs it: its heredocs and
    // here-strings (run as commands whatever the quoting), a `< <(…)`'s output, the pipe before
    // it; with none of its own, whatever the line it came in was fed.
    const own = command.heredocs.length + command.herestrings.length + command.stdinProcs.length > 0 || command.piped;
    let fed = null;
    const feedOf = own
      ? () =>
          (fed ??= [
            ...command.heredocs.map((doc) => inner(doc.body)),
            ...command.herestrings.map((word) => inner(word.value)),
            ...command.stdinProcs.map((text) => printedVerdict(parseLine(text).commands, ctx)),
            ...(command.piped ? [printedThrough(index)] : []),
          ])
      : feed;
    const first = command.words.find((word) => !ASSIGNMENT.test(word.value));
    // `alias x='…'`: the value is a command line wherever x is used; a later `x …` on this line expands it.
    if (first?.value === "alias") {
      for (const word of command.words.slice(command.words.indexOf(first) + 1)) {
        const defined = /^([^=\s]+)=(.*)$/s.exec(word.value);
        if (!defined) continue;
        aliases.set(defined[1], defined[2]);
        found.push(inner(defined[2]));
      }
    } else if (first !== undefined && !first.dynamic && aliases.has(first.value)) {
      const rest = command.words.slice(command.words.indexOf(first) + 1).map((word) => word.value);
      found.push(inner([aliases.get(first.value), ...rest].join(" "), { feed: feedOf }));
    }
    for (const target of runs(command.words, xargs)) {
      if (target.argv) found.push(judge(target, ctx));
      else if (target.line !== undefined) found.push(inner(target.line, { feed: feedOf, xargs: target.xargs ?? false }));
      else if (target.deep) found.push(ask("This command stacks more wrappers than the guard reads; the user confirms it changes no infrastructure."));
      else if (target.ask !== undefined) found.push(ask(target.ask));
      else if (target.printed !== undefined) found.push(printedVerdict(parseLine(target.printed).commands, ctx));
      else if (target.stdin && feedOf !== null) found.push(...feedOf());
    }
    // `>(X)` runs X on what this command writes: what the pipeline prints through this command.
    for (const text of command.outProcs) found.push(inner(text, { feed: () => [printedThrough(index + 1)] }));
    const exempt = depth === 0 && !moved && allow.size > 0 && command.start !== -1 && allow.has(JSON.stringify(command.tokens));
    verdicts.push(...found.filter((verdict) => !(exempt && verdict?.liftable === true)));
    if (/^(cd|pushd|popd)$/.test(first?.value ?? "")) moved = true;
  });
  return strongest(verdicts);
};

// Verdict constructors, so every rule reads as one line.
const deny = (reason) => ({ decision: "deny", reason });
const ask = (reason) => ({ decision: "ask", reason });
// Marks a data-delete deny that a project exemption may lift; every other verdict stands.
const liftable = (verdict) => ({ ...verdict, liftable: true });
// A rule-set row's verdict (`statusContexts`, `repoVariables`), as its `verdict` field says.
const rowVerdict = (row) => (row.verdict === "deny" ? deny(row.reason) : ask(row.reason));

// No project or pack rules: what an absent file means, and the default for evaluate(). With no
// `branches` or `sets`, evaluate() takes both from the rule sets (defaultSets()).
const NO_RULES = { deny: [], ask: [], allow: new Set(), error: "" };

// Verdicts from project and pack rules for one command. `match` reads the program text (prefixes
// removed, as the built-in rules do); `unless` reads the whole command, so it can see `VAR=value`.
const ruleVerdicts = (rules, text, typed) => {
  const fires = (rule) => rule.match.test(text) && !(rule.unless?.test(typed) ?? false);
  return [...rules.deny.filter(fires).map((rule) => ruleVerdict(deny, rule)), ...rules.ask.filter(fires).map((rule) => ruleVerdict(ask, rule))];
};

// A rule's verdict names its file. A pack's deny is data-delete class, so an exemption may lift it;
// the project's own deny, a rule set's, and every ask stand.
const ruleVerdict = (make, rule) => {
  const verdict = make(`${rule.reason} (${rule.file})`);
  return make === deny && !rule.project && !rule.set ? liftable(verdict) : verdict;
};

// Why every command is refused when a rule file, pack, or set doesn't load, naming it. `off` is the
// off switch's name (the first of `offEnv`), so the message names one that works for this caller.
const loadError = (file, error, off = DEFAULT_OFF_ENV[0]) => `${file} didn't load (${error instanceof Error ? error.message : String(error)}), so every shell command is refused. Stop and tell the user: they fix the file or set ${off}=off. Don't edit guard rules to get a command through.`;

// The `files` option checked against DEFAULT_FILES: each key known, each value a relative path or
// null. Throws naming the key, so a misspelt one refuses every command instead of dropping a file.
const filesOf = (files) => {
  if (!isRecord(files)) throw new Error("the files option must be an object");
  onlyKeys(files, Object.keys(DEFAULT_FILES), "the files option");
  const paths = { ...DEFAULT_FILES };
  for (const [key, value] of Object.entries(files)) {
    if (value !== null) relativePath(value, `files.${key}`);
    paths[key] = value;
  }
  return paths;
};

// A path inside the project, written relative to its root: no `..`, no absolute path, no shell syntax.
const relativePath = (value, at) => {
  const path = nonEmpty(value, at);
  if (isAbsolute(path) || path.split(/[\\/]/).includes("..") || /[*?[\]{}$`~\n]/.test(path)) throw new Error(`${at} must be a path inside the project, relative to its root`);
  return path;
};

// The config file's knobs, checked (CONFIG_KEYS); its deny, ask, and allow are read later by
// parseRules(), once the sets are loaded. Throws naming the bad field.
const parseConfig = (text) => {
  const data = JSON.parse(text);
  if (!isRecord(data)) throw new Error("the top level must be an object");
  onlyKeys(data, CONFIG_KEYS, "the top level");
  const twice = duplicateKey(text);
  if (twice !== null) throw new Error(`"${twice}" appears twice in one object`);
  const sets = listOf(data, "sets").map((name, index) => {
    if (typeof name !== "string" || !BUNDLED_SETS.includes(name)) throw new Error(`sets[${index}] is not a bundled rule set (${BUNDLED_SETS.join(", ")})`);
    return name;
  });
  return {
    data,
    sets: data["sets"] === undefined ? null : sets,
    ruleDir: data["ruleDir"] === undefined ? null : relativePath(data["ruleDir"], "ruleDir"),
    protectedBranches: data["protectedBranches"] === undefined ? null : branchNames(data["protectedBranches"], "protectedBranches"),
    askOnPush: data["askOnPush"] === undefined ? null : branchList(data["askOnPush"], "askOnPush"),
    askTags: data["askTags"] === undefined ? null : askTagsOf(data["askTags"]),
  };
};

// The ask gate's settings (askTags): `tags` (the reasons a question may reach the user), and
// optional `refusal` (the text an untagged question gets), `tools` (the tool names it judges; all
// when absent), `log` (a JSONL file each question is recorded in; `~/` is the home folder).
export const askTagsOf = (value) => {
  if (!isRecord(value)) throw new Error('"askTags" must be an object');
  onlyKeys(value, ["tags", "refusal", "tools", "log"], "askTags");
  const tags = value["tags"];
  if (!Array.isArray(tags) || tags.length === 0 || !tags.every((tag) => typeof tag === "string" && /^[\w-]+$/.test(tag))) throw new Error('"askTags.tags" must be a non-empty array of tags (letters, digits, - and _)');
  const tools = value["tools"] === undefined ? null : typeof value["tools"] === "string" ? [value["tools"]] : value["tools"];
  if (tools !== null && (!Array.isArray(tools) || tools.length === 0 || !tools.every((tool) => typeof tool === "string" && tool !== ""))) throw new Error('"askTags.tools" must be a tool name or a non-empty array of them');
  return { tags, refusal: optional(value, "refusal", "askTags"), tools, log: optional(value, "log", "askTags") };
};

// Loads, from the project root: the config (`files.config`, reins.json), the rule sets it or the
// caller names (`sets`; the caller's list wins; none by default), the protected branches, then the
// pack files (`ruleDir`, name order). Never throws: an absent config or pack file adds nothing, and
// a file that is present but broken, a set that doesn't load, or an unknown `files` key comes back
// as `error`. `loaded` names the sets read; `sets` is them, compiled (loadSets()); `guard` is the
// guard's own files (compileGuard()); `askTags` the config's ask-gate settings, or null.
export const loadRules = (root, { files = {}, sets: names, offEnv = DEFAULT_OFF_ENV } = {}) => {
  const off = offEnv[0] ?? DEFAULT_OFF_ENV[0];
  // Which file is being read, so the error names it.
  let file = "the files option";
  try {
    const paths = filesOf(files);
    file = paths.config ?? "the config";
    const configText = paths.config === null ? null : readRuleFile(join(root, paths.config));
    const config = configText === null ? null : parseConfig(configText);
    const setNames = names ?? config?.sets ?? [];
    if (!Array.isArray(setNames)) throw new Error("the sets option must be an array");
    const sets = loadSets(setNames, off);
    if (sets.error !== "") return { ...NO_RULES, sets, loaded: [], askTags: null, error: sets.error };
    const ruleDir = config?.ruleDir ?? paths.ruleDir;
    const guard = compileGuard([...[paths.config, paths.branches].filter((path) => path !== null), ...(ruleDir === null ? [] : [`${ruleDir}/`]), ...HOOK_FILES, ...sets.guardFiles]);
    let branches = sets.branches;
    if (config?.protectedBranches) branches = { ...branches, protected: new Set(config.protectedBranches) };
    if (config?.askOnPush) branches = { ...branches, askOnPush: new Set(config.askOnPush) };
    if (paths.branches !== null) {
      file = paths.branches;
      const named = protectedBranches(readRuleFile(join(root, paths.branches)));
      if (named !== null && config?.protectedBranches) throw new Error(`"protectedBranches" is also set in ${paths.config}; name it in one file`);
      if (named !== null) branches = { ...branches, protected: new Set(named) };
    }
    const rules = { deny: [], ask: [], allow: new Set(), branches, sets, guard, loaded: sets.loaded, askTags: config?.askTags ?? null, error: "" };
    // The pack files, then the config's own rules (the project's: it alone may hold `allow`).
    const read = [...(ruleDir === null ? [] : packFiles(root, ruleDir).map((name) => ({ name, text: null }))), ...(configText === null ? [] : [{ name: paths.config, text: configText }])];
    for (const each of read) {
      file = each.name;
      const project = each.text !== null;
      const text = each.text ?? readRuleFile(join(root, each.name));
      // Absent: nothing to add.
      if (text === null) continue;
      const parsed = parseRules(text, { project, branches, sets, guard, extraKeys: project ? CONFIG_KEYS : [] });
      // Each rule keeps its file (named in its reason) and whether an exemption may lift it.
      rules.deny.push(...parsed.deny.map((rule) => ({ ...rule, file, project })));
      rules.ask.push(...parsed.ask.map((rule) => ({ ...rule, file, project })));
      for (const command of parsed.allow) rules.allow.add(command);
    }
    return rules;
  } catch (error) {
    return { ...NO_RULES, askTags: null, error: loadError(file, error, off) };
  }
};

// A list of branch names, or a throw naming `key`, so a typo can't switch protection off.
const branchNames = (list, key) => {
  if (!Array.isArray(list) || list.length === 0 || !list.every((name) => typeof name === "string" && /^[\w.][\w./-]*$/.test(name))) {
    throw new Error(`"${key}" must be a non-empty array of branch names`);
  }
  return list;
};

// The same, where an empty list is a choice (`askOnPush: []` asks on no push).
const branchList = (list, key) => (Array.isArray(list) && list.length === 0 ? list : branchNames(list, key));

// The branches the `branches` file protects (`"protectedBranches": ["main", "dev"]`), or null when it
// is absent or names none. Only that key is the guard's: the file's other keys are its own
// tooling's. A list that isn't one of branch names throws.
const protectedBranches = (text) => {
  if (text === null) return null;
  const data = JSON.parse(text);
  if (!isRecord(data) || data["protectedBranches"] === undefined) return null;
  return branchNames(data["protectedBranches"], "protectedBranches");
};

// ── Rule sets: a team's own rules as data (sets/*.json) ──
//
// A set file is a project rule file's shape, plus knobs the evaluators read. Unknown keys, a
// missing reason, or a pattern that doesn't compile break the set, and a set that doesn't load
// refuses every command. No `allow`: a set never exempts, and no exemption lifts a set's row or a
// knob's verdict (exemption() runs the sets too, so an `allow` that meets one is a broken file).
// - `deny`, `ask`: rows. With no `on`, a row reads as a pack's does (ruleVerdicts(); its reason names
//   the set file). `on: "program"` reads each program the command runs, past its wrappers and with
//   the line's variables filled in, as POLICY does; `on: "segment"` reads the command as typed and
//   as the shell decodes it (case folded). For both, `unless` reads the same text, unanchored, and
//   the reason is shown as written.
// - `protectedBranches` (one set at most; replaces CORE_PROTECTED), `workflowOnlyBranches`.
// - `statusContexts`: [{ match, flags, verdict, reason, unreadable }], a commit status posted
//   through `gh api` whose context matches. A context the guard can't read asks, built in;
//   `unreadable` replaces that ask's reason.
// - `repoVariables`: [{ name, free, verdict, reason, unreadableBody, unreadableName }], a GitHub
//   Actions variable set or deleted (`gh variable`, `gh api`), unless set to a `free` value. A value
//   the guard can't read (an env file, `--input`, `@file`) or a name the shell fills in asks, built
//   in; the `unreadable*` texts replace those asks' reasons.
// A set with no rows or knobs (`{}`) doesn't load.
// - `markerFiles`: [{ name, reason }], a file only the user writes: a write to a pattern that could
//   name it asks (markerWrites()); a row refuses the plain name.
// - `freezeMarkers`: [{ file, branch, reason }], a marker in the clone's git dir that freezes a
//   branch: a push to it is refused while the marker is there (`{pr}` in the reason is its text).
// - `skipCi`: { match, flags, allowOn, reason, unreadable }, a commit whose message matches is
//   refused off `allowOn` (`{branch}` in the reason names it), asked about when the branch can't be read.
// - `pushEnvDeny`: [name], a variable that skips the pre-push checks, refused on a push.
// - `gitConfigAsk`: [{ key, reason }], a git setting that asks when set (on a command or in config).
// - `guardFiles`: [path], more of the guard's own files, relative to the project root (a folder ends
//   in `/`): a shell write to one asks, as a write to the config does.
const SET_KEYS = ["$comment", "deny", "ask", "protectedBranches", "workflowOnlyBranches", "statusContexts", "repoVariables", "markerFiles", "freezeMarkers", "skipCi", "pushEnvDeny", "gitConfigAsk", "guardFiles"];

// Every set merged, in order, with nothing in it: what loadSets() fills, and what a failed load holds.
const noSets = () => ({ error: "", loaded: [], program: [], segment: [], deny: [], ask: [], protectedBranches: /** @type {string[] | null} */ (null), workflowOnly: [], statusContexts: [], repoVariables: [], markerFiles: [], freezeMarkers: [], skipCi: [], pushEnvDeny: [], gitConfigAsk: [], guardFiles: [], branches: { protected: new Set(CORE_PROTECTED), workflowOnly: new Set(), askOnPush: CORE_ASK_ON_PUSH_SET } });

// Where a set is: a bare name is the package's sets/`<name>.json`, never the hook's cwd; a path
// ending in .json is that file (a test's copy). `label` names it in a reason or an error.
const setFile = (name) => {
  if (typeof name === "string" && /^[a-z0-9][a-z0-9-]*$/.test(name)) {
    if (!BUNDLED_SETS.includes(name)) throw new Error(`"${name}" is not a bundled rule set (${BUNDLED_SETS.join(", ")})`);
    return { path: fileURLToPath(new URL(`../sets/${name}.json`, import.meta.url)), label: `${SET_DIR}/${name}.json` };
  }
  if (typeof name === "string" && name.endsWith(".json")) return { path: resolve(name), label: name };
  throw new Error(`${JSON.stringify(name)} is not a rule set's name or a .json path`);
};

// Loads and merges the named sets, in order, then POLICY behind their program rows. Never throws:
// a set that is missing, unreadable, or broken comes back as `error`, naming it.
const loadSets = (names, off) => {
  const sets = noSets();
  let file = SET_DIR;
  try {
    for (const name of names) {
      const { path, label } = setFile(name);
      file = label;
      const text = readRuleFile(path);
      if (text === null) throw new Error("it is missing; every rule set the guard names must load");
      const set = parseSet(text, label);
      if (set.protectedBranches !== null && sets.protectedBranches !== null) throw new Error('"protectedBranches" is already set by an earlier rule set');
      sets.protectedBranches ??= set.protectedBranches;
      for (const key of ["program", "segment", "deny", "ask", "workflowOnly", "statusContexts", "repoVariables", "markerFiles", "freezeMarkers", "skipCi", "pushEnvDeny", "gitConfigAsk", "guardFiles"]) sets[key].push(...set[key]);
      sets.loaded.push(name);
    }
  } catch (error) {
    return { ...noSets(), error: loadError(file, error, off) };
  }
  sets.program.push(...POLICY);
  sets.branches = { protected: new Set(sets.protectedBranches ?? CORE_PROTECTED), workflowOnly: new Set(sets.workflowOnly), askOnPush: CORE_ASK_ON_PUSH_SET };
  return sets;
};

// No rule sets (the core alone, POLICY included), loaded once, for a caller whose rules carry none.
let defaultLoaded = null;
const defaultSets = () => {
  defaultLoaded ??= loadSets([]);
  return defaultLoaded;
};

// Checks one set file and compiles it. Throws a message naming the bad field, as parseRules() does.
const parseSet = (text, file) => {
  const data = JSON.parse(text);
  if (!isRecord(data)) throw new Error("the top level must be an object");
  onlyKeys(data, SET_KEYS, "the top level");
  const twice = duplicateKey(text);
  if (twice !== null) throw new Error(`"${twice}" appears twice in one object`);
  const set = { ...noSets(), protectedBranches: data["protectedBranches"] === undefined ? null : branchNames(data["protectedBranches"], "protectedBranches") };
  for (const verdict of ["deny", "ask"]) {
    for (const [index, entry] of listOf(data, verdict).entries()) {
      const at = `${verdict}[${index}]`;
      if (!isRecord(entry)) throw new Error(`${at} must be an object`);
      if (entry["on"] === undefined) {
        set[verdict].push({ ...rule(entry, at), file, project: false, set: true });
        continue;
      }
      const { on, ...row } = entry;
      if (on !== "program" && on !== "segment") throw new Error(`${at}.on must be "program" or "segment"`);
      const read = tableRow(row, at);
      (on === "program" ? set.program : set.segment).push({ ...read, verdict });
    }
  }
  if (data["workflowOnlyBranches"] !== undefined) set.workflowOnly.push(...branchNames(data["workflowOnlyBranches"], "workflowOnlyBranches"));
  set.statusContexts = listOf(data, "statusContexts").map((entry, index) => {
    const at = `statusContexts[${index}]`;
    knobEntry(entry, ["match", "flags", "verdict", "reason", "unreadable"], at);
    return { match: pattern(nonEmpty(entry["match"], `${at}.match`), flagsOf(entry, at), `${at}.match`), verdict: verdictOf(entry, at), reason: nonEmpty(entry["reason"], `${at}.reason`), unreadable: optional(entry, "unreadable", at) };
  });
  set.repoVariables = listOf(data, "repoVariables").map((entry, index) => {
    const at = `repoVariables[${index}]`;
    knobEntry(entry, ["name", "free", "verdict", "reason", "unreadableBody", "unreadableName"], at);
    const name = nonEmpty(entry["name"], `${at}.name`);
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new Error(`${at}.name must be a variable name`);
    const free = entry["free"] ?? [];
    if (!Array.isArray(free) || !free.every((value) => typeof value === "string")) throw new Error(`${at}.free must be an array of strings`);
    return { name, exact: new RegExp(`^${name}$`, "i"), inPath: new RegExp(`(?:^|[/=])${name}$`, "i"), free, verdict: verdictOf(entry, at), reason: nonEmpty(entry["reason"], `${at}.reason`), unreadableBody: optional(entry, "unreadableBody", at), unreadableName: optional(entry, "unreadableName", at) };
  });
  set.markerFiles = listOf(data, "markerFiles").map((entry, index) => {
    const at = `markerFiles[${index}]`;
    knobEntry(entry, ["name", "reason"], at);
    return { name: fileName(entry["name"], `${at}.name`), reason: nonEmpty(entry["reason"], `${at}.reason`) };
  });
  set.freezeMarkers = listOf(data, "freezeMarkers").map((entry, index) => {
    const at = `freezeMarkers[${index}]`;
    knobEntry(entry, ["file", "branch", "reason"], at);
    return { file: fileName(entry["file"], `${at}.file`), branch: branchNames([entry["branch"]], `${at}.branch`)[0], reason: nonEmpty(entry["reason"], `${at}.reason`) };
  });
  if (data["skipCi"] !== undefined) {
    const entry = data["skipCi"];
    knobEntry(entry, ["match", "flags", "allowOn", "reason", "unreadable"], "skipCi");
    const allowOn = entry["allowOn"] ?? [];
    if (!Array.isArray(allowOn) || !allowOn.every((name) => typeof name === "string")) throw new Error('"skipCi.allowOn" must be an array of branch names');
    set.skipCi.push({ match: pattern(nonEmpty(entry["match"], "skipCi.match"), flagsOf(entry, "skipCi"), "skipCi.match"), allowOn, reason: nonEmpty(entry["reason"], "skipCi.reason"), unreadable: nonEmpty(entry["unreadable"], "skipCi.unreadable") });
  }
  set.pushEnvDeny = listOf(data, "pushEnvDeny").map((name, index) => {
    if (typeof name !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new Error(`pushEnvDeny[${index}] must be a variable name`);
    return name;
  });
  set.guardFiles = listOf(data, "guardFiles").map((path, index) => relativePath(path, `guardFiles[${index}]`));
  set.gitConfigAsk = listOf(data, "gitConfigAsk").map((entry, index) => {
    const at = `gitConfigAsk[${index}]`;
    knobEntry(entry, ["key", "reason"], at);
    const key = nonEmpty(entry["key"], `${at}.key`);
    if (!/^[A-Za-z0-9][A-Za-z0-9.-]*$/.test(key)) throw new Error(`${at}.key must be a git setting's name`);
    return { key: key.toLowerCase(), reason: nonEmpty(entry["reason"], `${at}.reason`) };
  });
  // A set with nothing in it (`{}`, empty lists) would switch its rules off as quietly as a deleted
  // one, so it refuses every command as a missing set does.
  const held = SET_KEYS.filter((key) => key !== "$comment").reduce((count, key) => count + (Array.isArray(data[key]) ? data[key].length : data[key] === undefined ? 0 : 1), 0);
  if (held === 0) throw new Error("it holds no rows or knobs; every rule set the guard names must hold its rules");
  return set;
};

// A set row read as POLICY reads its rows: `match`, optional `unless` (the same text, unanchored),
// optional `flags: "i"` (both), `reason`.
const tableRow = (entry, at) => {
  onlyKeys(entry, ["match", "unless", "flags", "reason"], at);
  const flags = flagsOf(entry, at);
  const reason = nonEmpty(entry["reason"], `${at}.reason`);
  const match = pattern(nonEmpty(entry["match"], `${at}.match`), flags, `${at}.match`);
  const unless = entry["unless"] === undefined ? null : pattern(nonEmpty(entry["unless"], `${at}.unless`), flags, `${at}.unless`);
  return { match, unless, reason };
};

// Schema helpers for the set knobs; each throws with the field's path.
const listOf = (data, key) => {
  const value = data[key] ?? [];
  if (!Array.isArray(value)) throw new Error(`"${key}" must be an array`);
  return value;
};
const knobEntry = (entry, keys, at) => {
  if (!isRecord(entry)) throw new Error(`${at} must be an object`);
  onlyKeys(entry, keys, at);
};
// "g" or "y" would make test() remember where it stopped and miss every other call.
const flagsOf = (entry, at) => {
  const flags = entry["flags"] ?? "";
  if (flags !== "" && flags !== "i") throw new Error(`${at}.flags may only be "i"`);
  return flags;
};
const verdictOf = (entry, at) => {
  if (entry["verdict"] !== "deny" && entry["verdict"] !== "ask") throw new Error(`${at}.verdict must be "deny" or "ask"`);
  return entry["verdict"];
};
const optional = (entry, key, at) => (entry[key] === undefined ? undefined : nonEmpty(entry[key], `${at}.${key}`));
const fileName = (value, at) => {
  const name = nonEmpty(value, at);
  if (!/^[\w.-]+$/.test(name) || /^\.+$/.test(name)) throw new Error(`${at} must be a plain file name`);
  return name;
};

// The pack rule files in `dir`, by name; none when the directory isn't there.
const packFiles = (root, dir) => {
  try {
    return readdirSync(join(root, dir)).filter((name) => name.endsWith(".json")).toSorted().map((name) => `${dir}/${name}`);
  } catch (error) {
    if (isMissing(error, join(root, dir))) return [];
    throw error;
  }
};

// A rule file's text, or null when nothing is at that path. A dangling symlink or an unreadable
// file is not "absent": it throws, so the caller refuses everything. So is a FIFO or a device:
// reading one blocks, and the watchdog can stop JavaScript but not a read blocked in the kernel.
const readRuleFile = (path) => {
  try {
    if (!statSync(path).isFile()) throw new Error(`${path} is not a regular file`);
    return readFileSync(path, "utf8");
  } catch (error) {
    if (isMissing(error, path)) return null;
    throw error;
  }
};

// True when `error` says nothing is at `path` and not even a link sits there.
const isMissing = (error, path) => {
  if (!(error instanceof Error) || !("code" in error) || error.code !== "ENOENT") return false;
  try {
    lstatSync(path);
    return false;
  } catch {
    return true;
  }
};

// Characters that make a command more than plain words: an exemption with one could match more
// than the one command it names (`$X`, a background `&`, a redirect, a subshell, a glob, a brace, `~`).
const SHELL_SYNTAX = /[$`&;|<>(){}[\]*?~\n]/;

// Checks one rule file and compiles its patterns. Throws a message naming the bad field: an unknown
// key, a missing reason, or a pattern that doesn't compile would otherwise drop a rule silently.
// Exemptions (`allow`) belong to the project file only; a pack can only refuse or ask. `extraKeys`
// are the config's knobs, which share its file (parseConfig() reads them).
const parseRules = (text, { project, branches, sets, guard, extraKeys = [] }) => {
  const data = JSON.parse(text);
  if (!isRecord(data)) throw new Error("the top level must be an object");
  const kinds = project ? ["deny", "ask", "allow"] : ["deny", "ask"];
  onlyKeys(data, [...kinds, "$comment", ...extraKeys], "the top level");
  // JSON.parse keeps only the last of two same-named keys, so a second "deny" block or "match" would erase the first.
  const twice = duplicateKey(text);
  if (twice !== null) throw new Error(`"${twice}" appears twice in one object`);
  const list = (kind) => {
    const value = data[kind] ?? [];
    if (!Array.isArray(value)) throw new Error(`"${kind}" must be an array`);
    return value.map((entry, index) => {
      const at = `${kind}[${index}]`;
      if (!isRecord(entry)) throw new Error(`${at} must be an object`);
      return kind === "allow" ? exemption(entry, at, branches, sets, guard) : rule(entry, at);
    });
  };
  return { deny: list("deny"), ask: list("ask"), allow: project ? list("allow") : [] };
};

// A deny or ask entry: `match` (anchor it with ^), `reason`, optional `unless`, optional `flags: "i"`.
const rule = (entry, at) => {
  onlyKeys(entry, ["match", "unless", "flags", "reason"], at);
  const reason = nonEmpty(entry["reason"], `${at}.reason`);
  // "g" or "y" would make test() remember where it stopped and miss every other call.
  const flags = entry["flags"] ?? "";
  if (flags !== "" && flags !== "i") throw new Error(`${at}.flags may only be "i"`);
  const match = pattern(nonEmpty(entry["match"], `${at}.match`), flags, `${at}.match`);
  if (entry["unless"] === undefined) return { match, unless: null, reason };
  // `unless` reads from the command's first word, so a comment or a later argument can't satisfy it.
  const unless = pattern(nonEmpty(entry["unless"], `${at}.unless`), flags, `${at}.unless`);
  return { match, unless: new RegExp(`^(?:${unless.source})`, flags), reason };
};

// An exemption: one literal command, compared word for word (its tokens as one string that keeps
// their boundaries, so `a "b c"` and `a b c` differ), so it can't widen to another path or verb.
const exemption = (entry, at, branches, sets, guard) => {
  onlyKeys(entry, ["command", "reason"], at);
  nonEmpty(entry["reason"], `${at}.reason`);
  const command = nonEmpty(entry["command"], `${at}.command`);
  if (SHELL_SYNTAX.test(command)) throw new Error(`${at}.command must be one plain command, with no $ \` & ; | < > ( ) { } [ ] * ? ~ or newline`);
  // Run it past the built-in rules and the rule sets with itself exempt: anything left is a rule no
  // exemption may lift (branch protection, Ready, merges, reruns, --no-verify, destructive SQL,
  // migration tools, any set's row or knob), so the file is broken.
  const key = JSON.stringify(words(command));
  for (const branch of [...branches.protected, ""]) {
    const left = evaluate(command, { branch, branchIn: () => branch, rules: { ...NO_RULES, branches, sets, guard, allow: new Set([key]) } });
    if (left) throw new Error(`${at}.command meets a built-in rule an exemption can't lift: ${left.reason}`);
  }
  return key;
};

// The first key given twice in one JSON object, at any depth, or null. `text` already parsed.
const duplicateKey = (text) => {
  // One entry per open object (its keys so far) or array (null).
  const open = [];
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (char === "{") open.push(new Set());
    else if (char === "[") open.push(null);
    else if (char === "}" || char === "]") open.pop();
    else if (char === '"') {
      // Read to the closing quote, stepping over escapes.
      let end = i + 1;
      while (end < text.length && text[end] !== '"') end += text[end] === "\\" ? 2 : 1;
      const raw = text.slice(i, end + 1);
      i = end;
      // Inside an object, a string followed by ":" is a key.
      let next = end + 1;
      while (/\s/.test(text[next] ?? "")) next += 1;
      const keys = open.at(-1);
      if (keys instanceof Set && text[next] === ":") {
        const key = String(JSON.parse(raw));
        if (keys.has(key)) return key;
        keys.add(key);
      }
    }
  }
  return null;
};

// Schema helpers: each throws with the field's path.
const isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
const onlyKeys = (value, allowed, at) => {
  const unknown = Object.keys(value).find((key) => !allowed.includes(key));
  if (unknown !== undefined) throw new Error(`${at} has an unknown key "${unknown}"`);
};
const nonEmpty = (value, at) => {
  if (typeof value !== "string" || value.trim() === "") throw new Error(`${at} must be a non-empty string`);
  return value;
};
const pattern = (source, flags, at) => {
  try {
    return new RegExp(source, flags);
  } catch (error) {
    throw new Error(`${at}: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
  }
};

// The host a hook was called for decides the input and output shapes.
const hostOf = (value) => (value === "cursor" ? "cursor" : "claude");

// The human's off switch, for a session where the guard is in the way: any `offEnv` name set to `off`.
const guardOff = (offEnv = DEFAULT_OFF_ENV) => offEnv.some((name) => process.env[name] === "off");

// The ask the watchdog gives when no verdict came in time.
const watchdogAsk = () => ask(`The guard didn't reach a verdict within its ${WATCHDOG_MS} ms watchdog, so it stopped reading; the user confirms this command. Tell the user if this repeats: something in the guard is slow.`);

// The project root a hook reads its config from: the caller's `root`, else the project folder the
// host exports to hook processes (CLAUDE_PROJECT_DIR, CURSOR_PROJECT_DIR), else the hook's own cwd.
// Never the payload's cwd, which moves with the agent.
const rootOf = (root) => root ?? process.env["CLAUDE_PROJECT_DIR"] ?? process.env["CURSOR_PROJECT_DIR"] ?? process.cwd();

// Hook entry point: stdin JSON in, host-specific JSON out, always within WATCHDOG_MS.
// Options: `host` ("claude" or "cursor"; default argv[2]), `root`, `files`, `sets` (loadRules()),
// `offEnv` (the off switch's names; DEFAULT_OFF_ENV).
//
// The guard fails closed to ask, never to allow: the host's own timeout (10 s) lets a command run,
// so a guard bug must reach the user instead. A line over MAX_COMMAND_CHARS asks before it is
// parsed, a read over MAX_EVALUATE_MS of CPU time (or MAX_EVALUATE_WALL_MS of wall-clock) asks (evaluate()), an exception asks and names it, and hook
// input with no command in it asks. Two watchdogs share the one deadline: a timer while stdin is read (a host that never closes it),
// then vm's `timeout` around the evaluation (hookVerdict() below), which V8 enforces from its own
// thread, so a loop that forgets tick() or a rule pattern that backtracks is stopped mid-run and
// the answer is an ask naming the watchdog, before the hook's own timeout lets the command run.
// Nothing stops a blocking system call, so every one the evaluation makes bounds itself (git's
// timeout, rule files read only when regular). Not a worker thread: one costs ~50 ms to start on
// every command, and exit waits for a worker blocked in a system call, so it bounds nothing more.
// Exported for the hook entry, which turns a guard that doesn't
// load, or exits any other way than with an answer, into a block.
export const main = ({ host = hostOf(process.argv[2]), root, files, sets, offEnv = DEFAULT_OFF_ENV } = {}) => {
  const started = performance.now();
  const off = () => guardOff(offEnv);
  const say = (verdict) => respond(verdict, hostOf(host));
  let answered = false;
  // Writes the first answer and exits; anything after it (the stdin timer) is a no-op.
  const answer = (verdict) => {
    if (answered) return;
    answered = true;
    say(verdict);
    process.exit(0);
  };
  // Fail closed to ask: a guard bug must neither let the command through unseen nor wedge the
  // session, so the user decides, told why. With the off switch set, nothing is said.
  // The answer goes out before the stderr note, which may fail (a closed stderr is EPIPE) and must
  // not take the answer with it.
  const failed = (error) => {
    if (answered) return;
    answered = true;
    const message = error instanceof Error ? error.message : String(error);
    say(off() ? null : ask(`The guard failed (${message}), so the user confirms this command. Tell the user: a guard bug must not let a command through unseen.`));
    try {
      writeSync(2, `reins: failed (${message})\n`);
    } catch {
      // Nowhere left to say it; the answer is already out.
    }
    process.exit(0);
  };
  // Started first, so it covers reading stdin too (a host that never closes it).
  setTimeout(() => answer(off() ? null : watchdogAsk()), WATCHDOG_MS);
  const chunks = [];
  process.stdin.on("data", (chunk) => chunks.push(chunk));
  process.stdin.on("error", failed);
  process.stdin.on("end", () => {
    try {
      // Claude sends { tool_input: { command }, cwd }; Cursor sends { command, cwd }.
      const input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      const raw = input?.tool_input?.command ?? input?.command;
      const cwd = String(input?.cwd ?? process.cwd());
      if (off()) {
        answer(null);
        return;
      }
      // No command where the host puts one (a renamed field, a different tool's input): asking,
      // not reading "" and allowing, so a change in the host's shape can't switch the guard off.
      if (typeof raw !== "string") {
        answer(ask("The guard found no command in the hook's input (`tool_input.command` or `command`), so it couldn't read what will run; the user confirms. Tell the user: the host's hook input may have changed shape."));
        return;
      }
      const command = raw;
      // Whatever is left of the deadline; vm throws ERR_SCRIPT_EXECUTION_TIMEOUT when it runs out.
      const left = Math.max(1, Math.ceil(WATCHDOG_MS - (performance.now() - started)));
      answer(runInNewContext("verdict()", { verdict: () => hookVerdict(command, cwd, { root, files, sets, offEnv }) }, { timeout: left }));
    } catch (error) {
      if (watchdogFired(error)) answer(watchdogAsk());
      else failed(error);
    }
  });
};

// main()'s evaluation, all of it under the watchdog: branch lookups, rule files, and evaluate().
// `root` is where the config and the project's rule files are read (rootOf()); `files`, `sets`,
// and `offEnv` go to loadRules().
// Exported for a caller that judges the argv it is about to spawn the way the hook judges a typed command.
export const hookVerdict = (command, cwd, { root, files, sets, offEnv } = {}) => {
  // The branch is read lazily, by the first rule that needs it (a push or commit parsed from the line, whatever
  // spelling got it there: `g''it`, `$'g\x69t'`, `sh -c "…"`), so a line that never pushes looks nothing up.
  const branch = () => currentBranch(cwd);
  // A `cd X` / `git -C X` directory, resolved from the hook's cwd (and `~` from home).
  const branchIn = (dir) => currentBranch(dir.startsWith("~") ? join(homedir(), dir.slice(1)) : resolve(cwd, dir));
  // A freeze marker (`file`) for a push run in the hook's cwd (null) or a `cd X` / `git -C X` directory.
  const shipFreezeIn = (dir, file) => shipFreeze(dir === null ? cwd : dir.startsWith("~") ? join(homedir(), dir.slice(1)) : resolve(cwd, dir), file);
  // A command's directory: the hook's cwd, or a `cd` target resolved from it (and `~` from home).
  const where = (dir) => (dir === null ? cwd : dir.startsWith("~") ? join(homedir(), dir.slice(1)) : resolve(cwd, dir));
  // A file's text there, or null when it is missing, not a regular file (`/dev/stdin`, a FIFO, a
  // directory), unreadable, or too big to judge. stat, not lstat: a symlink is judged by what it
  // points at, so a link can't carry a huge file past the size cap.
  const readSql = (dir, path) => {
    try {
      const full = resolve(where(dir), path);
      const found = statSync(full);
      return found.isFile() && found.size <= MAX_SQL_FILE_BYTES ? readFileSync(full, "utf8") : null;
    } catch {
      return null;
    }
  };
  // The same, as "" when it can't be read (a .env or package.json that isn't there says nothing).
  const readText = (dir, path) => readSql(dir, path) ?? "";
  // What a folder holds (a multi-file Prisma schema): its files and folders, up to 256 entries read
  // one at a time (opendir, so a huge folder isn't listed whole), `more` past that. Null when
  // nothing is there; { dir: false } for anything that isn't a folder (stat follows a symlink).
  const dirIn = (dir, path) => {
    let handle = null;
    try {
      const full = resolve(where(dir), path);
      if (!statSync(full).isDirectory()) return { dir: false };
      handle = opendirSync(full);
      const files = [];
      const dirs = [];
      for (let entry = handle.readSync(); entry !== null; entry = handle.readSync()) {
        if (files.length + dirs.length >= 256) return { dir: true, files, dirs, more: true };
        // A symlink is judged by what it points at, as readSql does; a dangling one is a file
        // that can't be read (unseen when it is a `.prisma`), not a reason to drop the folder.
        let folder = entry.isDirectory();
        try {
          if (entry.isSymbolicLink()) folder = statSync(join(full, entry.name)).isDirectory();
        } catch {
          folder = false;
        }
        if (folder) dirs.push(entry.name);
        else files.push(entry.name);
      }
      return { dir: true, files, dirs, more: false };
    } catch (error) {
      // Nothing there says nothing; anything else that fails to list is unreadable.
      return error instanceof Error && "code" in error && error.code === "ENOENT" ? null : { dir: false };
    } finally {
      handle?.closeSync();
    }
  };
  // Whether a `cd` target is a directory there; a `cd` into one that isn't fails, and the guard loses track.
  const dirExists = (dir) => {
    try {
      return statSync(where(dir)).isDirectory();
    } catch {
      return false;
    }
  };
  // A database URL variable as the tool will see it: this process's environment (the agent's), then
  // `file` (default .env; null for the environment only) where the command runs, as dotenv loads it
  // (it never overrides a set variable).
  // `useEnv` false skips the environment, for a variable the line removed (`unset`, `env -u`).
  const targetIn = (/** @type {string | null} */ dir, /** @type {string} */ name, /** @type {string | null} */ file = ".env", useEnv = true) => {
    if (useEnv && process.env[name] !== undefined) return { value: process.env[name], from: "the environment" };
    const value = file === null ? undefined : dotenvValue(readText(dir, file), name);
    return value === undefined ? null : { value, from: file };
  };
  // package.json's command for a script name where the command runs, or "".
  const scriptIn = (dir, name) => {
    try {
      const script = JSON.parse(readText(dir, "package.json")).scripts?.[name];
      return typeof script === "string" ? script : "";
    } catch {
      return "";
    }
  };
  // Rule files live at the project root, whatever the command's cwd.
  const rules = loadRules(rootOf(root), { files, sets, offEnv });
  return evaluate(command, { branch, branchIn, shipFreezeIn, rules, targetIn, scriptIn, fileIn: readSql, dirIn, dirExists });
};

// Writes a verdict (or null, no opinion) in the calling host's shape. writeSync, not
// process.stdout.write: a pipe's stdout is asynchronous on macOS, and main() exits right after.
export const respond = (verdict, host = "claude") => {
  // Cursor treats missing or invalid JSON as a block, so it always gets an answer.
  if (host === "cursor") {
    const permission = verdict?.decision ?? "allow";
    const message = verdict ? `reins: ${verdict.reason}` : undefined;
    writeSync(1, JSON.stringify({ permission, user_message: message, agent_message: message }));
    return;
  }

  // Claude: silence means "no opinion"; a verdict goes out as a permission decision.
  if (verdict) {
    writeSync(
      1,
      JSON.stringify({
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: verdict.decision,
          permissionDecisionReason: `reins: ${verdict.reason}`,
        },
      }),
    );
  }
};
