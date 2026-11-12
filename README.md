# Shell Bouncer

Shell Bouncer checks shell commands before Claude Code or Cursor runs them. It can block commands covered by your rules or send them to you for approval. The built-in rules cover actions such as rewriting protected Git branches and deleting data from remote databases.

## Install

Requires Node.js 22 or later. Use Git on your PATH for branch-aware rules.

```sh
npm install --global shell-bouncer
bouncer --version
bouncer explain 'git status'
```

The package installs the `bouncer` command. Existing hooks can still use the `reins` alias.

## Connect your agent

Merge the appropriate example into your existing settings. Install Bouncer in the environment where the agent runs and make sure its hook process can find `bouncer` on PATH. If needed, use the absolute path from `command -v bouncer`, then restart the agent.

**Claude Code** — `.claude/settings.json` ([hook docs](https://code.claude.com/docs/en/hooks)):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "bouncer hook claude", "timeout": 10 }]
      }
    ]
  }
}
```

**Cursor** — `.cursor/hooks.json` ([hook docs](https://cursor.com/docs/hooks)):

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      { "command": "bouncer hook cursor", "timeout": 10, "failClosed": true }
    ]
  }
}
```

## Project rules

No configuration is required for the built-in policy. To add a protected branch or enable an optional workflow set, create `reins.json` in your project root:

```json
{
  "protectedBranches": ["main", "master", "production"],
  "sets": ["draft-flow"]
}
```

Run `bouncer sets` to see what the optional sets cover. Run `bouncer explain '<command>'` from the directory where the agent would run the command to see the verdict without executing it. Pass `--root <dir>` to use that directory for both configuration and evaluation.

Claude Code users can optionally configure `askTags` and wire `bouncer ask-gate` to a `PreToolUse` hook matching `AskUserQuestion`. For example, `"askTags": { "tags": ["only-you"] }` requires each question to begin with `[only-you]`. This separate hook is off by default and lets questions through if its input or config cannot be read.

## Scope and privacy

Bouncer is a guardrail for configured shell hooks. Keep your agent's sandbox, access controls, and repository protection in place. Commands outside those hooks are outside Bouncer's scope.

Bouncer does not send telemetry. It reads the hook input and may inspect local project files such as `reins.json`, `.env`, or a referenced SQL file to decide what a command would do. Verdict reasons go back to the agent host. If you enable `askTags.log`, the local log records timestamps and matching tags, without question text. Choose a file inside an existing directory in the project, keep the log out of version control, and restrict it to your user.

To stop using the guard, remove its hook entry before uninstalling the package. See [SECURITY.md](SECURITY.md) for reporting guidance. Shell Bouncer is source-available under the Functional Source License; see [LICENSE](LICENSE).
