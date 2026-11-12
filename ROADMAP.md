# 0.2.0 candidates

- Add `bouncer doctor` for Node, PATH, project config, and host hook setup.
- Ship a JSON Schema for project configuration and add structured output to `bouncer explain`.
- Exercise real Claude Code and Cursor installations in integration tests. Verify permission outcomes, startup failures, and timeouts.
- Share bounded input and file reads across the CLI and hook. Isolate filesystem calls that can block past the watchdog.
- Split the parser from policy evaluation so each can be tested and maintained independently.
- Evaluate Windows support with a test matrix before advertising it.
- Decide on a public support channel and whether to publish the source. If the source becomes public, configure trusted npm publishing and provenance.
