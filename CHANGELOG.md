# Changelog

## 0.1.1

- Add `shell-bouncer` as a CLI alias alongside `bouncer` and `reins`.
- Use Shell Bouncer as the product name throughout the documentation.

## 0.1.0

- Initial npm release as `shell-bouncer`. Use `bouncer` for new hook setups; `reins` remains an alias.
- Add installation instructions for Claude Code and Cursor, plus `bouncer --version`.
- Make `bouncer explain` honor the project root and guard state.
- Keep question text out of ask logs, limit where the project can write them, and avoid echoing invalid hook JSON.
- Bound reads of Git freeze markers and preserve the freeze when a marker exists but cannot be read.
