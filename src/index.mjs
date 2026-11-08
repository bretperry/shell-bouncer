// The package's public surface: `import { evaluate, loadRules, main, askGate } from "reins"`.
// In the app: nothing at runtime; a caller (a project's own hook adapter) imports it.
// Used by: package.json "exports"; tested by test/*.test.mjs.
// Uses: src/guard.mjs (the guard), src/ask-gate.mjs (the ask gate, as `askGate`).
// Run: not directly; import it.
// When: a project wraps reins in its own hook, or judges a command it is about to spawn.
// Env: none here.
// Writes: nothing.
// Exit: n/a (a module).
export { BUNDLED_SETS, DEFAULT_FILES, PACKAGE_NAME, DEFAULT_OFF_ENV, LIMITS, WATCHDOG_MS, askTagsOf, destroysSql, dotenvValue, evaluate, hookVerdict, loadRules, main, parseLine, respond, shipFreeze, targetOf, words } from "./guard.mjs";
export * as askGate from "./ask-gate.mjs";
