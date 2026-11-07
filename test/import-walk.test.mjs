// The package source must import only Node builtins and its own files.
// Used by: node:test.
// Run: node --test test/import-walk.test.mjs.
// When: changing the guard's modules or their imports.
// Env: none.
// Writes: nothing.
// Exit: 0 imports stay inside the package source, 1 a boundary escapes.
import assert from "node:assert/strict";
import { builtinModules } from "node:module";
import { readdirSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = realpathSync(fileURLToPath(new URL("../src/", import.meta.url)));
const builtins = new Set(builtinModules.flatMap((name) => [name, `node:${name}`]));

// Computed imports are refused because their targets cannot be checked statically.
const imports = (file) => {
  const source = readFileSync(file, "utf8").replace(/^[ \t]*\/\/.*$/gm, "");
  for (const call of source.matchAll(/\b(?:import|require)\s*\(([^)]*)\)/g)) {
    assert.match(call[1].trim(), /^(["'])[^"']+\1$/, `${file}: computed import`);
  }
  return [...source.matchAll(/(?:from\s+|import\s*\(\s*|require\s*\(\s*|^import\s+)["']([^"']+)["']/gm)].map((match) => match[1]);
};

test("every runtime import stays in the package source or Node builtins", () => {
  const files = readdirSync(root, { recursive: true }).filter((name) => name.endsWith(".mjs"));
  assert.ok(files.length > 0);
  for (const name of files) {
    const file = join(root, name);
    for (const specifier of imports(file)) {
      if (builtins.has(specifier)) continue;
      assert.ok(specifier.startsWith("."), `${name}: external dependency ${specifier}`);
      const target = realpathSync(resolve(dirname(file), specifier));
      assert.ok(!relative(root, target).startsWith(".."), `${name}: escapes package source: ${specifier}`);
    }
  }
});
