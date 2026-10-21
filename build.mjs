import { build } from "esbuild"
import { execFileSync } from "node:child_process"
import { chmod, rm } from "node:fs/promises"
import { createRequire } from "node:module"
const shared = {
  bundle: true,
  platform: "node",
  target: "node22",
  format: "esm",
}
await rm("dist", { recursive: true, force: true })
await build({
  ...shared,
  entryPoints: ["src/main.ts"],
  outfile: "dist/cli.mjs",
  banner: { js: "#!/usr/bin/env node" },
})
await build({
  ...shared,
  entryPoints: ["src/index.ts"],
  outfile: "dist/index.mjs",
})
await chmod("dist/cli.mjs", 0o755)
// Type declarations for the library entry only. Tests are not reachable from index.ts.
const tsc = createRequire(import.meta.url).resolve("typescript/bin/tsc")
execFileSync(process.execPath, [tsc, "-p", "tsconfig.build.json"], {
  stdio: "inherit",
})
