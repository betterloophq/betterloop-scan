import { build } from "esbuild"
import { chmod, rm } from "node:fs/promises"
await rm("dist", { recursive: true, force: true })
await build({
  entryPoints: ["src/main.ts"],
  outfile: "dist/cli.mjs",
  bundle: true,
  platform: "node",
  target: "node22",
  format: "esm",
  banner: { js: "#!/usr/bin/env node" },
})
await chmod("dist/cli.mjs", 0o755)
