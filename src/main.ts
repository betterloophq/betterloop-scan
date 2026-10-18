import { run } from "./cli.js"

process.exitCode = await run(process.argv.slice(2), {
  env: process.env,
  stdin: process.stdin,
  stdout: process.stdout,
  isTTY: Boolean(process.stdin.isTTY && process.stdout.isTTY),
  platform: process.platform,
  cwd: process.cwd(),
})
