import { homedir } from "node:os"
import { resolve } from "node:path"
import { createInterface } from "node:readline/promises"
import type { Readable, Writable } from "node:stream"
import { detectAgents } from "./checks/agents.js"
import { jsonReport, terminal } from "./report.js"
import { scan } from "./scan.js"
import { AGENT_NAMES, type AgentId, type Env, type Scope } from "./types.js"

export interface Io {
  env: Env
  stdin: Readable
  stdout: Writable
  isTTY: boolean
  platform: string
  cwd: string
}

const IDS = Object.keys(AGENT_NAMES) as AgentId[]
const SCOPES: Scope[] = ["global", "project", "both"]

interface Args {
  agent?: string
  scope?: string
  path?: string
  home?: string
  prodAccounts?: string
  json: boolean
}

function parse(argv: string[]): Args {
  const a: Args = { json: false }
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i]
    if (k === "--json") a.json = true
    else if (
      ["--agent", "--scope", "--path", "--home", "--prod-accounts"].includes(k)
    ) {
      const v = argv[++i]
      if (v === undefined) throw new Error(`${k} needs a value`)
      if (k === "--prod-accounts") a.prodAccounts = v
      else a[k.slice(2) as "agent" | "scope" | "path" | "home"] = v
    } else throw new Error(`Unknown option: ${k}`)
  }
  return a
}

function pickAgents(
  value: string,
  detected: AgentId[],
  notes: string[]
): AgentId[] {
  const named = value.split(",").map((s) => s.trim())
  if (named.includes("all")) return IDS
  const picked: AgentId[] = []
  for (const n of named) {
    if (!IDS.includes(n as AgentId)) throw new Error(`Unknown agent: ${n}`)
    if (detected.includes(n as AgentId)) picked.push(n as AgentId)
    else
      notes.push(`${AGENT_NAMES[n as AgentId]} is not installed. Skipping it.`)
  }
  return picked
}

export async function run(argv: string[], io: Io): Promise<number> {
  const out = (s: string) => void io.stdout.write(s)
  if (io.platform === "win32") {
    out("Windows is not supported yet\n")
    return 0
  }
  let args: Args
  try {
    args = parse(argv)
  } catch (e) {
    out(`${(e as Error).message}\n`)
    return 2
  }
  const home = resolve(args.home ?? homedir())
  const path = resolve(io.cwd, args.path ?? ".")
  const detected = detectAgents(home, io.env)
  const notes: string[] = []
  let agentValue = args.agent
  let scopeValue = args.scope
  const ask = io.isTTY && !args.json && (!agentValue || !scopeValue)

  try {
    if (ask) {
      const rl = createInterface({ input: io.stdin, output: io.stdout })
      try {
        if (!agentValue) {
          out("Which coding agent do you want to check?\n")
          IDS.forEach((id, i) =>
            out(
              `  ${i + 1}) ${AGENT_NAMES[id]} (${detected.includes(id) ? "detected" : "not found"})\n`
            )
          )
          out(`  ${IDS.length + 1}) All detected\n`)
          const answer = await rl.question(
            `Pick one or more, comma-separated [${IDS.length + 1}]: `
          )
          const nums = answer
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean)
          agentValue =
            !nums.length || nums.includes(String(IDS.length + 1))
              ? detected.join(",") || "none"
              : nums.map((n) => IDS[Number(n) - 1] ?? n).join(",")
        }
        if (!scopeValue) {
          out("Where should we check?\n")
          out(
            "  1) Global: this machine's user-level config (home folder, environment variables)\n"
          )
          out("  2) Project: only the current folder (or --path)\n")
          out("  3) Both\n")
          const answer = (await rl.question("Pick one [3]: ")).trim()
          scopeValue = SCOPES[Number(answer || "3") - 1] ?? answer
        }
      } finally {
        rl.close()
      }
    }
    const scope = (scopeValue ?? "both") as Scope
    if (!SCOPES.includes(scope)) throw new Error(`Unknown scope: ${scope}`)
    const agents =
      agentValue === "none"
        ? []
        : pickAgents(agentValue ?? "all", detected, notes)
    if (agentValue === "none")
      notes.push("No coding agents detected on this machine.")
    const prodAccounts = (args.prodAccounts ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
    for (const id of prodAccounts)
      if (!/^\d{12}$/.test(id))
        throw new Error("--prod-accounts needs 12-digit AWS account IDs")
    const result = scan({
      agents,
      scope,
      path,
      home,
      env: io.env,
      prodAccounts,
    })
    out(args.json ? jsonReport(result, notes) : terminal(result, notes))
    return 0
  } catch (e) {
    out(`${(e as Error).message}\n`)
    return 2
  }
}
