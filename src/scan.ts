import { walk } from "./fsx.js"
import { checkAgents } from "./checks/agents.js"
import { checkCloud } from "./checks/cloud.js"
import { checkDatabase } from "./checks/database.js"
import { checkSsh } from "./checks/ssh.js"
import type { AgentId, Ctx, Env, Finding, Scope } from "./types.js"
import { label, score } from "./weights.js"

export interface ScanOptions {
  agents: AgentId[]
  scope: Scope
  path: string
  home: string
  env: Env
  prodAccounts?: string[]
}

export interface ScanResult {
  agents: AgentId[]
  scope: Scope
  findings: Finding[]
  score: number
  label: "Small" | "Medium" | "Large"
}

export function scan(o: ScanOptions): ScanResult {
  const findings: Finding[] = []
  const ctx: Ctx = {
    home: o.home,
    prodAccounts: o.prodAccounts ?? [],
    project: o.path,
    env: o.env,
    agents: o.agents,
    global: o.scope !== "project",
    inProject: o.scope !== "global",
    add: (f) => findings.push(f),
    display(file) {
      if (file.startsWith(o.path + "/")) return file.slice(o.path.length + 1)
      if (file.startsWith(o.home + "/")) return "~" + file.slice(o.home.length)
      return file
    },
  }
  const files = ctx.inProject ? walk(o.path) : []
  checkDatabase(ctx, files)
  checkAgents(ctx)
  checkSsh(ctx)
  checkCloud(ctx, files)
  const s = score(findings)
  return {
    agents: o.agents,
    scope: o.scope,
    findings,
    score: s,
    label: label(s),
  }
}
