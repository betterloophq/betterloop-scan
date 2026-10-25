import { walk } from "./fsx.js"
import { checkAgents } from "./checks/agents.js"
import { checkCloud } from "./checks/cloud.js"
import { checkDatabase } from "./checks/database.js"
import { checkSsh } from "./checks/ssh.js"
import type { AgentId, Ctx, Env, Finding, Reach, Scope } from "./types.js"
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
  reach: Reach[]
  score: number
  label: "Small" | "Medium" | "Large"
}

export function scan(o: ScanOptions): ScanResult {
  const findings: Finding[] = []
  // One entry per kind and name; later sightings fill in missing identifiers.
  const reach = new Map<string, Reach>()
  const ctx: Ctx = {
    home: o.home,
    prodAccounts: o.prodAccounts ?? [],
    project: o.path,
    env: o.env,
    agents: o.agents,
    global: o.scope !== "project",
    inProject: o.scope !== "global",
    add: (f) => findings.push(f),
    reach(r) {
      const key = `${r.kind}:${r.name}`
      const seen = reach.get(key)
      reach.set(key, seen ? { ...r, ...seen, ...defined(seen, r) } : r)
    },
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
    reach: [...reach.values()],
    score: s,
    label: label(s),
  }
}

// Fields the earlier sighting lacked, taken from the later one.
function defined(seen: Reach, next: Reach): Partial<Reach> {
  const out: Partial<Reach> = {}
  for (const k of ["account", "role", "host"] as const)
    if (!seen[k] && next[k]) out[k] = next[k]
  return out
}
