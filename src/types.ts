export type Severity = "critical" | "high" | "medium" | "low" | "info"
// "environments" is only produced by callers that judge findings against their own environment rules.
export type Category = "database" | "agents" | "ssh" | "cloud" | "environments"
export type AgentId = "claude-code" | "codex" | "cursor"
export type Scope = "global" | "project" | "both"
export type Env = Record<string, string | undefined>

export interface Finding {
  category: Category
  severity: Severity
  title: string
  location: string
  fix: string
}

/**
 * Something on this machine an agent could use to reach a system, with its
 * non-secret identifiers. Kept in memory for callers such as `betterloop scan`
 * that match it against an organization's environments. Never printed and
 * never part of --json.
 */
export interface Reach {
  kind:
    | "aws_profile"
    | "aws_env_key"
    | "azure_subscription"
    | "database"
    | "env_file"
    | "gcp_project"
    | "kube_context"
    | "ssh_host"
    | "ssh_key"
  name: string
  account?: string
  role?: string
  host?: string
  location: string
}

export interface Ctx {
  home: string
  project: string
  prodAccounts: string[]
  env: Env
  agents: AgentId[]
  global: boolean
  inProject: boolean
  add(f: Finding): void
  reach(r: Reach): void
  display(file: string): string
}

export const AGENT_NAMES: Record<AgentId, string> = {
  "claude-code": "Claude Code",
  codex: "Codex",
  cursor: "Cursor",
}
