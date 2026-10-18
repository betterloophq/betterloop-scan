export type Severity = "critical" | "high" | "medium" | "low" | "info"
export type Category = "database" | "agents" | "ssh" | "cloud"
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

export interface Ctx {
  home: string
  project: string
  prodAccounts: string[]
  env: Env
  agents: AgentId[]
  global: boolean
  inProject: boolean
  add(f: Finding): void
  display(file: string): string
}

export const AGENT_NAMES: Record<AgentId, string> = {
  "claude-code": "Claude Code",
  codex: "Codex",
  cursor: "Cursor",
}
