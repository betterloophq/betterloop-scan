import { accessSync, constants } from "node:fs"
import { join } from "node:path"
import { json, read, sections } from "../fsx.js"
import { AGENT_NAMES, type AgentId, type Ctx, type Env } from "../types.js"

// `cursor-agent` is UNCONFIRMED in current Cursor docs (they only show `agent`). Kept as an alias.
const BINARIES: Record<AgentId, string[]> = {
  "claude-code": ["claude"],
  codex: [],
  cursor: ["agent", "cursor-agent"],
}
const HOME_DIRS: Record<AgentId, string> = {
  "claude-code": ".claude",
  codex: ".codex",
  cursor: ".cursor",
}

function onPath(bin: string, env: Env): boolean {
  return (env.PATH ?? "").split(":").some((dir) => {
    try {
      accessSync(join(dir, bin), constants.X_OK)
      return true
    } catch {
      return false
    }
  })
}

export function detectAgents(home: string, env: Env): AgentId[] {
  return (Object.keys(HOME_DIRS) as AgentId[]).filter(
    (id) =>
      dirExists(join(home, HOME_DIRS[id])) ||
      BINARIES[id].some((b) => onPath(b, env))
  )
}

function dirExists(p: string): boolean {
  try {
    accessSync(p, constants.R_OK)
    return true
  } catch {
    return false
  }
}

// ponytail: substring heuristic on name, command, args and url. Misses renamed servers.
const RISKY =
  /postgres|mysql|mongo|redis|sqlite|supabase|database|aws|gcp|gcloud|azure|kube|k8s|docker|filesystem|shell|terminal|bash|ssh/i

function mcp(ctx: Ctx, agent: AgentId, where: string, servers: unknown) {
  if (!servers || typeof servers !== "object") return
  for (const [name, s] of Object.entries(servers as Record<string, any>)) {
    const text = [
      name,
      s?.command,
      ...(Array.isArray(s?.args) ? s.args : []),
      s?.url,
    ]
      .filter((x) => typeof x === "string")
      .join(" ")
    const risky = RISKY.test(text)
    ctx.add({
      category: "agents",
      severity: risky ? "high" : "low",
      title: `${AGENT_NAMES[agent]} MCP server "${name}"${risky ? " with database, cloud, shell or filesystem access" : ""}`,
      location: where,
      fix: risky
        ? "Remove it, or limit it to read-only access on a non-production target."
        : "Remove it if you do not use it.",
    })
  }
}

const BROAD_ALLOW = /^(Bash|Bash\(\*\))$/

function claude(ctx: Ctx) {
  const files: [string, boolean][] = [
    [join(ctx.home, ".claude/settings.json"), true],
    [join(ctx.project, ".claude/settings.json"), false],
    [join(ctx.project, ".claude/settings.local.json"), false],
  ]
  for (const [file, isGlobal] of files) {
    if (isGlobal ? !ctx.global : !ctx.inProject) continue
    const s = json(file)
    if (!s || typeof s !== "object") continue
    const where = ctx.display(file)
    if (s.permissions?.defaultMode === "bypassPermissions")
      ctx.add({
        category: "agents",
        severity: "critical",
        title:
          "Claude Code runs with no permission prompts (bypassPermissions)",
        location: where,
        fix: 'Set permissions.defaultMode to "default" so risky actions ask first.',
      })
    if (s.skipDangerousModePermissionPrompt === true)
      ctx.add({
        category: "agents",
        severity: "high",
        title: "Claude Code skips the bypass-mode warning",
        location: where,
        fix: "Remove skipDangerousModePermissionPrompt.",
      })
    for (const rule of Array.isArray(s.permissions?.allow)
      ? s.permissions.allow
      : [])
      if (typeof rule === "string" && BROAD_ALLOW.test(rule))
        ctx.add({
          category: "agents",
          severity: "high",
          title: `Claude Code allows every shell command (${rule})`,
          location: where,
          fix: "Replace it with specific rules like Bash(npm test).",
        })
  }
  if (ctx.global) {
    const file = join(ctx.home, ".claude.json")
    mcp(ctx, "claude-code", ctx.display(file), json(file)?.mcpServers)
  }
  if (ctx.inProject) {
    const mcpFile = join(ctx.project, ".mcp.json")
    mcp(ctx, "claude-code", ctx.display(mcpFile), json(mcpFile)?.mcpServers)
    // Local-scope servers live in ~/.claude.json under the project path, so they count as project scope.
    const local = json(join(ctx.home, ".claude.json"))?.projects?.[ctx.project]
    mcp(ctx, "claude-code", "~/.claude.json (this project)", local?.mcpServers)
  }
}

function codexFile(ctx: Ctx, file: string) {
  const text = read(file)
  if (!text) return
  const where = ctx.display(file)
  const tables = sections(text)
  const seen = new Set<string>()
  for (const [table, kv] of tables) {
    // `[profiles.*]` is UNCONFIRMED in current Codex docs (they moved to separate profile files). Kept.
    if (table === "" || table.startsWith("profiles.")) {
      if (kv.approval_policy === "never")
        ctx.add({
          category: "agents",
          severity: "critical",
          title: `Codex never asks for approval${table ? ` (${table})` : ""}`,
          location: where,
          fix: 'Set approval_policy to "on-request".',
        })
      if (kv.sandbox_mode === "danger-full-access")
        ctx.add({
          category: "agents",
          severity: "critical",
          title: `Codex runs with no sandbox${table ? ` (${table})` : ""}`,
          location: where,
          fix: 'Set sandbox_mode to "workspace-write".',
        })
    }
    const name = /^mcp_servers\.([^.]+)/.exec(table)?.[1]
    if (name && !seen.has(name)) {
      seen.add(name)
      const t = tables.get(`mcp_servers.${name}`) ?? {}
      mcp(ctx, "codex", where, {
        [name]: { command: t.command, args: [t.args], url: t.url },
      })
    }
  }
}

// Cursor CLI permission files. Paths and the `Shell(*)` token are UNCONFIRMED in current docs.
function cursorCli(ctx: Ctx, file: string) {
  const allow = json(file)?.permissions?.allow
  if (!Array.isArray(allow)) return
  for (const rule of allow)
    if (
      typeof rule === "string" &&
      /^(Shell\(\*\)|Shell\(\*\*\)|Mcp\(\*:\*\))$/.test(rule)
    )
      ctx.add({
        category: "agents",
        severity: "high",
        title: `Cursor CLI allows everything (${rule})`,
        location: ctx.display(file),
        fix: "Replace it with specific allow rules.",
      })
}

function cursor(ctx: Ctx) {
  if (ctx.global) {
    const f = join(ctx.home, ".cursor/mcp.json")
    mcp(ctx, "cursor", ctx.display(f), json(f)?.mcpServers)
    cursorCli(ctx, join(ctx.home, ".cursor/cli-config.json"))
  }
  if (ctx.inProject) {
    const f = join(ctx.project, ".cursor/mcp.json")
    mcp(ctx, "cursor", ctx.display(f), json(f)?.mcpServers)
    cursorCli(ctx, join(ctx.project, ".cursor/cli.json"))
  }
}

export function checkAgents(ctx: Ctx) {
  if (ctx.agents.includes("claude-code")) claude(ctx)
  if (ctx.agents.includes("codex")) {
    if (ctx.global) codexFile(ctx, join(ctx.home, ".codex/config.toml"))
    if (ctx.inProject) codexFile(ctx, join(ctx.project, ".codex/config.toml"))
  }
  if (ctx.agents.includes("cursor")) cursor(ctx)
}
