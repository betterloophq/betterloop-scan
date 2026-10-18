import type { ScanResult } from "./scan.js"
import { AGENT_NAMES, type Category } from "./types.js"
import { WEIGHTS } from "./weights.js"

const CATEGORIES: [Category, string][] = [
  ["database", "1. Database credentials"],
  ["agents", "2. What the agents can run"],
  ["ssh", "3. SSH keys"],
  ["cloud", "4. Cloud credentials and secrets"],
]
const SCOPE_TEXT = {
  global: "global (home folder and environment variables)",
  project: "project only",
  both: "global and project",
}

export const NOTE =
  "Agent choice only filters check 2. Checks 1, 3 and 4 cover anything any agent on this machine can reach."

export function summary(r: ScanResult): string {
  const names = r.agents.map((a) => AGENT_NAMES[a]).join(", ") || "none"
  return `Scope: ${SCOPE_TEXT[r.scope]}, agents: ${names}`
}

export function topFixes(r: ScanResult): string[] {
  const seen = new Set<string>()
  return r.findings
    .filter((f) => f.severity !== "info")
    .sort((a, b) => WEIGHTS[b.severity] - WEIGHTS[a.severity])
    .map((f) => f.fix)
    .filter((fix) => !seen.has(fix) && seen.add(fix))
    .slice(0, 5)
}

export function terminal(r: ScanResult, notes: string[]): string {
  const out = ["Betterloop blast-radius scan", summary(r), NOTE, ...notes, ""]
  out.push(`Score: ${r.score}/100 (${r.label} blast radius)`)
  out.push("The score covers only what was checked.", "")
  for (const [cat, title] of CATEGORIES) {
    out.push(title)
    const found = r.findings.filter((f) => f.category === cat)
    if (!found.length) out.push("  Nothing found.")
    for (const f of found)
      out.push(
        `  [${f.severity.toUpperCase()}] ${f.title}`,
        `    where: ${f.location}`,
        ...(f.severity === "info" ? [] : [`    fix: ${f.fix}`])
      )
    out.push("")
  }
  out.push("Top 5 fixes")
  const fixes = topFixes(r)
  if (!fixes.length) out.push("  None needed.")
  fixes.forEach((fix, i) => out.push(`  ${i + 1}. ${fix}`))
  return out.join("\n") + "\n"
}

export function jsonReport(r: ScanResult, notes: string[]): string {
  return (
    JSON.stringify(
      {
        scope: r.scope,
        agents: r.agents,
        summary: summary(r),
        notes: [NOTE, ...notes],
        score: r.score,
        label: r.label,
        findings: r.findings,
        topFixes: topFixes(r),
      },
      null,
      2
    ) + "\n"
  )
}
