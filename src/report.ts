import type { ScanResult } from "./scan.js"
import { AGENT_NAMES, type Category, type Severity } from "./types.js"
import { CATEGORY_CAP, WEIGHTS } from "./weights.js"

const CATEGORIES: [Category, string, string][] = [
  ["database", "1. Database credentials", "Database"],
  ["agents", "2. What the agents can run", "Agents"],
  ["ssh", "3. SSH keys", "SSH keys"],
  ["cloud", "4. Cloud credentials and secrets", "Cloud"],
]
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"]
const SCOPE_TEXT = {
  global: "global (home folder and environment variables)",
  project: "project only",
  both: "global and project",
}
const LABEL_COLOR = { Small: "32", Medium: "33", Large: "31" }

export const NOTE =
  "Agent choice only filters check 2. Checks 1, 3 and 4 cover anything any agent on this machine can reach."

export function summary(r: ScanResult): string {
  const names = r.agents.map((a) => AGENT_NAMES[a]).join(", ") || "none"
  return `Scope: ${SCOPE_TEXT[r.scope]}, agents: ${names}`
}

/** Findings that share a fix become one line, ordered by the points they cost together. */
export function fixGroups(r: ScanResult) {
  const groups = new Map<
    string,
    { fix: string; count: number; points: number }
  >()
  for (const f of r.findings) {
    if (f.severity === "info") continue
    const g = groups.get(f.fix) ?? { fix: f.fix, count: 0, points: 0 }
    g.count++
    g.points += WEIGHTS[f.severity]
    groups.set(f.fix, g)
  }
  return [...groups.values()].sort((a, b) => b.points - a.points)
}

export function topFixes(r: ScanResult): string[] {
  return fixGroups(r)
    .slice(0, 5)
    .map((g) => g.fix)
}

/** Score, one line per category and the top fixes. Findings stay hidden until asked for. */
export function compact(
  r: ScanResult,
  notes: string[],
  color: boolean
): string {
  const paint = (code: string, s: string) =>
    color ? `\x1b[${code}m${s}\x1b[0m` : s
  const filled = Math.round(r.score / 5)
  const out = ["Betterloop blast-radius scan", summary(r), NOTE, ...notes, ""]
  out.push(
    `   ${paint("1;" + LABEL_COLOR[r.label], `${r.score} / 100   ${r.label.toUpperCase()} blast radius`)}`,
    `   ${paint(LABEL_COLOR[r.label], "█".repeat(filled))}${"░".repeat(20 - filled)}`,
    "   The score covers only what was checked.",
    ""
  )
  for (const [cat, , name] of CATEGORIES) {
    const found = r.findings.filter(
      (f) => f.category === cat && f.severity !== "info"
    )
    if (!found.length) {
      out.push(`   ${name.padEnd(11)} ${paint("32", "✓")} nothing found`)
      continue
    }
    const counts = SEVERITIES.map(
      (s) => [s, found.filter((f) => f.severity === s).length] as const
    )
      .filter(([, n]) => n)
      .map(([s, n]) => `${n} ${s}`)
      .join(" · ")
    const lost = found.reduce((sum, f) => sum + WEIGHTS[f.severity], 0)
    const points = lost > CATEGORY_CAP ? `-${CATEGORY_CAP} (max)` : `-${lost}`
    out.push(`   ${name.padEnd(11)} ${counts.padEnd(34)} ${points}`)
  }
  out.push("", "Top fixes")
  const fixes = fixGroups(r).slice(0, 5)
  if (!fixes.length) out.push("   None needed.")
  fixes.forEach((g, i) =>
    out.push(
      `   ${i + 1}. ${g.fix}${g.count > 1 ? `  (${g.count} findings)` : ""}`
    )
  )
  return out.join("\n") + "\n"
}

/** Every finding, grouped by category. Shown with --details or on request. */
export function details(r: ScanResult): string {
  const out = [""]
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
  return out.join("\n")
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
