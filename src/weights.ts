import type { Category, Finding, Severity } from "./types.js"

// The one place where scoring is tuned.
export const WEIGHTS: Record<Severity, number> = {
  critical: 20,
  high: 10,
  medium: 5,
  low: 2,
  info: 0,
}
export const CATEGORY_CAP = 30

export function score(findings: Finding[]): number {
  const lost: Partial<Record<Category, number>> = {}
  for (const f of findings)
    lost[f.category] = (lost[f.category] ?? 0) + WEIGHTS[f.severity]
  const total = Object.values(lost).reduce(
    (sum, n) => sum + Math.min(n, CATEGORY_CAP),
    0
  )
  return Math.max(0, 100 - total)
}

export function label(s: number): "Small" | "Medium" | "Large" {
  return s >= 80 ? "Small" : s >= 50 ? "Medium" : "Large"
}
