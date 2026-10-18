import type { Severity } from "./types.js"

export interface SecretPattern {
  name: string
  re: RegExp
  // Length of the literal prefix that is safe to print.
  prefix: number
  severity: Severity
}

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: "AWS access key",
    re: /\bAKIA[0-9A-Z]{16}\b/g,
    prefix: 4,
    severity: "critical",
  },
  {
    name: "AWS temporary key",
    re: /\bASIA[0-9A-Z]{16}\b/g,
    prefix: 4,
    severity: "medium",
  },
  {
    name: "GitHub token",
    re: /\bgh[po]_[A-Za-z0-9]{36,}\b/g,
    prefix: 4,
    severity: "medium",
  },
  {
    name: "GitHub token",
    re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
    prefix: 11,
    severity: "medium",
  },
  {
    name: "Slack token",
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g,
    prefix: 3,
    severity: "medium",
  },
  {
    name: "Stripe live key",
    re: /\bsk_live_[A-Za-z0-9]{16,}/g,
    prefix: 8,
    severity: "critical",
  },
  {
    name: "Anthropic API key",
    re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g,
    prefix: 7,
    severity: "medium",
  },
  {
    name: "OpenAI API key",
    re: /\bsk-(?!ant-)[A-Za-z0-9_-]{20,}/g,
    prefix: 3,
    severity: "medium",
  },
  {
    name: "Google API key",
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    prefix: 4,
    severity: "medium",
  },
  {
    name: "Private key block",
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
    prefix: 0,
    severity: "medium",
  },
  {
    name: "JWT",
    re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
    prefix: 3,
    severity: "medium",
  },
]

// Type, known prefix and length only. Never the value.
export function mask(p: SecretPattern, matched: string): string {
  return p.prefix
    ? `${p.name} (${matched.slice(0, p.prefix)}…, ${matched.length} chars)`
    : `${p.name} (key block)`
}
