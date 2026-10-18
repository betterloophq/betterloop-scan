import {
  closeSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  statSync,
} from "node:fs"
import { join } from "node:path"

const MAX_BYTES = 1_000_000
const MAX_DEPTH = 6
const SKIP = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "vendor",
  ".next",
  "coverage",
])

export function read(file: string): string | undefined {
  try {
    const s = statSync(file)
    if (!s.isFile() || s.size > MAX_BYTES) return undefined
    return readFileSync(file, "utf8")
  } catch {
    return undefined
  }
}

// Reads only the first `n` bytes. Used for private keys so we never hold more than the header.
export function readHead(file: string, n: number): string | undefined {
  try {
    const fd = openSync(file, "r")
    try {
      const buf = Buffer.alloc(n)
      return buf.subarray(0, readSync(fd, buf, 0, n, 0)).toString("latin1")
    } finally {
      closeSync(fd)
    }
  } catch {
    return undefined
  }
}

export function json(file: string): any {
  const text = read(file)
  if (!text) return undefined
  try {
    return JSON.parse(text.replace(/^﻿/, ""))
  } catch {
    return undefined
  }
}

export function list(dir: string): string[] {
  try {
    return readdirSync(dir)
  } catch {
    return []
  }
}

// Files under root: depth <= 6, no symlinks, skips vendored/build dirs.
// ponytail: 5s wall-clock cap instead of a smarter budget, revisit if huge monorepos truncate.
export function walk(root: string, budgetMs = 5000): string[] {
  const out: string[] = []
  const deadline = Date.now() + budgetMs
  const go = (dir: string, depth: number) => {
    if (depth > MAX_DEPTH || Date.now() > deadline) return
    let entries
    try {
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const e of entries) {
      const p = join(dir, e.name)
      if (e.isDirectory()) {
        if (!SKIP.has(e.name)) go(p, depth + 1)
      } else if (e.isFile()) out.push(p)
    }
  }
  go(root, 0)
  return out
}

// Tiny reader for INI and TOML section/key lines. Values are unquoted, comments dropped.
// ponytail: line-based, no multi-line arrays or inline tables. Use a real parser if we ever need values from those.
export function sections(text: string): Map<string, Record<string, string>> {
  const out = new Map<string, Record<string, string>>([["", {}]])
  let cur = ""
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line || line[0] === "#" || line[0] === ";") continue
    const head = /^\[+\s*(.+?)\s*\]+$/.exec(line)
    if (head) {
      cur = head[1].replace(/["']/g, "")
      if (!out.has(cur)) out.set(cur, {})
      continue
    }
    const kv = /^([A-Za-z0-9_.-]+)\s*=\s*(.*)$/.exec(line)
    if (kv)
      out.get(cur)![kv[1]] = kv[2]
        .replace(/\s+#.*$/, "")
        .trim()
        .replace(/^["']|["']$/g, "")
  }
  return out
}

// Splits on separators and camelCase, so org_acme_prod, acme-prd and OrgProd match.
// Glued forms (acmeprod, prdacme) match too, but not product, produce, prodigy or delivery.
// "live" only matches as its own word.
// ponytail: heuristic on names. A production profile named "main" is not caught, use --prod-accounts for AWS.
export function isProdName(s: string): boolean {
  const tokens = s
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean)
  return tokens.some(
    (t) =>
      /^(prod|prd|production|live)\d*$/.test(t) ||
      /^[a-z]+(prod|prd|production)\d*$/.test(t) ||
      (/^(prod|prd|production)[a-z]+/.test(t) && !/^prod(u[cs]|ig)/.test(t))
  )
}
