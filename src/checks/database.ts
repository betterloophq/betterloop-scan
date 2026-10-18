import { isProdName, read } from "../fsx.js"
import type { Ctx } from "../types.js"

const URL_RE =
  /\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?):\/\/([^\s'"`<>]+)/g
const HOST_KEY =
  /(?:^|_)(?:DB|DATABASE|POSTGRES|PG|MYSQL|MONGO|MONGODB|REDIS)_?HOST(?:NAME)?$/

function parseUrl(rest: string) {
  const authority = rest.split(/[/?#]/, 1)[0]
  const at = authority.lastIndexOf("@")
  const userinfo = at >= 0 ? authority.slice(0, at) : ""
  const first = authority.slice(at + 1).split(",")[0]
  const host = first.startsWith("[")
    ? first.slice(1, first.indexOf("]"))
    : first.replace(/:\d+$/, "")
  const colon = userinfo.indexOf(":")
  return { host, password: colon >= 0 && colon < userinfo.length - 1 }
}

type Kind = "local" | "production" | "remote"
function classify(host: string, key: string): Kind {
  if (["localhost", "127.0.0.1", "::1"].includes(host.toLowerCase()))
    return "local"
  if (isProdName(host) || isProdName(key)) return "production"
  return host.includes(".") ? "remote" : "local"
}

function report(
  ctx: Ctx,
  where: string,
  key: string,
  scheme: string,
  host: string,
  password: boolean
) {
  if (!host || /[${}]/.test(host)) return
  const kind = classify(host, key)
  const pw = password ? ", password in URL" : ""
  const severity =
    kind === "production"
      ? password
        ? "critical"
        : "high"
      : kind === "remote"
        ? "high"
        : "info"
  ctx.add({
    category: "database",
    severity,
    title: `${scheme} database credentials (${kind}${pw}) in ${key}`,
    location: where,
    fix:
      kind === "local"
        ? "Nothing needed for a local database."
        : "Remove this from the machine. Give agents a read-only, non-production database user.",
  })
}

function scanText(ctx: Ctx, where: string, key: string, value: string) {
  if (HOST_KEY.test(key) && value && !value.includes("://"))
    report(ctx, where, key, "host", value, false)
  for (const m of value.matchAll(URL_RE)) {
    const { host, password } = parseUrl(m[2])
    report(ctx, where, key, m[1], host, password)
  }
}

export function checkDatabase(ctx: Ctx, projectFiles: string[]) {
  if (ctx.global)
    for (const [key, value] of Object.entries(ctx.env))
      if (value) scanText(ctx, "environment variable", key, value)
  if (!ctx.inProject) return
  for (const file of projectFiles) {
    if (!/^\.env/.test(file.split("/").pop()!)) continue
    const text = read(file)
    if (!text) continue
    for (const line of text.split(/\r?\n/)) {
      const kv = /^\s*(?:export\s+)?([A-Za-z0-9_.-]+)\s*=\s*(.*)$/.exec(line)
      if (kv)
        scanText(
          ctx,
          ctx.display(file),
          kv[1],
          kv[2].trim().replace(/^["']|["']$/g, "")
        )
    }
  }
}
