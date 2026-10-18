import { spawnSync } from "node:child_process"
import { join } from "node:path"
import { isProdName, list, read, readHead } from "../fsx.js"
import type { Ctx } from "../types.js"

const HEADER = /-----BEGIN ([A-Z ]*)PRIVATE KEY-----/

// true = protected by a passphrase. Reads the header only, never the key body beyond the cipher name.
function hasPassphrase(head: string): boolean | undefined {
  const m = HEADER.exec(head)
  if (!m) return undefined
  if (m[1] === "OPENSSH ") {
    const body = head
      .slice(m.index + m[0].length)
      .replace(/[^A-Za-z0-9+/=]/g, "")
    const raw = Buffer.from(body.slice(0, 96), "base64")
    // magic "openssh-key-v1\0", then a length-prefixed cipher name
    const len = raw.readUInt32BE(15)
    return raw.subarray(19, 19 + len).toString("latin1") !== "none"
  }
  if (m[1] === "ENCRYPTED ") return true
  return head.includes("ENCRYPTED")
}

export function checkSsh(ctx: Ctx) {
  if (!ctx.global) return
  const dir = join(ctx.home, ".ssh")
  for (const name of list(dir).filter(
    (n) => !/\.pub$|^(known_hosts|config|authorized_keys)/.test(n)
  )) {
    const file = join(dir, name)
    const head = readHead(file, 600)
    const protectedKey = head === undefined ? undefined : safe(head)
    if (protectedKey === undefined) continue
    ctx.add({
      category: "ssh",
      severity: protectedKey ? "info" : "high",
      title: `SSH private key ${protectedKey ? "protected by a passphrase" : "without a passphrase"}`,
      location: ctx.display(file),
      fix: protectedKey
        ? "Nothing needed."
        : "Add a passphrase with: ssh-keygen -p -f <key>",
    })
  }

  // Keys loaded in ssh-agent. Skipped silently when there is no agent.
  if (ctx.env.SSH_AUTH_SOCK) {
    const r = spawnSync("ssh-add", ["-l"], {
      env: ctx.env,
      encoding: "utf8",
      timeout: 3000,
    })
    if (r.status === 0)
      for (const _ of r.stdout.split("\n").filter(Boolean))
        ctx.add({
          category: "ssh",
          severity: "low",
          title: "SSH key loaded in ssh-agent (usable without a passphrase)",
          location: "ssh-agent",
          fix: "Unload keys you are not using with: ssh-add -D",
        })
  }

  const config = read(join(dir, "config"))
  if (config) {
    const hosts = [...config.matchAll(/^\s*Host\s+(.+)$/gim)]
      .flatMap((m) => m[1].trim().split(/\s+/))
      .filter((h) => !/[*?!]/.test(h))
    ctx.add({
      category: "ssh",
      severity: "info",
      title: `${hosts.length} SSH host entries`,
      location: ctx.display(join(dir, "config")),
      fix: "Nothing needed.",
    })
    for (const h of hosts.filter(isProdName))
      ctx.add({
        category: "ssh",
        severity: "high",
        title: "SSH config has a production-looking host",
        location: ctx.display(join(dir, "config")),
        fix: "Keep production access off machines that run AI agents. Use a jump host with approval.",
      })
  }
  const known = read(join(dir, "known_hosts"))
  if (known)
    ctx.add({
      category: "ssh",
      severity: "info",
      title: `${known.split("\n").filter(Boolean).length} known SSH servers`,
      location: ctx.display(join(dir, "known_hosts")),
      fix: "Nothing needed.",
    })
}

function safe(head: string): boolean | undefined {
  try {
    return hasPassphrase(head)
  } catch {
    return undefined
  }
}
