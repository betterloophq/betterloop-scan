import { join } from "node:path"
import { isProdName, json, list, read, sections } from "../fsx.js"
import { SECRET_PATTERNS, mask } from "../patterns.js"
import type { Ctx } from "../types.js"

const ROTATE = "Move it to a secret manager and rotate it."

function aws(ctx: Ctx) {
  // A profile usually appears in both files. Flag a production profile once.
  const prodProfiles = new Set<string>()
  const credFile = join(ctx.home, ".aws/credentials")
  const creds = read(credFile)
  if (creds)
    for (const [profile, kv] of sections(creds)) {
      const id = kv.aws_access_key_id
      if (!id) continue
      ctx.reach({
        kind: "aws_profile",
        name: profile,
        location: ctx.display(credFile),
      })
      const longLived = id.startsWith("AKIA")
      ctx.add({
        category: "cloud",
        severity: longLived ? "critical" : "medium",
        title: `AWS ${longLived ? "long-lived" : "temporary"} access key (${id.slice(0, 4)}…, ${id.length} chars) in profile ${profile}`,
        location: ctx.display(credFile),
        fix: longLived
          ? "Replace static keys with AWS SSO and delete this key."
          : "Prefer SSO. Temporary keys expire, but still let agents act as you.",
      })
      if (isProdName(profile) && !prodProfiles.has(profile)) {
        prodProfiles.add(profile)
        ctx.add({
          category: "cloud",
          severity: "high",
          title: `AWS profile "${profile}" looks like production`,
          location: ctx.display(credFile),
          fix: "Keep production access off machines that run AI agents.",
        })
      }
    }
  const confFile = join(ctx.home, ".aws/config")
  const conf = read(confFile)
  if (conf)
    for (const [section, kv] of sections(conf)) {
      if (!section) continue
      const name = section.replace(/^profile\s+/, "")
      // arn:aws:iam::<account>:role/<name>
      const arn = /^arn:aws[\w-]*:iam::(\d{12}):role\/(.+)$/.exec(
        kv.role_arn ?? ""
      )
      ctx.reach({
        kind: "aws_profile",
        name,
        account: kv.sso_account_id ?? arn?.[1],
        role: kv.sso_role_name ?? arn?.[2],
        location: ctx.display(confFile),
      })
      if (Object.keys(kv).some((k) => k.startsWith("sso_") || k === "role_arn"))
        ctx.add({
          category: "cloud",
          severity: "medium",
          title: `AWS SSO or role profile "${name}"`,
          location: ctx.display(confFile),
          fix: "Log out of SSO when not working: aws sso logout.",
        })
      const onProdAccount = ctx.prodAccounts.some((id) =>
        [kv.sso_account_id, kv.role_arn].some((v) => v?.includes(id))
      )
      if ((isProdName(name) || onProdAccount) && !prodProfiles.has(name)) {
        prodProfiles.add(name)
        ctx.add({
          category: "cloud",
          severity: "high",
          title: onProdAccount
            ? `AWS profile "${name}" targets a production account from your list`
            : `AWS profile "${name}" looks like production`,
          location: ctx.display(confFile),
          fix: "Keep production access off machines that run AI agents.",
        })
      }
    }
  const id = ctx.env.AWS_ACCESS_KEY_ID
  if (id) {
    ctx.reach({
      kind: "aws_env_key",
      name: "AWS_ACCESS_KEY_ID",
      location: "AWS_ACCESS_KEY_ID",
    })
    const longLived = id.startsWith("AKIA")
    ctx.add({
      category: "cloud",
      severity: longLived ? "critical" : "medium",
      title: `AWS access key in environment (${id.slice(0, 4)}…, ${id.length} chars)`,
      location: "AWS_ACCESS_KEY_ID",
      fix: "Unset it and use AWS SSO.",
    })
  }
}

function gcloud(ctx: Ctx) {
  const dir = join(ctx.home, ".config/gcloud")
  const adc = join(dir, "application_default_credentials.json")
  const a = json(adc)
  if (a)
    ctx.add({
      category: "cloud",
      severity: a.type === "service_account" ? "high" : "medium",
      title: `Google Cloud default credentials (${a.type ?? "unknown type"})`,
      location: ctx.display(adc),
      fix: "Run: gcloud auth application-default revoke",
    })
  for (const n of list(join(dir, "configurations"))) {
    const file = join(dir, "configurations", n)
    const text = read(file)
    if (!text) continue
    const project = [...sections(text).values()]
      .map((kv) => kv.project)
      .find(Boolean)
    if (project)
      ctx.reach({
        kind: "gcp_project",
        name: project,
        location: ctx.display(file),
      })
    if (project && isProdName(project))
      ctx.add({
        category: "cloud",
        severity: "high",
        title: "gcloud configuration points at a production-looking project",
        location: ctx.display(file),
        fix: "Keep production access off machines that run AI agents.",
      })
  }
  const keyPath = ctx.env.GOOGLE_APPLICATION_CREDENTIALS
  if (keyPath)
    ctx.add({
      category: "cloud",
      severity: json(keyPath)?.type === "service_account" ? "high" : "medium",
      title: "GOOGLE_APPLICATION_CREDENTIALS is set",
      location: "GOOGLE_APPLICATION_CREDENTIALS",
      fix: "Unset it. Use short-lived credentials instead of key files.",
    })
}

function azure(ctx: Ctx) {
  const dir = join(ctx.home, ".azure")
  const profile = json(join(dir, "azureProfile.json"))
  const cache = ["msal_token_cache.json", "accessTokens.json"].find((n) =>
    read(join(dir, n))
  )
  if (!profile && !cache) return
  for (const s of Array.isArray(profile?.subscriptions)
    ? profile.subscriptions
    : [])
    if (typeof s?.id === "string")
      ctx.reach({
        kind: "azure_subscription",
        name: typeof s.name === "string" ? s.name : s.id,
        account: s.id,
        location: ctx.display(join(dir, "azureProfile.json")),
      })
  const subs = Array.isArray(profile?.subscriptions)
    ? profile.subscriptions.length
    : 0
  ctx.add({
    category: "cloud",
    severity: "medium",
    title: `Azure login (${subs} subscriptions${cache ? ", token cache present" : ""})`,
    location: ctx.display(join(dir, profile ? "azureProfile.json" : cache!)),
    fix: "Run: az logout",
  })
}

function kube(ctx: Ctx) {
  const file = join(ctx.home, ".kube/config")
  const text = read(file)
  if (!text) return
  // ponytail: line-based. Each "- " item under contexts: is one context.
  const items: { name?: string; cluster?: string; user?: string }[] = []
  let inContexts = false
  for (const line of text.split(/\r?\n/)) {
    if (/^[A-Za-z]/.test(line)) inContexts = line.startsWith("contexts:")
    else if (inContexts) {
      if (/^\s*-\s/.test(line)) items.push({})
      const m = /^\s*(?:-\s+)?(name|cluster|user):\s*["']?([^"'\s#]+)/.exec(
        line
      )
      if (m && items.length) items[items.length - 1][m[1] as "name"] = m[2]
    }
  }
  const names = items.map((i) => i.name).filter((n): n is string => !!n)
  for (const i of items)
    if (i.name)
      ctx.reach({
        kind: "kube_context",
        name: i.name,
        host: i.cluster,
        role: i.user,
        location: ctx.display(file),
      })
  // EKS contexts and clusters carry the account ID inside their ARN.
  if (ctx.prodAccounts.some((id) => text.includes(id)))
    ctx.add({
      category: "cloud",
      severity: "high",
      title: "Kubernetes config references a production account from your list",
      location: ctx.display(file),
      fix: "Remove it from machines that run AI agents.",
    })
  if (!names.length) return
  ctx.add({
    category: "cloud",
    severity: "medium",
    title: `Kubernetes config with ${names.length} contexts`,
    location: ctx.display(file),
    fix: "Delete contexts you do not need: kubectl config delete-context <name>",
  })
  for (const n of names.filter(isProdName))
    ctx.add({
      category: "cloud",
      severity: "high",
      title: `Kubernetes context "${n}" looks like production`,
      location: ctx.display(file),
      fix: "Remove it from machines that run AI agents.",
    })
}

function tokens(ctx: Ctx) {
  const gh = join(ctx.home, ".config/gh/hosts.yml")
  if (/oauth_token:\s*\S/.test(read(gh) ?? ""))
    ctx.add({
      category: "cloud",
      severity: "medium",
      title: "GitHub CLI token stored on disk",
      location: ctx.display(gh),
      fix: "Run: gh auth logout, then log in with a token limited to what you need.",
    })
  const docker = join(ctx.home, ".docker/config.json")
  const auths = json(docker)?.auths
  const n = auths ? Object.values<any>(auths).filter((a) => a?.auth).length : 0
  if (n)
    ctx.add({
      category: "cloud",
      severity: "medium",
      title: `Docker registry logins stored on disk (${n})`,
      location: ctx.display(docker),
      fix: "Run: docker logout, and use a credential helper.",
    })
  const npmrc = join(ctx.home, ".npmrc")
  if (/_authToken\s*=\s*[^\s$]/.test(read(npmrc) ?? ""))
    ctx.add({
      category: "cloud",
      severity: "medium",
      title: "npm auth token stored in .npmrc",
      location: ctx.display(npmrc),
      fix: "Use a read-only, short-lived npm token, or an environment reference.",
    })
  for (const [k, v] of Object.entries(ctx.env))
    if (
      v &&
      k !== "AWS_ACCESS_KEY_ID" &&
      /(_TOKEN|_SECRET|_KEY|_PASSWORD)$|^GITHUB_TOKEN$/.test(k) &&
      !/PUBLIC|PUBLISHABLE/.test(k) &&
      // Short-lived tokens IDEs inject into their own terminals, not stored secrets.
      !/^VSCODE_|_IDE_AUTH_TOKEN$/.test(k)
    )
      ctx.add({
        category: "cloud",
        severity: "medium",
        title: `Secret set in environment (${v.length} chars)`,
        location: k,
        fix: "Unset it in your shell profile. Pass it only to the command that needs it.",
      })
}

export function checkCloud(ctx: Ctx, projectFiles: string[]) {
  if (ctx.global) {
    aws(ctx)
    gcloud(ctx)
    azure(ctx)
    kube(ctx)
    tokens(ctx)
  }
  if (!ctx.inProject) return
  for (const file of projectFiles) {
    const base = file.split("/").pop()!
    const isEnv = /^\.env/.test(base)
    if (!isEnv && !/\.(json|ya?ml|toml|ini|cfg|conf|properties)$/.test(base))
      continue
    if (/lock/i.test(base)) continue
    const text = read(file)
    if (!text) continue
    const where = ctx.display(file)
    if (base.endsWith(".json") && /"type"\s*:\s*"service_account"/.test(text))
      ctx.add({
        category: "cloud",
        severity: "high",
        title: "Google Cloud service-account key file",
        location: where,
        fix: "Delete the key file. Use short-lived credentials instead.",
      })
    for (const p of SECRET_PATTERNS)
      for (const m of text.matchAll(p.re))
        ctx.add({
          category: "cloud",
          severity: p.severity,
          title: `${mask(p, m[0])} in ${where}`,
          location: where,
          fix: ROTATE,
        })
  }
}
