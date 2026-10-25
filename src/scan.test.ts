import { describe, it, expect, afterAll } from "vitest"
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join } from "node:path"
import { PassThrough, Readable, Writable } from "node:stream"
import { run } from "./cli.js"
import { scan } from "./scan.js"
import type { AgentId, Env, Finding, Scope } from "./types.js"
import { isProdName } from "./fsx.js"
import { CATEGORY_CAP, WEIGHTS, label, score } from "./weights.js"

// Synthetic secrets are built at runtime so no real-looking literal sits in the repo.
const AKIA = "AKIA" + "SYNTHETICEX12345"
const ASIA = "ASIA" + "SYNTHETICEX12345"
const GHP = "ghp_" + "SYNTHETICEXAMPLEONLY0123456789abcdefgh"
const STRIPE = "sk_" + "live_" + "SYNTHETICEXAMPLE0123456789"
const OPENAI = "sk-" + "SYNTHETICEXAMPLEONLY1234567890"
const DBPASS = "synthpw" + "9876"
const SECRETS = [AKIA, ASIA, GHP, STRIPE, OPENAI, DBPASS]

const roots: string[] = []
function sandbox() {
  const root = mkdtempSync(join(tmpdir(), "bl-scan-"))
  roots.push(root)
  const home = join(root, "home")
  const project = join(root, "project")
  mkdirSync(home)
  mkdirSync(project)
  const put = (base: string) => (rel: string, text: string) => {
    mkdirSync(dirname(join(base, rel)), { recursive: true })
    writeFileSync(join(base, rel), text)
  }
  return { home, project, inHome: put(home), inProject: put(project) }
}
afterAll(() =>
  roots.forEach((r) => rmSync(r, { recursive: true, force: true }))
)

function go(
  s: ReturnType<typeof sandbox>,
  scope: Scope,
  agents: AgentId[] = ["claude-code", "codex", "cursor"],
  env: Env = {}
) {
  return scan({
    agents,
    scope,
    path: s.project,
    home: s.home,
    env: { PATH: "", ...env },
  })
}
const has = (fs: Finding[], text: string) =>
  fs.some((f) => f.title.includes(text))

function sshHeader(cipher: string) {
  const raw = Buffer.concat([
    Buffer.from("openssh-key-v1\0"),
    Buffer.from([0, 0, 0, cipher.length]),
    Buffer.from(cipher),
    Buffer.alloc(40),
  ])
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${raw.toString("base64")}\n-----END OPENSSH PRIVATE KEY-----\n`
}

describe("database", () => {
  it("labels hosts and notes embedded passwords", () => {
    const s = sandbox()
    s.inProject(
      ".env",
      [
        `DATABASE_URL=postgres://u:${DBPASS}@db.prod.example.com/app`,
        `REPLICA_URL=mysql://u@db.example.com/app`,
        `LOCAL_URL=redis://localhost:6379`,
        `COMPOSE_URL=mongodb://u:x@mongo/app`,
        `PROD_DB_HOST=db.internal.example.com`,
      ].join("\n")
    )
    const f = go(s, "project").findings.filter((x) => x.category === "database")
    expect(
      f.find((x) => x.title.includes("production, password in URL"))?.severity
    ).toBe("critical")
    expect(f.find((x) => x.title.includes("(remote)"))?.severity).toBe("high")
    expect(
      f
        .filter((x) => x.title.includes("(local"))
        .every((x) => x.severity === "info")
    ).toBe(true)
    expect(
      f.find((x) => x.title.includes("host database credentials (production)"))
        ?.severity
    ).toBe("high")
  })
  it("reads environment variables only in global scope", () => {
    const s = sandbox()
    const env = { DATABASE_URL: "postgresql://u:p@db.example.com/x" }
    expect(has(go(s, "global", [], env).findings, "remote")).toBe(true)
    expect(has(go(s, "project", [], env).findings, "remote")).toBe(false)
  })
})

describe("agents", () => {
  it("flags Claude Code bypass mode, broad allow, and MCP servers", () => {
    const s = sandbox()
    s.inHome(
      ".claude/settings.json",
      JSON.stringify({
        permissions: {
          defaultMode: "bypassPermissions",
          allow: ["Bash(*)", "Read"],
        },
        skipDangerousModePermissionPrompt: true,
      })
    )
    s.inHome(
      ".claude.json",
      JSON.stringify({
        mcpServers: {
          pg: { command: "npx", args: ["postgres-mcp"] },
          notes: { command: "notes" },
        },
      })
    )
    s.inProject(
      ".mcp.json",
      JSON.stringify({ mcpServers: { aws: { command: "aws-mcp" } } })
    )
    const f = go(s, "both", ["claude-code"]).findings
    expect(f.find((x) => x.title.includes("bypassPermissions"))?.severity).toBe(
      "critical"
    )
    expect(has(f, "allows every shell command")).toBe(true)
    expect(has(f, "skips the bypass-mode warning")).toBe(true)
    expect(f.find((x) => x.title.includes('"pg"'))?.severity).toBe("high")
    expect(f.find((x) => x.title.includes('"notes"'))?.severity).toBe("low")
    expect(has(f, '"aws"')).toBe(true)
  })
  it("flags Codex settings and MCP tables", () => {
    const s = sandbox()
    s.inHome(
      ".codex/config.toml",
      'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n[mcp_servers.kube]\ncommand = "kubectl-mcp"\n[mcp_servers.kube.env]\nA = "b"\n'
    )
    const f = go(s, "global", ["codex"]).findings
    expect(has(f, "never asks for approval")).toBe(true)
    expect(has(f, "no sandbox")).toBe(true)
    expect(f.filter((x) => x.title.includes('"kube"'))).toHaveLength(1)
  })
  it("flags Cursor MCP servers and broad CLI allow rules", () => {
    const s = sandbox()
    s.inHome(
      ".cursor/mcp.json",
      JSON.stringify({ mcpServers: { fs: { command: "filesystem-mcp" } } })
    )
    s.inProject(
      ".cursor/cli.json",
      JSON.stringify({ permissions: { allow: ["Shell(*)"] } })
    )
    const f = go(s, "both", ["cursor"]).findings
    expect(has(f, '"fs"')).toBe(true)
    expect(has(f, "Cursor CLI allows everything")).toBe(true)
  })
})

describe("ssh", () => {
  it("reads passphrase state from the header and flags prod hosts", () => {
    const s = sandbox()
    s.inHome(".ssh/id_open", sshHeader("none"))
    s.inHome(".ssh/id_locked", sshHeader("aes256-ctr"))
    s.inHome(
      ".ssh/id_pem",
      "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n"
    )
    s.inHome(".ssh/id_open.pub", "ssh-ed25519 AAAA")
    s.inHome(
      ".ssh/config",
      "Host dev\n  HostName a\nHost prod-api\n  HostName b\nHost *\n"
    )
    s.inHome(".ssh/known_hosts", "a ssh-ed25519 X\nb ssh-ed25519 Y\n")
    const f = go(s, "global", []).findings.filter((x) => x.category === "ssh")
    expect(
      f.filter((x) => x.title.includes("without a passphrase"))
    ).toHaveLength(1)
    expect(
      f.filter((x) => x.title.includes("protected by a passphrase"))
    ).toHaveLength(2)
    expect(has(f, "2 SSH host entries")).toBe(true)
    expect(
      f.filter((x) => x.title.includes("production-looking host"))
    ).toHaveLength(1)
    expect(has(f, "2 known SSH servers")).toBe(true)
  })
})

describe("cloud", () => {
  it("covers global cloud files and tokens", () => {
    const s = sandbox()
    s.inHome(
      ".aws/credentials",
      `[prod]\naws_access_key_id = ${AKIA}\naws_secret_access_key = x\n[tmp]\naws_access_key_id = ${ASIA}\n`
    )
    s.inHome(".aws/config", "[profile sso-prod]\nsso_start_url = https://x\n")
    s.inHome(
      ".config/gcloud/application_default_credentials.json",
      JSON.stringify({ type: "authorized_user" })
    )
    s.inHome(
      ".azure/azureProfile.json",
      JSON.stringify({ subscriptions: [{}, {}] })
    )
    s.inHome(
      ".kube/config",
      "contexts:\n- context:\n    cluster: c\n  name: prod-eks\n- context:\n    cluster: d\n  name: dev\n"
    )
    s.inHome(".config/gh/hosts.yml", "github.com:\n  oauth_token: abc\n")
    s.inHome(
      ".docker/config.json",
      JSON.stringify({ auths: { "r.io": { auth: "x" }, "s.io": {} } })
    )
    s.inHome(".npmrc", "//registry.npmjs.org/:_authToken=abc\n")
    const f = go(s, "global", [], {
      GITHUB_TOKEN: "x",
      MY_API_KEY: "y",
      AWS_ACCESS_KEY_ID: AKIA,
    }).findings
    expect(f.filter((x) => x.severity === "critical")).toHaveLength(2)
    expect(has(f, 'AWS profile "prod" looks like production')).toBe(true)
    expect(has(f, 'AWS profile "sso-prod" looks like production')).toBe(true)
    expect(has(f, "AWS temporary access key")).toBe(true)
    expect(has(f, "Google Cloud default credentials")).toBe(true)
    expect(has(f, "Azure login (2 subscriptions")).toBe(true)
    expect(has(f, 'Kubernetes context "prod-eks"')).toBe(true)
    expect(has(f, 'Kubernetes context "dev"')).toBe(false)
    expect(has(f, "GitHub CLI token")).toBe(true)
    expect(has(f, "Docker registry logins stored on disk (1)")).toBe(true)
    expect(has(f, "npm auth token")).toBe(true)
    expect(
      f.filter((x) => x.title.startsWith("Secret set in environment"))
    ).toHaveLength(2)
  })
  it("finds project secrets and service-account files", () => {
    const s = sandbox()
    s.inProject(
      ".env.local",
      [`A=${AKIA}`, `B=${GHP}`, `C=${STRIPE}`, `D=${OPENAI}`].join("\n")
    )
    s.inProject("keys/sa.json", '{"type": "service_account"}')
    s.inProject("node_modules/x/.env", `A=${AKIA}`)
    const f = go(s, "project").findings.filter((x) => x.category === "cloud")
    expect(
      f.find((x) =>
        x.title.startsWith("AWS access key (AKIA…, 20 chars) in .env.local")
      )
    ).toBeTruthy()
    expect(has(f, "GitHub token (ghp_…")).toBe(true)
    expect(has(f, "Stripe live key (sk_live_…")).toBe(true)
    expect(has(f, "OpenAI API key (sk-…")).toBe(true)
    expect(has(f, "service-account")).toBe(true)
    expect(f.some((x) => x.location.includes("node_modules"))).toBe(false)
  })
})

describe("prod names", () => {
  it("matches separated, glued, camelCase and short forms", () => {
    for (const n of [
      "org_name_prod",
      "acme-prd",
      "OrgProd",
      "acmeprod",
      "ACMEPROD",
      "prd01",
      "production",
      "prodacme",
      "team.live",
      "acmeProd-eu",
    ])
      expect(isProdName(n), n).toBe(true)
  })
  it("ignores look-alikes", () => {
    for (const n of [
      "product",
      "produce",
      "prodigy",
      "delivery",
      "alive",
      "reproduce",
      "protocol",
      "dev",
      "staging",
      "main",
      "myproducts",
    ])
      expect(isProdName(n), n).toBe(false)
  })
})

describe("prod accounts", () => {
  const ACCT = "123456789" + "012"
  it("flags AWS profiles and kube configs that point at a listed account", () => {
    const s = sandbox()
    s.inHome(
      ".aws/config",
      `[profile main]
role_arn = arn:aws:iam::${ACCT}:role/admin
[profile sso-x]
sso_account_id = ${ACCT}
[profile other]
sso_account_id = 999999999999
`
    )
    s.inHome(
      ".kube/config",
      `contexts:\n- context:\n    cluster: arn:aws:eks:eu-west-1:${ACCT}:cluster/a\n  name: main\n`.replace(
        /\\n/g,
        "\n"
      )
    )
    const f = scan({
      agents: [],
      scope: "global",
      path: s.project,
      home: s.home,
      env: { PATH: "" },
      prodAccounts: [ACCT],
    }).findings
    expect(has(f, 'AWS profile "main" targets a production account')).toBe(true)
    expect(has(f, 'AWS profile "sso-x" targets a production account')).toBe(
      true
    )
    expect(has(f, 'AWS profile "other"')).toBe(false)
    expect(has(f, "Kubernetes config references a production account")).toBe(
      true
    )
    expect(f.map((x) => x.title).join()).not.toContain(ACCT)
  })
  it("rejects malformed account IDs", async () => {
    const c = capture()
    const code = await run(["--prod-accounts", "123"], {
      env: {},
      stdin: new Readable({ read() {} }),
      stdout: c.stdout,
      isTTY: false,
      platform: "linux",
      cwd: "/",
    })
    expect(code).toBe(2)
    expect(c.text()).toContain("12-digit")
  })
})

describe("score", () => {
  const mk = (
    category: Finding["category"],
    severity: Finding["severity"],
    n = 1
  ): Finding[] =>
    Array.from({ length: n }, () => ({
      category,
      severity,
      title: "",
      location: "",
      fix: "",
    }))
  it("subtracts per severity", () => {
    expect(score([])).toBe(100)
    expect(score(mk("agents", "critical"))).toBe(100 - WEIGHTS.critical)
    expect(score([...mk("agents", "high"), ...mk("ssh", "low")])).toBe(
      100 - WEIGHTS.high - WEIGHTS.low
    )
    expect(score(mk("ssh", "info", 50))).toBe(100)
  })
  it("caps each category and floors at 0", () => {
    expect(score(mk("cloud", "critical", 10))).toBe(100 - CATEGORY_CAP)
    const all = (["database", "agents", "ssh", "cloud"] as const).flatMap((c) =>
      mk(c, "critical", 5)
    )
    expect(score(all)).toBe(Math.max(0, 100 - 4 * CATEGORY_CAP))
  })
  it("labels ranges", () => {
    expect([100, 80, 79, 50, 49, 0].map(label)).toEqual([
      "Small",
      "Small",
      "Medium",
      "Medium",
      "Large",
      "Large",
    ])
  })
})

describe("selection", () => {
  function fixture() {
    const s = sandbox()
    s.inHome(".codex/config.toml", 'approval_policy = "never"')
    s.inHome(
      ".claude/settings.json",
      JSON.stringify({ permissions: { defaultMode: "bypassPermissions" } })
    )
    s.inHome(".aws/credentials", `[a]\naws_access_key_id = ${AKIA}\n`)
    s.inProject(
      ".claude/settings.json",
      JSON.stringify({ permissions: { allow: ["Bash"] } })
    )
    s.inProject(".env", "DATABASE_URL=postgres://u:p@db.example.com/x")
    return s
  }
  it("--agent codex checks only Codex settings", () => {
    const f = go(fixture(), "both", ["codex"]).findings
    expect(has(f, "Codex never asks")).toBe(true)
    expect(has(f, "Claude Code")).toBe(false)
    expect(has(f, "long-lived access key")).toBe(true)
  })
  it("--scope project reads nothing from home", () => {
    const f = go(fixture(), "project").findings
    expect(has(f, "allows every shell command")).toBe(true)
    expect(has(f, "remote")).toBe(true)
    expect(has(f, "Codex")).toBe(false)
    expect(has(f, "bypassPermissions")).toBe(false)
    expect(has(f, "AWS")).toBe(false)
  })
  it("--scope global reads nothing from the project", () => {
    const f = go(fixture(), "global").findings
    expect(has(f, "bypassPermissions")).toBe(true)
    expect(has(f, "long-lived access key")).toBe(true)
    expect(has(f, "allows every shell command")).toBe(false)
    expect(has(f, "remote")).toBe(false)
  })
})

// Answers are typed only after their prompt appears, as a person would.
function capture(answers: string[] = [], stdin = new PassThrough()) {
  let text = ""
  const stdout = new Writable({
    write(c, _e, cb) {
      text += c
      if (/(\[\d\]: |\[y\/N\] )$/.test(String(c)))
        setImmediate(() => stdin.write(answers.shift() + "\n"))
      cb()
    },
  })
  return { stdout, stdin, text: () => text }
}

describe("cli", () => {
  it("non-TTY run uses defaults and does not hang", async () => {
    const s = sandbox()
    s.inHome(".codex/config.toml", 'sandbox_mode = "danger-full-access"')
    const c = capture()
    const code = await run(["--home", s.home, "--path", s.project], {
      env: { PATH: "" },
      stdin: new Readable({ read() {} }),
      stdout: c.stdout,
      isTTY: false,
      platform: "linux",
      cwd: s.project,
    })
    expect(code).toBe(0)
    expect(c.text()).toContain(
      "Scope: global and project, agents: Claude Code, Codex, Cursor"
    )
    expect(c.text()).toContain("Top fixes")
  })
  it("asks both questions on a TTY", async () => {
    const s = sandbox()
    s.inHome(".codex/config.toml", 'approval_policy = "never"')
    const c = capture(["2", "3", "y"])
    const code = await run(["--home", s.home, "--path", s.project], {
      env: { PATH: "" },
      stdin: c.stdin,
      stdout: c.stdout,
      isTTY: true,
      platform: "linux",
      cwd: s.project,
    })
    expect(code).toBe(0)
    expect(c.text()).toContain("Which coding agent do you want to check?")
    expect(c.text()).toContain("Where should we check?")
    expect(c.text()).toContain("Scope: global and project, agents: Codex")
    expect(c.text()).toContain("Codex never asks for approval")
  })
  it("says so when an explicit agent is not installed", async () => {
    const s = sandbox()
    const c = capture()
    await run(
      ["--agent", "cursor", "--json", "--home", s.home, "--path", s.project],
      {
        env: { PATH: "" },
        stdin: new Readable({ read() {} }),
        stdout: c.stdout,
        isTTY: false,
        platform: "linux",
        cwd: s.project,
      }
    )
    const out = JSON.parse(c.text())
    expect(out.agents).toEqual([])
    expect(out.notes.join(" ")).toContain("Cursor is not installed")
  })
  it("calls onResult once with the result, after the report is printed", async () => {
    const s = sandbox()
    const c = capture()
    const seen: { score: number; printed: boolean }[] = []
    await run(
      ["--home", s.home, "--path", s.project],
      {
        env: { PATH: "" },
        stdin: new Readable({ read() {} }),
        stdout: c.stdout,
        isTTY: false,
        platform: "linux",
        cwd: s.project,
      },
      (r) =>
        void seen.push({
          score: r.score,
          printed: c.text().includes("Top fixes"),
        })
    )
    expect(seen).toEqual([{ score: 100, printed: true }])
  })
  it("does not call onResult when the run fails", async () => {
    const c = capture()
    let called = false
    const code = await run(
      ["--bogus"],
      {
        env: {},
        stdin: new Readable({ read() {} }),
        stdout: c.stdout,
        isTTY: false,
        platform: "linux",
        cwd: "/",
      },
      () => void (called = true)
    )
    expect(code).toBe(2)
    expect(called).toBe(false)
  })
  it("prints a notice on Windows", async () => {
    const c = capture()
    const code = await run([], {
      env: {},
      stdin: new Readable({ read() {} }),
      stdout: c.stdout,
      isTTY: false,
      platform: "win32",
      cwd: "/",
    })
    expect(code).toBe(0)
    expect(c.text()).toBe("Windows is not supported yet\n")
  })
  it("never prints a synthetic secret value, in terminal or JSON output", async () => {
    const s = sandbox()
    s.inHome(
      ".aws/credentials",
      `[default]\naws_access_key_id = ${AKIA}\n[t]\naws_access_key_id = ${ASIA}\n`
    )
    s.inProject(
      ".env",
      [
        `DATABASE_URL=postgres://u:${DBPASS}@db.example.com/x`,
        `G=${GHP}`,
        `S=${STRIPE}`,
        `O=${OPENAI}`,
      ].join("\n")
    )
    const env = { PATH: "", AWS_ACCESS_KEY_ID: AKIA, MY_TOKEN: GHP }
    for (const extra of [[], ["--json"], ["--details"]]) {
      const c = capture()
      await run(["--home", s.home, "--path", s.project, ...extra], {
        env,
        stdin: new Readable({ read() {} }),
        stdout: c.stdout,
        isTTY: false,
        platform: "linux",
        cwd: s.project,
      })
      expect(c.text().length).toBeGreaterThan(100)
      for (const secret of SECRETS) {
        expect(c.text()).not.toContain(secret)
        expect(c.text()).not.toContain(secret.slice(6))
      }
    }
  })
})

describe("static guarantees", () => {
  const files = (dir: string): string[] =>
    readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
      e.isDirectory()
        ? files(join(dir, e.name))
        : e.name.endsWith(".ts") && !e.name.endsWith(".test.ts")
          ? [join(dir, e.name)]
          : []
    )
  const sources = files(__dirname).map(
    (f) => [f, readFileSync(f, "utf8")] as const
  )
  it("imports no network modules and makes no fetch calls", () => {
    const banned =
      /(?:from|import\()\s*["'](?:node:)?(?:net|http|https|http2|tls|dgram|dns|dns\/promises|undici)["']|\bfetch\s*\(|XMLHttpRequest|WebSocket/
    for (const [file, text] of sources) expect(text, file).not.toMatch(banned)
  })
  it("never writes, moves or deletes files", () => {
    const banned =
      /\b(?:writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|rename|renameSync|mkdir|mkdirSync|copyFile)\s*\(/
    for (const [file, text] of sources) expect(text, file).not.toMatch(banned)
  })
})

describe("compact report", () => {
  function fixture() {
    const s = sandbox()
    s.inHome(
      ".aws/credentials",
      `[default]\naws_access_key_id = ${AKIA}\n[team-prod]\naws_access_key_id = ${AKIA}\n`
    )
    s.inHome(".aws/config", "[profile team-prod]\nregion = eu-west-1\n")
    for (const n of ["a", "b", "c", "d"])
      s.inHome(`.ssh/id_${n}`, sshHeader("none"))
    return s
  }
  async function cli(
    s: ReturnType<typeof sandbox>,
    opts: {
      tty?: boolean
      answers?: string[]
      env?: Env
      extra?: string[]
    } = {}
  ) {
    const c = capture(opts.answers ?? [])
    await run(
      [
        "--agent",
        "all",
        "--scope",
        "both",
        "--home",
        s.home,
        "--path",
        s.project,
        ...(opts.extra ?? []),
      ],
      {
        env: { PATH: "", ...opts.env },
        stdin: c.stdin,
        stdout: c.stdout,
        isTTY: opts.tty ?? false,
        platform: "linux",
        cwd: s.project,
      }
    )
    return c.text()
  }
  it("shows the score, one line per category and grouped fixes, and hides findings", async () => {
    const text = await cli(fixture())
    expect(text).toMatch(/\d+ \/ 100 {3}(SMALL|MEDIUM|LARGE) blast radius/)
    expect(text).toMatch(/SSH keys +4 high +-30 \(max\)/)
    expect(text).toMatch(/Database +✓ nothing found/)
    expect(text).toContain(
      "Replace static keys with AWS SSO and delete this key.  (2 findings)"
    )
    expect(text).toContain("findings hidden. Run with --details to see them.")
    expect(text).not.toContain("where:")
  })
  it("--details prints every finding without asking", async () => {
    const text = await cli(fixture(), { tty: true, extra: ["--details"] })
    expect(text).toContain("where: ~/.ssh/id_a")
    expect(text).not.toContain("Show them? [y/N]")
  })
  it("on a terminal, asks before showing findings", async () => {
    const shown = await cli(fixture(), { tty: true, answers: ["y"] })
    expect(shown).toContain("findings hidden. Show them? [y/N]")
    expect(shown).toContain("where: ~/.ssh/id_a")
    const hidden = await cli(fixture(), { tty: true, answers: [""] })
    expect(hidden).not.toContain("where:")
  })
  it("colors only on a terminal, and never with NO_COLOR", async () => {
    expect(await cli(fixture(), { tty: true, answers: [""] })).toContain(
      "\x1b["
    )
    expect(await cli(fixture())).not.toContain("\x1b[")
    expect(
      await cli(fixture(), { tty: true, answers: [""], env: { NO_COLOR: "1" } })
    ).not.toContain("\x1b[")
  })
  it("says nothing is hidden when there is nothing to show", async () => {
    const text = await cli(sandbox())
    expect(text).toContain("100 / 100")
    expect(text).toContain("None needed.")
    expect(text).not.toContain("hidden")
  })
})

describe("scoring fixes", () => {
  it("flags a production AWS profile once, even when it is in both files", () => {
    const s = sandbox()
    s.inHome(".aws/credentials", `[team-prod]\naws_access_key_id = ${ASIA}\n`)
    s.inHome(".aws/config", "[profile team-prod]\nregion = eu-west-1\n")
    const f = go(s, "global", []).findings
    expect(
      f.filter((x) => x.title.includes("looks like production"))
    ).toHaveLength(1)
  })
  it("ignores session tokens that IDEs inject into their terminals", () => {
    const s = sandbox()
    const f = go(s, "global", [], {
      VSCODE_GIT_IPC_AUTH_TOKEN: "x".repeat(64),
      GEMINI_CLI_IDE_AUTH_TOKEN: "y".repeat(36),
      MY_API_TOKEN: "z".repeat(20),
    }).findings
    expect(f.map((x) => x.location)).toEqual(["MY_API_TOKEN"])
  })
})
