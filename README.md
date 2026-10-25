# betterloop-scan

See how much damage the AI coding agents on your machine could do.

```sh
npx betterloop-scan
```

Claude Code, Codex and Cursor run commands as you. Whatever you can reach, they can reach: production databases, cloud accounts, servers over SSH, live API keys. `betterloop-scan` looks for those on your machine and gives you a **blast radius score** (0 to 100, higher is safer), a list of findings, and a fix for each.

- **Read-only.** It never writes, moves or deletes a file.
- **Offline.** No network calls and no telemetry. Nothing leaves your machine.
- **Secrets stay hidden.** Findings show the type, the location and the length, for example `AWS access key (AKIA…, 20 chars) in .env.local`. Values are never printed.
- **No dependencies.** Node standard library only.
- **Fast.** Usually about a second.

Requires Node.js 22 or newer on macOS or Linux. On Windows it prints "Windows is not supported yet" and exits.

## Usage

Run it in a terminal and it asks two questions:

1. **Which coding agent do you want to check?** Claude Code, Codex, Cursor, or all detected. You can pick more than one.
2. **Where should we check?** Global (your home folder and environment variables), project (the current folder), or both.

The report opens with the score, one line per category and the top fixes. In a terminal it then asks whether to show every finding. `--details` prints them straight away.

Flags skip the questions. If input is not a terminal, nothing is asked and the defaults (all agents, both scopes) are used.

```sh
npx betterloop-scan --agent claude-code --scope project
npx betterloop-scan --agent codex,cursor --path ~/code/my-app
npx betterloop-scan --prod-accounts 111122223333,444455556666
npx betterloop-scan --json
```

| Flag                    | Meaning                                                                                         |
| ----------------------- | ----------------------------------------------------------------------------------------------- |
| `--agent <list>`        | `claude-code`, `codex`, `cursor` or `all`. Comma-separated.                                     |
| `--scope <scope>`       | `global`, `project` or `both` (default).                                                        |
| `--path <dir>`          | Project folder. Defaults to the current folder.                                                 |
| `--prod-accounts <ids>` | 12-digit AWS account IDs to treat as production. Comma-separated.                               |
| `--details`             | Print every finding. Otherwise only the score, a line per category and the top fixes are shown. |
| `--json`                | Machine-readable output. Never asks questions.                                                  |
| `--home <dir>`          | Use another folder as the home folder. Mostly for tests.                                        |

The exit code is `0` on success, even when findings exist. Bad flags exit with `2`.

## Use as a library

```ts
import { scan } from "betterloop-scan"

const result = scan({
  agents: ["claude-code"],
  scope: "project",
  path: process.cwd(),
  home: os.homedir(),
  env: process.env,
})
console.log(result.score, result.label)
```

`scan` is synchronous and read-only. Findings carry masked text only, never secret values.

`run(argv, io, onResult)` runs the full CLI (flags, questions, report) and calls `onResult` with the result after printing.

## What it checks

The agent choice only filters check 2. Checks 1, 3 and 4 always run, because any agent on the machine can reach what they cover.

| #   | Check                                | What it looks for                                                                                                                                                                                                          |
| --- | ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Database credentials                 | Connection strings and `DB_HOST`-style keys (Postgres, MySQL, MongoDB, Redis) in `.env*` files and environment variables. Each host is labeled local, production-looking or remote, with a note if a password is embedded. |
| 2   | What the agents can run              | Agents with no permission prompts, broad allow rules like `Bash(*)`, and MCP servers with database, cloud, shell or filesystem access. Reads each agent's own settings.                                                    |
| 3   | SSH keys                             | Private keys with no passphrase, keys loaded in ssh-agent, production-looking hosts in `~/.ssh/config`. Only the key header is read.                                                                                       |
| 4   | Cloud credentials and secret strings | AWS, Google Cloud, Azure, Kubernetes, GitHub CLI, Docker and npm credentials on disk. Secret-looking environment variable names. In project files: service-account keys and known secret formats.                          |

**Global** scope covers your home folder (`~/.ssh`, `~/.aws`, `~/.kube`, `~/.config/gcloud`, `~/.azure`, `~/.claude`, `~/.codex`, `~/.cursor`, `~/.claude.json`, `~/.npmrc`, `~/.docker`, `~/.config/gh`) and environment variables. **Project** scope covers files in the project folder, up to 6 folders deep, skipping `node_modules`, `.git`, `dist`, `build`, `vendor`, `.next` and `coverage`.

## How "production" is decided

It is a guess from names. A profile, context, host or key counts as production when its name contains `prod`, `prd`, `production` or `live` as its own word or part of a name. That covers `org_acme_prod`, `acme-prd`, `OrgProd` and `acmeprod`. It does not match `product`, `produce` or `delivery`.

A profile named `main` that points at a production AWS account looks safe by name. Pass `--prod-accounts` and any AWS profile or Kubernetes config that targets those accounts is flagged too.

## Scoring

The score starts at 100 and drops for each finding.

| Severity | Points lost | Examples                                                                                                                                                                         |
| -------- | ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Critical | 20          | Agent runs with no permission prompts. Production database URL with a password. Long-lived AWS key. Live payment or cloud secret in a project file.                              |
| High     | 10          | Remote database credentials. Production-named kube context or AWS profile. SSH key with no passphrase. Service-account key file. `Bash(*)`. Database, cloud or shell MCP server. |
| Medium   | 5           | SSO or role cloud profiles. GitHub CLI, Docker or npm tokens. Other secrets in `.env` files.                                                                                     |
| Low      | 2           | Keys loaded in ssh-agent. Other MCP servers.                                                                                                                                     |

Each category loses at most 30 points, so one category cannot zero the score. The floor is 0.

| Score    | Blast radius |
| -------- | ------------ |
| 80 - 100 | Small        |
| 50 - 79  | Medium       |
| 0 - 49   | Large        |

The score covers only what was checked. A project-only scan of one agent says nothing about the rest of your machine, and the report header states what was covered.

## What it does not do

- It never connects to anything, so it cannot tell whether a credential still works or what rights it has.
- It reports what an agent could reach, not what has leaked.
- Names it does not recognize are missed: oddly named variables, renamed MCP servers, secret formats not in its list.
- It does not fix anything.

## Betterloop

`betterloop-scan` is a free tool from [Betterloop](https://betterloop.dev).

Betterloop is the platform for running AI coding agents across a team. Administrators publish signed rules for Claude Code, Codex and Cursor, review changes before they ship, and roll them out to every developer. The scan shows the risk on one machine. Betterloop is how a team controls it everywhere.

Learn more at [betterloop.dev](https://betterloop.dev).

## License

[MIT](LICENSE). This package is open source on its own.
