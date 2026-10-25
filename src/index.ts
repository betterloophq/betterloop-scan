// Library entry. Importing it has no side effects, unlike main.ts which runs the CLI.
export { run } from "./cli.js"
export type { Io } from "./cli.js"
export { scan } from "./scan.js"
export type { ScanOptions, ScanResult } from "./scan.js"
export { detectAgents } from "./checks/agents.js"
export type {
  AgentId,
  Category,
  Finding,
  Reach,
  Scope,
  Severity,
} from "./types.js"
