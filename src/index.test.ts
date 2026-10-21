import { describe, it, expect } from "vitest"
import * as api from "./index.js"

describe("library entry", () => {
  it("exposes exactly the supported API", () => {
    expect(Object.keys(api).sort()).toEqual(["detectAgents", "run", "scan"])
  })
})
