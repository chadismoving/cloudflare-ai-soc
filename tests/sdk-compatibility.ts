import { Agent } from "agents";
import { createMcpHandler } from "agents/mcp/server";
import Cloudflare from "cloudflare";
import type { Bindings } from "../apps/api/src/env";

// Compile-only spike: no instance, network operation, or application route is created.
export class CompatibilityAgent extends Agent<Bindings> {}
export const supportedMcpHandler = createMcpHandler;
export function restClientForRead(token: string): Cloudflare {
  return new Cloudflare({ apiToken: token, maxRetries: 0, timeout: 10000 });
}
