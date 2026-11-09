import { afterEach, expect, it, vi } from "vitest";
import { ApiError, api } from "../apps/console/src/client";

afterEach(() => vi.unstubAllGlobals());

it("explains an unavailable local server without automatically retrying a scenario mutation", async () => {
  vi.stubGlobal("window", { location: { hostname: "127.0.0.1" } });
  const fetch = vi.fn().mockRejectedValue(new TypeError("Failed to fetch"));
  vi.stubGlobal("fetch", fetch);
  const failed = api("/api/simulations/runs", {
    method: "POST",
    body: { scenarioId: "waf-spike" },
  });
  await expect(failed).rejects.toMatchObject({
    status: 0,
    message: expect.stringContaining("Run npm run dev"),
  });
  expect(fetch).toHaveBeenCalledTimes(1);
});

it("distinguishes connection failure from API policy errors and session redirects", async () => {
  vi.stubGlobal("window", { location: { hostname: "soc.example.invalid" } });
  const fetch = vi
    .fn()
    .mockRejectedValueOnce(new TypeError("Failed to fetch"))
    .mockResolvedValueOnce(
      new Response(JSON.stringify({ error: { message: "Budget exhausted" } }), {
        status: 402,
        headers: { "Content-Type": "application/json" },
      }),
    )
    .mockResolvedValueOnce({ type: "opaqueredirect", status: 0 });
  vi.stubGlobal("fetch", fetch);
  await expect(api("/api/session")).rejects.toMatchObject({
    status: 0,
    message: expect.stringContaining("Check your connection"),
  });
  await expect(api("/api/simulations/runs", { method: "POST" })).rejects.toMatchObject({
    status: 402,
    message: "Budget exhausted",
  });
  await expect(api("/api/session")).rejects.toEqual(
    new ApiError(401, "Your session expired. Reload to sign in."),
  );
});
