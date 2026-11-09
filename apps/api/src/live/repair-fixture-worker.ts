import { repairHost, repairScope } from "./repair-policy";

export default {
  fetch(request: Request) {
    const url = new URL(request.url);
    const test = repairScope.shape.path.safeParse(url.pathname);
    if (url.hostname !== repairHost || request.method !== "GET" || !test.success)
      return new Response(null, { status: 404 });
    return new Response("Isolated SOC repair test fixture", {
      headers: { "Cache-Control": "no-store", "X-SOC-Test-Fixture": "isolated-v1" },
    });
  },
} satisfies ExportedHandler;
