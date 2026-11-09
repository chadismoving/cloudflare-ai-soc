export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
export async function api<T>(
  path: string,
  options: { method?: string; body?: unknown; csrf?: string } = {},
): Promise<T> {
  const headers: Record<string, string> = {};
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (options.csrf) headers["X-CSRF-Token"] = options.csrf;
  let result: Response;
  try {
    result = await fetch(path, {
      method: options.method || "GET",
      credentials: "same-origin",
      redirect: "manual",
      headers,
      ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
    });
  } catch {
    const local = typeof window !== "undefined" && window.location.hostname === "127.0.0.1";
    throw new ApiError(
      0,
      local
        ? "Cannot reach the local server. Run npm run dev in the project folder, open its printed address, then reload this page. Requests are not retried automatically; check saved results before rerunning."
        : "Cannot reach the server. Check your connection, then reload. Requests are not retried automatically; check saved results before rerunning.",
    );
  }
  if (result.type === "opaqueredirect" || result.status === 0)
    throw new ApiError(401, "Your session expired. Reload to sign in.");
  if (!result.headers.get("Content-Type")?.includes("application/json"))
    throw new ApiError(result.status || 503, "Session unavailable. Reload to sign in.");
  const value = (await result.json()) as { error?: { message?: string } };
  if (!result.ok) throw new ApiError(result.status, value.error?.message || "Request failed.");
  return value as T;
}
