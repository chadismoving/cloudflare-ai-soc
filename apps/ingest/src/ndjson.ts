import { fail, limits } from "./schema";

export async function bytes(stream: ReadableStream<Uint8Array>, max: number) {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > max) fail("body_limit");
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}
export async function* lines(
  content: Uint8Array<ArrayBuffer>,
  gzip: boolean,
  activeLimits = limits,
) {
  let stream = new Blob([content]).stream();
  if (gzip) stream = stream.pipeThrough(new DecompressionStream("gzip"));
  const reader = stream.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
  let pending = "",
    expanded = 0,
    count = 0;
  const checkLine = (line: string) => {
    if (++count > activeLimits.lines) fail("row_limit");
    if (new TextEncoder().encode(line).length > activeLimits.line) fail("line_limit");
    return line;
  };
  try {
    for (;;) {
      let next: ReadableStreamReadResult<Uint8Array>;
      try {
        next = await reader.read();
      } catch {
        return fail("invalid_compression");
      }
      if (next.done) break;
      expanded += next.value.byteLength;
      if (expanded > activeLimits.expanded) fail("expanded_limit");
      try {
        pending += decoder.decode(next.value, { stream: true });
      } catch {
        return fail("invalid_utf8");
      }
      for (;;) {
        const end = pending.indexOf("\n");
        if (end < 0) break;
        const line = pending.slice(0, end).replace(/\r$/, "");
        pending = pending.slice(end + 1);
        yield checkLine(line);
      }
      if (new TextEncoder().encode(pending).length > activeLimits.line) fail("line_limit");
    }
    try {
      pending += decoder.decode();
    } catch {
      return fail("invalid_utf8");
    }
    if (pending) yield checkLine(pending);
  } finally {
    await reader.cancel().catch(() => {});
  }
}
