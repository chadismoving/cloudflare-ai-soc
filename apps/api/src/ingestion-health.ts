import { type IngestionCoverage, pilotRawKeys, pilotRawPrefix } from "@soc/shared";

export function observedWaitSeconds(uploaded: string, firstAttempt: string | null): number | null {
  if (!firstAttempt) return null;
  const elapsed = Date.parse(firstAttempt) - Date.parse(uploaded);
  return Number.isFinite(elapsed) && elapsed >= 0 ? Math.floor(elapsed / 1000) : null;
}

// Isolated synthetic bucket only. Caller must authenticate and authorize fixture-zone first.
// At most 20 metadata entries / 2 list requests; no bodies, writes or Queue access.
export async function reconcileIngestion(
  bucket: R2Bucket,
  db: D1Database,
  scope: IngestionCoverage["scope"],
): Promise<IngestionCoverage> {
  const cloud = scope === "cloud-pilot-20261029";
  const checkedAt = new Date().toISOString();
  const clock = Date.parse(checkedAt);
  const objects: IngestionCoverage["objects"] = [];
  let cursor: string | undefined;
  let scannedObjects = 0;
  let excludedObjects = 0;
  let scanComplete = false;
  for (let page = 0; page < 2; page++) {
    const listing = await bucket.list({
      prefix: cloud ? pilotRawPrefix : "raw/",
      limit: 10,
      ...(cursor ? { cursor } : {}),
    });
    for (const object of listing.objects) {
      scannedObjects++;
      if (
        (cloud && !pilotRawKeys.some((key) => key === object.key)) ||
        object.key.length > 240 ||
        !/^raw\/(http|firewall|notification)\/[a-zA-Z0-9_-]+\.ndjson(?:\.gz)?$/.test(object.key)
      ) {
        excludedObjects++;
        continue;
      }
      const row = await db
        .prepare(
          "SELECT etag,state,raw_expires_at FROM ingestion_objects WHERE object_key=? ORDER BY (etag=?) DESC,received_at DESC LIMIT 1",
        )
        .bind(object.key, object.etag)
        .first<{ etag: string; state: string; raw_expires_at: string }>();
      const age = Math.max(0, clock - object.uploaded.getTime());
      const expired =
        age >= 30 * 86400000 || (row?.etag === object.etag && row.raw_expires_at <= checkedAt);
      objects.push({
        key: object.key,
        uploadedAt: object.uploaded.toISOString(),
        ageSeconds: Math.floor(age / 1000),
        status: expired
          ? "expired"
          : !row
            ? "missing_checkpoint"
            : row.etag !== object.etag
              ? "etag_changed"
              : row.state,
      });
    }
    if (!listing.truncated) {
      scanComplete = true;
      break;
    }
    cursor = listing.cursor;
    if (!cursor) break;
  }
  return {
    simulation: true,
    scope,
    checkedAt,
    scanComplete,
    scannedObjects,
    excludedObjects,
    objects,
  };
}
