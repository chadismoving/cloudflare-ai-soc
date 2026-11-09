import { z } from "zod";

export const repairHost = "soc-test.d.example.invalid";
export const repairId = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
export const cloudId = /^[a-f0-9]{32}$/;
export const repairScope = z.object({
  path: z.string().regex(/^\/__soc_test\/[a-zA-Z0-9_-]{1,64}$/),
  client_ip: z.ipv4(),
});
export const repairDraft = repairScope
  .strict()
  .extend({ note: z.string().trim().min(12).max(300) });
export const repairExpression = (scope: z.infer<typeof repairScope>) =>
  `(http.host eq "${repairHost}" and http.request.uri.path eq "${scope.path}" and ip.src eq ${scope.client_ip})`;
export const repairRef = (id: string) => `soc_${id.replaceAll("-", "")}`;

export interface RepairRow extends z.infer<typeof repairScope> {
  id: string;
  note: string;
  status:
    | "pending"
    | "approved"
    | "rejected"
    | "applying"
    | "verified"
    | "rolling_back"
    | "rolled_back"
    | "review";
  requested_by: string;
  created_at: string;
  approved_by: string | null;
  approved_at: string | null;
  apply_before: string;
  rule_expires_at: string | null;
  ruleset_id: string | null;
  rule_id: string | null;
  lease_until: string | null;
  result: string | null;
}
