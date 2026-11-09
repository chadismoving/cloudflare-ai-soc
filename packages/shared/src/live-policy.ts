import { z } from "zod";
import { defaultWorkbenchPolicy, workbenchPolicySchema } from "./workbench";

export const livePolicySchema = workbenchPolicySchema.extend({
  provider: z.enum(["workers_ai", "disabled"]),
  maxDurationSeconds: z.number().int().min(60).max(600),
});
export type LivePolicy = z.infer<typeof livePolicySchema>;
export const defaultLivePolicy: LivePolicy = {
  ...defaultWorkbenchPolicy,
  provider: "workers_ai",
  maxDurationSeconds: 600,
  investigationDeadlineSeconds: 75,
};

export interface LivePolicyState {
  version: number;
  policy: LivePolicy;
}
