import { commentForSources, sanitizeComment, toEndpointValue } from "./endpoint-value";
import type { Candidate, EndpointSite, ImportPlan, PlannedSite } from "./types";

const BATCH = 500;

export function planImport(input: {
  candidates: Pick<Candidate, "site" | "selected" | "sources">[];
  existing: EndpointSite[];
  mode: "merge" | "replace";
  comment?: string;
  operator?: string;
}): ImportPlan {
  const existingByValue = new Map<string, string>();
  for (const site of input.existing) {
    const normalized = site.value.trim().toLowerCase();
    if (!existingByValue.has(normalized)) existingByValue.set(normalized, site.value);
  }

  const selected = new Map<string, PlannedSite>();
  const skipped: ImportPlan["skipped"] = [];

  for (const candidate of input.candidates) {
    if (!candidate.selected) continue;
    const normalized = toEndpointValue(candidate.site);
    if (!normalized.value) {
      skipped.push({
        value: candidate.site,
        reason: normalized.reason ?? "This value cannot be sent to Endpoint.",
      });
      continue;
    }
    if (selected.has(normalized.value)) continue;
    const operator = input.operator?.trim();
    const comment = sanitizeComment(
      input.comment?.trim() ||
        `${commentForSources(candidate.sources)}${operator ? ` by ${operator}` : ""}`,
    );
    selected.set(normalized.value, { value: normalized.value, comment });
  }

  const add: PlannedSite[] = [];
  const alreadyPresent: string[] = [];
  for (const [value, site] of selected) {
    if (existingByValue.has(value)) alreadyPresent.push(value);
    else add.push(site);
  }

  const remove: { value: string }[] = [];
  if (input.mode === "replace") {
    for (const [normalized, original] of existingByValue) {
      if (!selected.has(normalized)) remove.push({ value: original });
    }
  }

  return { add, remove, alreadyPresent, skipped };
}

export function batchPlan(plan: ImportPlan): { add?: PlannedSite[]; remove?: { value: string }[] }[] {
  const payloads: { add?: PlannedSite[]; remove?: { value: string }[] }[] = [];
  const adds = [...plan.add];
  const removes = [...plan.remove];
  if (adds.length === 0 && removes.length === 0) return [];
  while (adds.length > 0 || removes.length > 0) {
    const payload: { add?: PlannedSite[]; remove?: { value: string }[] } = {};
    const addBatch = adds.splice(0, BATCH);
    const removeBatch = removes.splice(0, BATCH);
    if (addBatch.length > 0) payload.add = addBatch;
    if (removeBatch.length > 0) payload.remove = removeBatch;
    payloads.push(payload);
  }
  return payloads;
}
