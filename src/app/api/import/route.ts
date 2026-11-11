import { applyImport, listExcludedSites, type CentralAuth } from "@/lib/central";
import { clientSecretFromEnv, isDataRegion, publicDefaults } from "@/lib/env";
import { sampleEndpointSites } from "@/lib/fixtures";
import { HttpError } from "@/lib/http-error";
import { planImport } from "@/lib/plan-import";
import type { Candidate, ImportMode } from "@/lib/types";

export const dynamic = "force-dynamic";

type ImportBody = {
  mode?: string;
  importMode?: string;
  candidates?: Candidate[];
  firewallUser?: string;
  clientId?: string;
  clientSecret?: string;
  useEnvClientSecret?: boolean;
  tenantId?: string;
  dataRegion?: string;
};

export async function POST(request: Request) {
  let body: ImportBody;
  try {
    body = (await request.json()) as ImportBody;
  } catch {
    return Response.json({ error: "Send a JSON request." }, { status: 400 });
  }

  const importMode: ImportMode = body.importMode === "replace" ? "replace" : "merge";
  const candidates = Array.isArray(body.candidates) ? body.candidates.slice(0, 1000) : [];
  if (candidates.length === 0) {
    return Response.json({ error: "Select at least one site before importing." }, { status: 400 });
  }

  try {
    if (body.mode === "sample") {
      const plan = planImport({
        candidates,
        existing: sampleEndpointSites(),
        mode: importMode,
        operator: body.firewallUser,
      });
      const result = await applyImport(
        { clientId: "sample", clientSecret: "sample" },
        plan,
        importMode,
        true,
      );
      return Response.json(result);
    }
    if (body.mode !== "live") {
      return Response.json({ error: "Choose sample data or a live tenant." }, { status: 400 });
    }

    const auth = requireCentral(body);
    const existing = await listExcludedSites(auth);
    const plan = planImport({
      candidates,
      existing,
      mode: importMode,
      operator: body.firewallUser,
    });
    if (importMode === "replace" && existing.length === 0 && plan.add.length === 0) {
      return Response.json({
        error: "The current Endpoint list is empty and there is nothing new to add.",
      }, { status: 400 });
    }
    const result = await applyImport(auth, plan, importMode, false);
    return Response.json(result);
  } catch (error) {
    if (error instanceof HttpError) {
      return Response.json({ error: error.message }, { status: error.status >= 400 && error.status < 600 ? error.status : 502 });
    }
    console.error("import failed", error instanceof Error ? error.name : "unknown");
    return Response.json({ error: "The Endpoint update failed." }, { status: 502 });
  }
}

function requireCentral(body: ImportBody): CentralAuth {
  const defaults = publicDefaults();
  const clientId = body.clientId?.trim() || defaults.clientId;
  const typedSecret = body.clientSecret?.trim() ?? "";
  const clientSecret = typedSecret || (body.useEnvClientSecret ? clientSecretFromEnv() : "");
  if (!clientId || !clientSecret) {
    throw new HttpError(400, "Enter the Sophos Central client ID and client secret.");
  }
  const region = body.dataRegion?.trim() || defaults.dataRegion;
  if (region && !isDataRegion(region)) {
    throw new HttpError(400, "Data region is not one of the Endpoint API regions.");
  }
  return {
    clientId,
    clientSecret,
    tenantId: body.tenantId?.trim() || defaults.tenantId || undefined,
    dataRegion: region || undefined,
  };
}
