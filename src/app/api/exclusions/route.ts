import { listExcludedSites, type CentralAuth } from "@/lib/central";
import { publicDefaults, clientSecretFromEnv, firewallApiKeyFromEnv, isDataRegion } from "@/lib/env";
import { extractSnapshot } from "@/lib/extract";
import { sampleEndpointSites, sampleSnapshot } from "@/lib/fixtures";
import { pullFirewall } from "@/lib/firewall";
import { HttpError } from "@/lib/http-error";
import type { EndpointSite, ExclusionLoad, FirewallSnapshot } from "@/lib/types";

export const dynamic = "force-dynamic";

type LoadBody = {
  mode?: string;
  firewallUrl?: string;
  firewallUser?: string;
  firewallApiKey?: string;
  useEnvFirewallKey?: boolean;
  allowInsecureTls?: boolean;
  clientId?: string;
  clientSecret?: string;
  useEnvClientSecret?: boolean;
  tenantId?: string;
  dataRegion?: string;
};

export async function POST(request: Request) {
  let body: LoadBody;
  try {
    body = (await request.json()) as LoadBody;
  } catch {
    return Response.json({ error: "Send a JSON request." }, { status: 400 });
  }

  try {
    if (body.mode === "sample") {
      return Response.json(buildLoad(sampleSnapshot(), sampleEndpointSites(), true));
    }
    if (body.mode !== "live") {
      return Response.json({ error: "Choose sample data or a live firewall." }, { status: 400 });
    }

    const apiKey = secretOrEnv(body.firewallApiKey, body.useEnvFirewallKey, firewallApiKeyFromEnv());
    const firewallUrl = body.firewallUrl?.trim() || publicDefaults().firewallUrl;
    if (!firewallUrl) return Response.json({ error: "Enter the firewall URL." }, { status: 400 });
    if (!apiKey) {
      return Response.json(
        { error: "Enter the firewall API key, or use the key from the server environment." },
        { status: 400 },
      );
    }

    const snapshot = await pullFirewall({
      baseUrl: firewallUrl,
      apiKey,
      allowInsecureTls: body.allowInsecureTls === true,
    });

    let endpointSites: EndpointSite[] | null = null;
    let endpointWarning: string | undefined;
    const central = centralAuth(body);
    if (central.warning) endpointWarning = central.warning;
    if (central.auth) {
      try {
        endpointSites = await listExcludedSites(central.auth);
      } catch (error) {
        endpointWarning =
          error instanceof HttpError
            ? error.message
            : "The current Endpoint exclusion list could not be read.";
      }
    }

    const load = buildLoad(snapshot, endpointSites, false);
    return Response.json({ ...load, endpointWarning });
  } catch (error) {
    return failure(error);
  }
}

function buildLoad(snapshot: FirewallSnapshot, endpointSites: EndpointSite[] | null, sample: boolean): ExclusionLoad {
  const extracted = extractSnapshot(snapshot);
  return {
    sample,
    candidates: extracted.candidates,
    filtered: extracted.filtered,
    endpointSites,
    summary: {
      webExceptions: snapshot.exceptions.length,
      tlsRules: snapshot.tlsRules.length,
      urlGroups: snapshot.urlGroups.length,
      fqdnHosts: snapshot.fqdnHosts.length,
      fqdnGroups: snapshot.fqdnGroups.length,
    },
  };
}

function centralAuth(body: LoadBody): { auth: CentralAuth | null; warning?: string } {
  const defaults = publicDefaults();
  const clientId = body.clientId?.trim() || defaults.clientId;
  const clientSecret = secretOrEnv(body.clientSecret, body.useEnvClientSecret, clientSecretFromEnv());
  const tenantId = body.tenantId?.trim() || "";
  const region = body.dataRegion?.trim() || defaults.dataRegion;
  if (!clientId && !clientSecret && !tenantId && !region) return { auth: null };
  if (!clientId || !clientSecret) {
    return {
      auth: null,
      warning: "Enter both the Sophos Central client ID and client secret to read the current Endpoint list.",
    };
  }
  if (region && !isDataRegion(region)) {
    return { auth: null, warning: "Data region is not one of the Endpoint API regions." };
  }
  return {
    auth: {
      clientId,
      clientSecret,
      tenantId: tenantId || defaults.tenantId || undefined,
      dataRegion: region || undefined,
    },
  };
}

function secretOrEnv(typed: string | undefined, useEnv: boolean | undefined, envValue: string): string {
  const value = typed?.trim() ?? "";
  if (value) return value;
  if (useEnv) return envValue;
  return "";
}

function failure(error: unknown) {
  if (error instanceof HttpError) {
    return Response.json({ error: error.message }, { status: error.status >= 400 && error.status < 600 ? error.status : 502 });
  }
  console.error("exclusion load failed", error instanceof Error ? error.name : "unknown");
  return Response.json({ error: "The firewall request failed." }, { status: 502 });
}
