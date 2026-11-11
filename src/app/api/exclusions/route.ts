import { listExcludedSites, type CentralAuth } from "@/lib/central";
import { extractSnapshot } from "@/lib/extract";
import { sampleEndpointSites, sampleSnapshot } from "@/lib/fixtures";
import { pullFirewall } from "@/lib/firewall";
import { HttpError } from "@/lib/http-error";
import { isDataRegion, type EndpointSite, type ExclusionLoad, type FirewallSnapshot } from "@/lib/types";

export const dynamic = "force-dynamic";

type LoadBody = {
  mode?: string;
  firewallUrl?: string;
  firewallUser?: string;
  firewallApiKey?: string;
  allowInsecureTls?: boolean;
  clientId?: string;
  clientSecret?: string;
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

    const apiKey = body.firewallApiKey?.trim() ?? "";
    const firewallUrl = body.firewallUrl?.trim() ?? "";
    if (!firewallUrl) return Response.json({ error: "Enter the firewall URL." }, { status: 400 });
    if (!apiKey) return Response.json({ error: "Enter the firewall API key." }, { status: 400 });

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
  const clientId = body.clientId?.trim() ?? "";
  const clientSecret = body.clientSecret?.trim() ?? "";
  const tenantId = body.tenantId?.trim() ?? "";
  const region = body.dataRegion?.trim() ?? "";
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
      tenantId: tenantId || undefined,
      dataRegion: region || undefined,
    },
  };
}

function failure(error: unknown) {
  if (error instanceof HttpError) {
    return Response.json({ error: error.message }, { status: error.status >= 400 && error.status < 600 ? error.status : 502 });
  }
  console.error("exclusion load failed", error instanceof Error ? error.name : "unknown");
  return Response.json({ error: "The firewall request failed." }, { status: 502 });
}
