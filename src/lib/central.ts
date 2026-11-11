import { HttpError, readLimitedText, redact } from "./http-error";
import { batchPlan } from "./plan-import";
import type { DataRegion, EndpointSite, ImportMode, ImportPlan, ImportResult, PlannedSite } from "./types";
import { DATA_REGIONS } from "./types";

const TOKEN_URL = "https://id.sophos.com/api/v2/oauth2/token";
const WHOAMI_URL = "https://api.central.sophos.com/whoami/v1";
const REGION_HOST = /^https:\/\/api-([a-z0-9]+)\.central\.sophos\.com$/;

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type CentralAuth = {
  clientId: string;
  clientSecret: string;
  tenantId?: string;
  dataRegion?: string;
};

type Session = {
  token: string;
  tenantId: string;
  apiHost: string;
  secrets: string[];
};

export async function listExcludedSites(auth: CentralAuth): Promise<EndpointSite[]> {
  const session = await openSession(auth);
  return readAllSites(session);
}

export async function applyImport(
  auth: CentralAuth,
  plan: ImportPlan,
  importMode: ImportMode,
  sample: boolean,
): Promise<ImportResult> {
  const payloads = batchPlan(plan);
  if (sample) {
    return {
      sample: true,
      importMode,
      added: plan.add,
      removed: plan.remove.map((site) => ({ value: site.value })),
      alreadyPresent: plan.alreadyPresent,
      skipped: plan.skipped,
      errors: [],
      payloads,
    };
  }

  if (payloads.length === 0) {
    return {
      sample: false,
      importMode,
      added: [],
      removed: [],
      alreadyPresent: plan.alreadyPresent,
      skipped: plan.skipped,
      errors: [],
      payloads: [],
    };
  }

  const session = await openSession(auth);
  const added: PlannedSite[] = [];
  const removed: PlannedSite[] = [];
  const errors: { message: string }[] = [];

  for (const payload of payloads) {
    try {
      const result = await patchSites(session, payload);
      added.push(...result.added);
      removed.push(...result.removed);
    } catch (error) {
      errors.push({
        message: error instanceof HttpError ? error.message : "The Endpoint update failed.",
      });
      break;
    }
  }

  return {
    sample: false,
    importMode,
    added,
    removed,
    alreadyPresent: plan.alreadyPresent,
    skipped: plan.skipped,
    errors,
    payloads,
  };
}

async function openSession(auth: CentralAuth): Promise<Session> {
  const secrets = [auth.clientSecret];
  const token = await fetchToken(auth.clientId, auth.clientSecret);
  secrets.push(token);
  const who = await whoami(token, secrets);
  const tenantId = resolveTenant(auth.tenantId, who);
  const apiHost = resolveHost(auth.dataRegion, who.dataRegion);
  return { token, tenantId, apiHost, secrets };
}

async function fetchToken(clientId: string, clientSecret: string): Promise<string> {
  let response: Response;
  try {
    response = await fetch(TOKEN_URL, {
      method: "POST",
      redirect: "manual",
      signal: AbortSignal.timeout(20_000),
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: clientId,
        client_secret: clientSecret,
        scope: "token",
      }),
    });
  } catch {
    throw new HttpError(502, "Could not reach Sophos ID to request an access token.");
  }
  const body = await parseJson(response, [clientSecret]);
  if (!response.ok || !body || typeof body.access_token !== "string" || !body.access_token) {
    throw new HttpError(response.status === 401 ? 401 : 502, centralFailure(response.status, body, [clientSecret]) || "Sophos ID did not return an access token.");
  }
  return body.access_token;
}

async function whoami(token: string, secrets: string[]): Promise<{ id: string; idType: string; dataRegion?: string }> {
  let response: Response;
  try {
    response = await fetch(WHOAMI_URL, {
      method: "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(20_000),
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
      },
    });
  } catch {
    throw new HttpError(502, "Could not reach Sophos Central Who am I.");
  }
  const body = await parseJson(response, secrets);
  if (!response.ok || !body || typeof body.id !== "string") {
    throw new HttpError(response.status || 502, centralFailure(response.status, body, secrets) || "Who am I failed.");
  }
  const apiHosts = body.apiHosts && typeof body.apiHosts === "object" ? (body.apiHosts as Record<string, unknown>) : {};
  return {
    id: body.id,
    idType: typeof body.idType === "string" ? body.idType : "",
    dataRegion: typeof apiHosts.dataRegion === "string" ? apiHosts.dataRegion : undefined,
  };
}

function resolveTenant(requested: string | undefined, who: { id: string; idType: string }): string {
  const trimmed = requested?.trim() ?? "";
  if (trimmed) {
    if (!UUID.test(trimmed)) throw new HttpError(400, "Tenant ID must be a UUID.");
    return trimmed;
  }
  if (who.idType !== "tenant") {
    throw new HttpError(
      400,
      "These credentials belong to a partner or organization. Enter the tenant ID to update.",
    );
  }
  if (!UUID.test(who.id)) throw new HttpError(502, "Who am I did not return a tenant UUID.");
  return who.id;
}

function resolveHost(requested: string | undefined, whoamiHost: string | undefined): string {
  const region = requested?.trim() ?? "";
  if (region) {
    if (!(DATA_REGIONS as readonly string[]).includes(region)) {
      throw new HttpError(400, "Data region is not one of the Endpoint API regions.");
    }
    return `https://api-${region as DataRegion}.central.sophos.com`;
  }
  if (!whoamiHost) {
    throw new HttpError(400, "Who am I did not return a data region. Choose one and try again.");
  }
  const match = REGION_HOST.exec(whoamiHost);
  if (!match || !(DATA_REGIONS as readonly string[]).includes(match[1] ?? "")) {
    throw new HttpError(502, "Who am I returned a data region this importer will not call.");
  }
  return whoamiHost;
}

async function readAllSites(session: Session): Promise<EndpointSite[]> {
  const sites: EndpointSite[] = [];
  let page = 1;
  let pageSize = 100;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const url = new URL(`${session.apiHost}/endpoint/v1/settings/web-control/tls-decryption/excluded-websites`);
    url.searchParams.set("page", String(page));
    url.searchParams.set("pageSize", String(pageSize));
    url.searchParams.set("pageTotal", "true");
    const body = await centralJson(url, "GET", session, undefined);
    const items = Array.isArray(body.items) ? body.items : null;
    if (!items) throw new HttpError(502, "Endpoint did not return an excluded-websites list.");
    for (const item of items) {
      if (!item || typeof item !== "object") continue;
      const record = item as Record<string, unknown>;
      if (typeof record.value !== "string") continue;
      sites.push({
        value: record.value,
        comment: typeof record.comment === "string" ? record.comment : undefined,
      });
    }
    const pages = body.pages && typeof body.pages === "object" ? (body.pages as Record<string, unknown>) : {};
    const total = typeof pages.total === "number" ? pages.total : undefined;
    const current = typeof pages.current === "number" ? pages.current : page;
    const maxSize = typeof pages.maxSize === "number" ? pages.maxSize : undefined;
    if (maxSize && maxSize > 0 && maxSize < pageSize) pageSize = maxSize;
    if (items.length === 0) break;
    if (total !== undefined && current >= total) break;
    if (total === undefined && items.length < pageSize) break;
    page = current + 1;
  }
  return sites;
}

async function patchSites(
  session: Session,
  payload: { add?: PlannedSite[]; remove?: { value: string }[] },
): Promise<{ added: PlannedSite[]; removed: PlannedSite[] }> {
  const url = new URL(`${session.apiHost}/endpoint/v1/settings/web-control/tls-decryption/excluded-websites`);
  const body = await centralJson(url, "PATCH", session, payload);
  return {
    added: parseSiteList(body.added),
    removed: parseSiteList(body.removed),
  };
}

async function centralJson(
  url: URL,
  method: "GET" | "PATCH",
  session: Session,
  payload: unknown,
): Promise<Record<string, unknown>> {
  let response: Response;
  try {
    response = await fetch(url, {
      method,
      redirect: "manual",
      signal: AbortSignal.timeout(20_000),
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${session.token}`,
        "X-Tenant-ID": session.tenantId,
        ...(payload ? { "Content-Type": "application/json" } : {}),
      },
      body: payload ? JSON.stringify(payload) : undefined,
    });
  } catch {
    throw new HttpError(502, "Could not reach the Sophos Endpoint API.");
  }
  if (response.status >= 300 && response.status < 400) {
    throw new HttpError(502, "Sophos Central redirected the request. This importer does not follow redirects.");
  }
  const body = await parseJson(response, session.secrets);
  if (!response.ok) {
    throw new HttpError(response.status, centralFailure(response.status, body, session.secrets));
  }
  if (!body) return {};
  return body;
}

async function parseJson(response: Response, secrets: string[]): Promise<Record<string, unknown> | null> {
  const text = await readLimitedText(response);
  const trimmed = text.trim();
  if (!trimmed) return null;
  try {
    const parsed = JSON.parse(trimmed) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    throw new HttpError(502, redact(trimmed, secrets) || "Sophos returned a response that was not JSON.");
  }
}

function centralFailure(status: number, body: Record<string, unknown> | null, secrets: string[]): string {
  const message = typeof body?.message === "string" ? redact(body.message, secrets) : "";
  const code = typeof body?.error === "string" ? body.error : "";
  const requestId = typeof body?.requestId === "string" ? body.requestId : "";
  if (status === 401) return "Sophos Central rejected the client credentials or the access token.";
  if (status === 403) return message || "This credential cannot update TLS exclusions for the tenant.";
  if (status === 422) {
    return message || "The exclusion list would exceed the Endpoint limit after this update.";
  }
  const detail = [code, message].filter(Boolean).join(": ");
  const suffix = requestId ? ` Request ${requestId}.` : "";
  return `${detail || `Sophos Central returned HTTP ${status}.`}${suffix}`;
}

function parseSiteList(value: unknown): PlannedSite[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (!item || typeof item !== "object") return [];
    const record = item as Record<string, unknown>;
    if (typeof record.value !== "string") return [];
    return [
      {
        value: record.value,
        comment: typeof record.comment === "string" ? record.comment : undefined,
      },
    ];
  });
}
