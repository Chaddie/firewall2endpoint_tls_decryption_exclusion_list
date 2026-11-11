import { Agent } from "undici";

import { HttpError, readLimitedText, redact } from "./http-error";
import { resolveFirewallTarget } from "./safe-firewall";
import type {
  FirewallSnapshot,
  FqdnGroup,
  FqdnHost,
  Reference,
  TlsRule,
  UrlGroup,
  WebException,
} from "./types";

const insecureAgent = new Agent({
  connect: { rejectUnauthorized: false },
});

type FirewallAuth = {
  baseUrl: string;
  apiKey: string;
  allowInsecureTls: boolean;
};

export async function pullFirewall(auth: FirewallAuth): Promise<FirewallSnapshot> {
  const target = await resolveFirewallTarget(auth.baseUrl);
  const exceptions = (await getCollection(target.apiBase, "/web/exceptions", auth))
    .map(parseException)
    .filter((item): item is WebException => item !== null);
  const tlsRules = (await getCollection(target.apiBase, "/tls-inspection/rules/ipv4", auth))
    .map(parseRule)
    .filter((item): item is TlsRule => item !== null);

  const needsUrlGroups = tlsRules.some(
    (rule) =>
      rule.action === "doNotDecrypt" &&
      rule.websites &&
      !isAny(rule.websites) &&
      (rule.websites.urlGroups?.length ?? 0) > 0,
  );
  const needsFqdnHosts = tlsRules.some((rule) => ruleNeedsFqdn(rule));
  const needsFqdnGroups = tlsRules.some(
    (rule) =>
      rule.action === "doNotDecrypt" &&
      rule.destinationNetworks &&
      !isAny(rule.destinationNetworks) &&
      (rule.destinationNetworks.fqdnGroups?.length ?? 0) > 0,
  );

  const [urlGroups, fqdnHosts, fqdnGroups] = await Promise.all([
    needsUrlGroups ? loadUrlGroups(target.apiBase, auth) : Promise.resolve([]),
    needsFqdnHosts || needsFqdnGroups ? loadFqdns(target.apiBase, auth) : Promise.resolve([]),
    needsFqdnGroups ? loadFqdnGroups(target.apiBase, auth) : Promise.resolve([]),
  ]);

  return { exceptions, tlsRules, urlGroups, fqdnHosts, fqdnGroups };
}

async function loadUrlGroups(apiBase: string, auth: FirewallAuth): Promise<UrlGroup[]> {
  return (await getCollection(apiBase, "/web/url-groups", auth))
    .map(parseUrlGroup)
    .filter((item): item is UrlGroup => item !== null);
}

async function loadFqdns(apiBase: string, auth: FirewallAuth): Promise<FqdnHost[]> {
  return (await getCollection(apiBase, "/network/addresses/fqdn", auth))
    .map(parseFqdn)
    .filter((item): item is FqdnHost => item !== null);
}

async function loadFqdnGroups(apiBase: string, auth: FirewallAuth): Promise<FqdnGroup[]> {
  return (await getCollection(apiBase, "/network/address-groups/fqdn", auth))
    .map(parseFqdnGroup)
    .filter((item): item is FqdnGroup => item !== null);
}

function ruleNeedsFqdn(rule: TlsRule): boolean {
  return (
    rule.action === "doNotDecrypt" &&
    Boolean(rule.destinationNetworks) &&
    !isAny(rule.destinationNetworks) &&
    (rule.destinationNetworks?.fqdnAddresses?.length ?? 0) > 0
  );
}

function isAny(value: object | undefined): value is { any: true } {
  return Boolean(value && "any" in value && (value as { any?: boolean }).any === true);
}

async function getCollection(apiBase: string, path: string, auth: FirewallAuth): Promise<unknown[]> {
  const items: unknown[] = [];
  let page = 1;
  let pageSize = 100;
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const url = new URL(`${apiBase}${path}`);
    url.searchParams.set("page", String(page));
    url.searchParams.set("pageSize", String(pageSize));
    url.searchParams.set("pageTotal", "true");
    const body = await firewallJson(url, auth);
    const pageItems = Array.isArray(body.items) ? body.items : null;
    if (!pageItems) {
      throw new HttpError(502, `Firewall response for ${path} did not include an items list.`);
    }
    items.push(...pageItems);
    const pages = asRecord(body.pages);
    const total = numberOrUndefined(pages?.total);
    const current = numberOrUndefined(pages?.current) ?? page;
    const maxSize = numberOrUndefined(pages?.maxSize);
    if (maxSize && maxSize > 0 && maxSize < pageSize) pageSize = maxSize;
    if (pageItems.length === 0) break;
    if (total !== undefined && current >= total) break;
    if (total === undefined && pageItems.length < pageSize) break;
    page = current + 1;
  }
  return items;
}

async function firewallJson(url: URL, auth: FirewallAuth): Promise<Record<string, unknown>> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(20_000),
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${auth.apiKey}`,
      },
      ...(auth.allowInsecureTls ? { dispatcher: insecureAgent } : {}),
    } as RequestInit);
  } catch {
    throw new HttpError(
      502,
      "Could not reach the firewall. Check the URL, port, and certificate. Certificate checks stay on unless you allow this firewall's certificate.",
    );
  }

  if (response.status >= 300 && response.status < 400) {
    throw new HttpError(502, "The firewall redirected the request. This importer does not follow redirects.");
  }

  const text = await readLimitedText(response);
  const trimmed = text.trim();
  if (trimmed.startsWith("<")) {
    throw new HttpError(
      502,
      "The firewall returned XML. These calls use the configuration REST API, which returns JSON.",
    );
  }

  let parsed: unknown = null;
  if (trimmed) {
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      throw new HttpError(502, "The firewall response was not JSON.");
    }
  }

  if (!response.ok) {
    throw new HttpError(response.status, firewallFailure(response.status, parsed, auth.apiKey));
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new HttpError(502, "The firewall response was not a JSON object.");
  }
  return parsed as Record<string, unknown>;
}

function firewallFailure(status: number, body: unknown, apiKey: string): string {
  const record = asRecord(body);
  const message = typeof record?.message === "string" ? redact(record.message, [apiKey]) : "";
  if (status === 401) {
    return message || "Firewall authentication failed. Use the API key from Administration, API access.";
  }
  if (status === 403) return message || "This API key is not allowed to read that configuration.";
  if (status === 404) return "The firewall did not recognize the configuration API path.";
  return message || `Firewall returned HTTP ${status}.`;
}

function parseException(value: unknown): WebException | null {
  const record = asRecord(value);
  if (!record || typeof record.name !== "string" || typeof record.id !== "string") return null;
  const skip = asRecord(record.skip);
  const conditions = asRecord(record.conditions);
  const destination = asRecord(conditions?.destinationIpOrNetworks);
  const urls = asRecord(conditions?.urlRegexPatterns);
  const categories = asRecord(conditions?.webCategories);
  const source = asRecord(conditions?.sourceIpOrNetworks);
  return {
    id: record.id,
    name: record.name,
    enabled: record.enabled === true,
    skip: { httpsDecryption: skip?.httpsDecryption === true },
    conditions: {
      sourceIpOrNetworks: { enabled: source?.enabled === true },
      destinationIpOrNetworks: {
        enabled: destination?.enabled === true,
        ipv4Networks: arrayOfRecords(destination?.ipv4Networks).flatMap((item) => {
          if (typeof item.ipv4Address !== "string") return [];
          return [{ ipv4Address: item.ipv4Address, cidr: numberOrUndefined(item.cidr) }];
        }),
        ipv6Networks: arrayOfRecords(destination?.ipv6Networks).flatMap((item) => {
          if (typeof item.ipv6Address !== "string") return [];
          return [{ ipv6Address: item.ipv6Address, prefixLength: numberOrUndefined(item.prefixLength) }];
        }),
      },
      urlRegexPatterns: {
        enabled: urls?.enabled === true,
        values: arrayOfStrings(urls?.values),
      },
      webCategories: {
        enabled: categories?.enabled === true,
        values: arrayOfRecords(categories?.values).flatMap(parseReference),
      },
    },
  };
}

function parseRule(value: unknown): TlsRule | null {
  const record = asRecord(value);
  if (!record || typeof record.name !== "string" || typeof record.id !== "string") return null;
  const action = typeof record.action === "string" ? record.action : "";
  return {
    id: record.id,
    name: record.name,
    enabled: record.enabled === true,
    action,
    websites: parseWebsites(record.websites),
    destinationNetworks: parseDestination(record.destinationNetworks),
  };
}

function parseWebsites(value: unknown): TlsRule["websites"] {
  const record = asRecord(value);
  if (!record) return undefined;
  if (record.any === true) return { any: true };
  return {
    urlGroups: arrayOfRecords(record.urlGroups).flatMap(parseReference),
    categories: arrayOfRecords(record.categories).flatMap(parseReference),
  };
}

function parseDestination(value: unknown): TlsRule["destinationNetworks"] {
  const record = asRecord(value);
  if (!record) return undefined;
  if (record.any === true) return { any: true };
  return {
    fqdnAddresses: arrayOfRecords(record.fqdnAddresses).flatMap(parseReference),
    fqdnGroups: arrayOfRecords(record.fqdnGroups).flatMap(parseReference),
    macAddresses: arrayOfRecords(record.macAddresses).flatMap(parseReference),
  };
}

function parseUrlGroup(value: unknown): UrlGroup | null {
  const record = asRecord(value);
  if (!record || typeof record.id !== "string" || typeof record.name !== "string") return null;
  return { id: record.id, name: record.name, urls: arrayOfStrings(record.urls) };
}

function parseFqdn(value: unknown): FqdnHost | null {
  const record = asRecord(value);
  if (!record || typeof record.id !== "string" || typeof record.name !== "string" || typeof record.fqdn !== "string") {
    return null;
  }
  return { id: record.id, name: record.name, fqdn: record.fqdn };
}

function parseFqdnGroup(value: unknown): FqdnGroup | null {
  const record = asRecord(value);
  if (!record || typeof record.id !== "string" || typeof record.name !== "string") return null;
  return {
    id: record.id,
    name: record.name,
    fqdns: arrayOfRecords(record.fqdns).flatMap((item) =>
      typeof item.name === "string" ? [{ name: item.name }] : [],
    ),
  };
}

function parseReference(value: Record<string, unknown>): Reference[] {
  if (typeof value.name !== "string" || !value.name) return [];
  return [{ id: typeof value.id === "string" ? value.id : undefined, name: value.name }];
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function arrayOfRecords(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const record = asRecord(item);
    return record ? [record] : [];
  });
}

function arrayOfStrings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string");
}

function numberOrUndefined(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}
