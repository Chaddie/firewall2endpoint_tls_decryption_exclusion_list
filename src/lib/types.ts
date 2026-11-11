export type SiteSourceKind = "web-exception" | "ssl-tls-rule";

export type SiteSource = {
  kind: SiteSourceKind;
  ruleId: string;
  ruleName: string;
  enabled: boolean;
  detail: string;
};

export type Candidate = {
  id: string;
  site: string;
  rawValues: string[];
  sources: SiteSource[];
  selected: boolean;
  valid: boolean;
  derived: boolean;
  invalidReason?: string;
  note?: string;
};

export type FilteredEntry = {
  kind: SiteSourceKind;
  ruleName: string;
  raw: string;
  reason: string;
};

export type EndpointSite = {
  value: string;
  comment?: string;
};

export type FirewallSummary = {
  webExceptions: number;
  tlsRules: number;
  urlGroups: number;
  fqdnHosts: number;
  fqdnGroups: number;
};

export type ExclusionLoad = {
  sample: boolean;
  candidates: Candidate[];
  filtered: FilteredEntry[];
  endpointSites: EndpointSite[] | null;
  endpointWarning?: string;
  summary: FirewallSummary;
};

export type ImportMode = "merge" | "replace";

export type PlannedSite = {
  value: string;
  comment?: string;
};

export type ImportPlan = {
  add: PlannedSite[];
  remove: { value: string }[];
  alreadyPresent: string[];
  skipped: { value: string; reason: string }[];
};

export type ImportResult = {
  sample: boolean;
  importMode: ImportMode;
  added: PlannedSite[];
  removed: PlannedSite[];
  alreadyPresent: string[];
  skipped: { value: string; reason: string }[];
  errors: { message: string }[];
  payloads: { add?: PlannedSite[]; remove?: { value: string }[] }[];
};

export type Reference = { id?: string; name: string };

export type IpNetwork = { ipv4Address?: string; cidr?: number; ipv6Address?: string; prefixLength?: number };

export type WebException = {
  id: string;
  name: string;
  enabled: boolean;
  conditions: {
    sourceIpOrNetworks: { enabled: boolean };
    destinationIpOrNetworks: {
      enabled: boolean;
      ipv4Networks: { ipv4Address: string; cidr?: number }[];
      ipv6Networks: { ipv6Address: string; prefixLength?: number }[];
    };
    urlRegexPatterns: { enabled: boolean; values: string[] };
    webCategories: { enabled: boolean; values: Reference[] };
  };
  skip: { httpsDecryption: boolean };
};

export type TlsWebsites =
  | { any: true }
  | { urlGroups?: Reference[]; categories?: Reference[] };

export type TlsDestination =
  | { any: true }
  | {
      fqdnAddresses?: Reference[];
      fqdnGroups?: Reference[];
      macAddresses?: Reference[];
    };

export type TlsRule = {
  id: string;
  name: string;
  enabled: boolean;
  action: "decrypt" | "doNotDecrypt" | "deny" | string;
  websites?: TlsWebsites;
  destinationNetworks?: TlsDestination;
};

export type UrlGroup = { id: string; name: string; urls: string[] };
export type FqdnHost = { id: string; name: string; fqdn: string };
export type FqdnGroup = { id: string; name: string; fqdns: { name: string }[] };

export type FirewallSnapshot = {
  exceptions: WebException[];
  tlsRules: TlsRule[];
  urlGroups: UrlGroup[];
  fqdnHosts: FqdnHost[];
  fqdnGroups: FqdnGroup[];
};

export const DATA_REGIONS = [
  "eu01",
  "eu02",
  "us01",
  "us03",
  "ca01",
  "au01",
  "jp01",
  "in01",
  "br01",
  "ae01",
] as const;

export type DataRegion = (typeof DATA_REGIONS)[number];

export function isDataRegion(value: string): value is DataRegion {
  return (DATA_REGIONS as readonly string[]).includes(value);
}
