import { DATA_REGIONS, type DataRegion } from "./types";

export type PublicDefaults = {
  firewallUrl: string;
  firewallUser: string;
  clientId: string;
  tenantId: string;
  dataRegion: string;
  hasFirewallApiKey: boolean;
  hasClientSecret: boolean;
};

function read(name: string): string {
  return process.env[name]?.trim() ?? "";
}

export function publicDefaults(): PublicDefaults {
  const region = read("SOPHOS_DATA_REGION");
  return {
    firewallUrl: read("SOPHOS_FIREWALL_URL"),
    firewallUser: read("SOPHOS_FIREWALL_USER"),
    clientId: read("SOPHOS_CLIENT_ID"),
    tenantId: read("SOPHOS_TENANT_ID"),
    dataRegion: (DATA_REGIONS as readonly string[]).includes(region) ? region : "",
    hasFirewallApiKey: read("SOPHOS_FIREWALL_PASSWORD").length > 0,
    hasClientSecret: read("SOPHOS_CLIENT_SECRET").length > 0,
  };
}

export function firewallApiKeyFromEnv(): string {
  return read("SOPHOS_FIREWALL_PASSWORD");
}

export function clientSecretFromEnv(): string {
  return read("SOPHOS_CLIENT_SECRET");
}

export function isDataRegion(value: string): value is DataRegion {
  return (DATA_REGIONS as readonly string[]).includes(value);
}
