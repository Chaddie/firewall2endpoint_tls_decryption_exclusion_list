import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";

import { HttpError } from "./http-error";

const blocked = new BlockList();
blocked.addSubnet("0.0.0.0", 8, "ipv4");
blocked.addSubnet("127.0.0.0", 8, "ipv4");
blocked.addSubnet("169.254.0.0", 16, "ipv4");
blocked.addSubnet("224.0.0.0", 4, "ipv4");
blocked.addAddress("255.255.255.255", "ipv4");
blocked.addAddress("::", "ipv6");
blocked.addAddress("::1", "ipv6");
blocked.addSubnet("fe80::", 10, "ipv6");
blocked.addSubnet("ff00::", 8, "ipv6");

const BLOCKED_HOSTS = new Set([
  "localhost",
  "localhost.localdomain",
  "metadata.google.internal",
  "metadata.internal",
]);

export type FirewallTarget = {
  origin: string;
  apiBase: string;
};

export async function resolveFirewallTarget(input: string): Promise<FirewallTarget> {
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    throw new HttpError(400, "Firewall URL is not valid.");
  }
  if (url.protocol !== "https:") {
    throw new HttpError(400, "Firewall URL must use HTTPS.");
  }
  if (url.username || url.password) {
    throw new HttpError(400, "Put the API key in the API key field, not in the URL.");
  }

  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!host || BLOCKED_HOSTS.has(host) || host.endsWith(".localhost") || host.endsWith(".local")) {
    throw new HttpError(400, "That firewall host is not allowed.");
  }

  if (isIP(host)) {
    assertAllowedIp(host);
  } else {
    let records: { address: string }[];
    try {
      records = await lookup(host, { all: true, verbatim: true });
    } catch {
      throw new HttpError(400, "Could not resolve the firewall hostname.");
    }
    if (records.length === 0) {
      throw new HttpError(400, "Could not resolve the firewall hostname.");
    }
    for (const record of records) assertAllowedIp(record.address);
  }

  const pathname = url.pathname.replace(/\/+$/, "");
  let apiPath = "/api/firewall-config/v1";
  if (pathname === "/api/firewall-config/v1") {
    apiPath = pathname;
  } else if (pathname !== "") {
    throw new HttpError(
      400,
      "Use the firewall origin, such as https://firewall.example:4444, or the API base ending in /api/firewall-config/v1.",
    );
  }

  return {
    origin: url.origin,
    apiBase: `${url.origin}${apiPath}`,
  };
}

function assertAllowedIp(address: string) {
  const mapped = address.toLowerCase().startsWith("::ffff:") ? address.slice(7) : address;
  const family = isIP(mapped);
  if (family === 0) throw new HttpError(400, "Could not read the firewall address.");
  const type = family === 4 ? "ipv4" : "ipv6";
  if (blocked.check(mapped, type)) {
    throw new HttpError(400, "That firewall address is not allowed.");
  }
}
