export const ENDPOINT_VALUE = /^[-:0-9a-z./]{3,2048}$/;
export const ENDPOINT_COMMENT = /^[-\p{L}\p{Nl}\d ,.']{0,300}$/u;

export type NormalizedSite = {
  value: string | null;
  derived: boolean;
  reason?: string;
};

const HOSTNAME =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function invalid(reason: string): NormalizedSite {
  return { value: null, derived: false, reason };
}

function validIpv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    const n = Number(part);
    return n >= 0 && n <= 255 && String(n) === part;
  });
}

function isCidr(value: string): boolean {
  const pieces = value.split("/");
  if (pieces.length !== 2) return false;
  const [ip, bits] = pieces;
  if (!ip || bits === undefined || !/^\d{1,2}$/.test(bits)) return false;
  const n = Number(bits);
  return validIpv4(ip) && n >= 0 && n <= 32;
}

function isRange(value: string): boolean {
  const pieces = value.split("-");
  if (pieces.length !== 2) return false;
  const [start, end] = pieces;
  return Boolean(start && end && validIpv4(start) && validIpv4(end));
}

function isIpv6(value: string): boolean {
  if (!value.includes(":")) return false;
  if (!/^[:0-9a-f.]+$/.test(value)) return false;
  if (!value.includes("::") && value.split(":").length < 3) return false;
  return true;
}

function isIpv6Cidr(value: string): boolean {
  const pieces = value.split("/");
  if (pieces.length !== 2) return false;
  const [addr, bits] = pieces;
  if (!addr || bits === undefined || !/^\d{1,3}$/.test(bits)) return false;
  const n = Number(bits);
  return isIpv6(addr) && n >= 0 && n <= 128;
}

function isHostname(value: string): boolean {
  return value.length <= 253 && HOSTNAME.test(value);
}

function isAddress(value: string): boolean {
  return isCidr(value) || isRange(value) || validIpv4(value) || isIpv6Cidr(value) || isIpv6(value);
}

/**
 * Turn a firewall URL, regex, domain, or address into a value the Endpoint
 * exclusion API accepts: `^[-:0-9a-z./]{3,2048}$`.
 */
export function toEndpointValue(input: string): NormalizedSite {
  const original = input.trim();
  if (!original) return invalid("Empty value.");

  let derived = false;
  let value = original;

  if (/^https?:\/\//i.test(value)) {
    try {
      const url = new URL(value);
      if (!url.hostname) return invalid("URL has no hostname.");
      value = url.hostname;
      derived = true;
    } catch {
      return invalid("URL could not be parsed.");
    }
  }

  const unescaped = value.replace(/\\\./g, ".").replace(/\\\//g, "/");
  if (unescaped !== value) derived = true;
  value = unescaped;

  if (value.startsWith("^")) {
    value = value.slice(1);
    derived = true;
  }
  if (value.endsWith("$")) {
    value = value.slice(0, -1);
    derived = true;
  }
  if (value.startsWith(".*.") ) {
    value = value.slice(3);
    derived = true;
  } else if (value.startsWith("*.")) {
    value = value.slice(2);
    derived = true;
  } else if (value.startsWith(".*")) {
    value = value.slice(2);
    derived = true;
  }
  if (value.endsWith(".*")) {
    value = value.slice(0, -2);
    derived = true;
  }
  if (value.endsWith(".")) {
    value = value.slice(0, -1);
    derived = true;
  }

  if (/[*()[\]|+?{}\\^$]/.test(value)) {
    const tokens =
      value.match(/[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+/gi) ??
      [];
    const unique = [...new Set(tokens.map((token) => token.toLowerCase()))];
    if (unique.length !== 1) return invalid("Pattern does not name a single website.");
    value = unique[0] ?? "";
    derived = true;
  }

  value = value.toLowerCase();

  if (value.includes("/") && !isCidr(value) && !isIpv6Cidr(value)) {
    const host = value.slice(0, value.indexOf("/"));
    if (host && host !== value) {
      value = host;
      derived = true;
    }
  }

  if (!isAddress(value) && !isHostname(value)) {
    return invalid("Not a domain, IP address, or IP range the Endpoint API accepts.");
  }
  if (!ENDPOINT_VALUE.test(value)) {
    return invalid("Value does not match the Endpoint exclusion pattern.");
  }

  const changed = value !== original.trim().toLowerCase();
  return { value, derived: derived || changed };
}

export function sanitizeComment(text: string): string {
  const cleaned = text.replace(/[^- \p{L}\p{Nl}\d,.']/gu, " ").replace(/\s+/g, " ").trim();
  const clipped = cleaned.slice(0, 300).trim();
  if (clipped && ENDPOINT_COMMENT.test(clipped)) return clipped;
  return "Imported from Sophos Firewall";
}

export function commentForSources(
  sources: { kind: string; ruleName: string }[],
): string {
  const names = [...new Set(sources.map((source) => source.ruleName))].slice(0, 3);
  const hasException = sources.some((source) => source.kind === "web-exception");
  const hasRule = sources.some((source) => source.kind === "ssl-tls-rule");
  const kind =
    hasException && hasRule ? "firewall rules" : hasRule ? "SSL/TLS rule" : "web exception";
  return sanitizeComment(`Imported from ${kind}: ${names.join(", ")}`);
}
