import { toEndpointValue } from "./endpoint-value";
import type {
  Candidate,
  FilteredEntry,
  FirewallSnapshot,
  FqdnHost,
  Reference,
  SiteSource,
  TlsRule,
  WebException,
} from "./types";

type Draft = {
  site: string;
  raw: string;
  valid: boolean;
  derived: boolean;
  invalidReason?: string;
  source: SiteSource;
};

export function extractSnapshot(snapshot: FirewallSnapshot): {
  candidates: Candidate[];
  filtered: FilteredEntry[];
} {
  const drafts: Draft[] = [];
  const filtered: FilteredEntry[] = [];
  for (const exception of snapshot.exceptions) {
    considerException(exception, drafts, filtered);
  }
  for (const rule of snapshot.tlsRules) {
    considerRule(rule, snapshot, drafts, filtered);
  }
  return { candidates: groupDrafts(drafts), filtered };
}

function considerException(exception: WebException, drafts: Draft[], filtered: FilteredEntry[]) {
  if (!exception.skip.httpsDecryption) {
    filtered.push({
      kind: "web-exception",
      ruleName: exception.name,
      raw: exception.name,
      reason: "Exception does not skip HTTPS decryption.",
    });
    return;
  }

  const source = (detail: string): SiteSource => ({
    kind: "web-exception",
    ruleId: exception.id,
    ruleName: exception.name,
    enabled: exception.enabled,
    detail,
  });

  let found = false;
  const conditions = exception.conditions;
  if (conditions.urlRegexPatterns.enabled) {
    for (const value of conditions.urlRegexPatterns.values) {
      found = true;
      pushDraft(drafts, value, source("URL pattern"));
    }
  }
  if (conditions.destinationIpOrNetworks.enabled) {
    for (const network of conditions.destinationIpOrNetworks.ipv4Networks) {
      if (!network.ipv4Address) continue;
      found = true;
      const prefix = network.cidr ?? 32;
      const raw = prefix === 32 ? network.ipv4Address : `${network.ipv4Address}/${prefix}`;
      pushDraft(drafts, raw, source("Destination IP"));
    }
    for (const network of conditions.destinationIpOrNetworks.ipv6Networks) {
      if (!network.ipv6Address) continue;
      found = true;
      const prefix = network.prefixLength ?? 128;
      const raw = prefix === 128 ? network.ipv6Address : `${network.ipv6Address}/${prefix}`;
      pushDraft(drafts, raw, source("Destination IP"));
    }
  }
  if (conditions.webCategories.enabled) {
    for (const category of conditions.webCategories.values) {
      filtered.push({
        kind: "web-exception",
        ruleName: exception.name,
        raw: category.name,
        reason: "Web category is not a website, so it was left out.",
      });
    }
  }

  if (found) return;
  if (conditions.sourceIpOrNetworks.enabled) {
    filtered.push({
      kind: "web-exception",
      ruleName: exception.name,
      raw: exception.name,
      reason: "Exception is limited by source address only, so it has no website to import.",
    });
    return;
  }
  if (!conditions.webCategories.enabled) {
    filtered.push({
      kind: "web-exception",
      ruleName: exception.name,
      raw: exception.name,
      reason: "Exception skips HTTPS decryption without a website, URL, or destination.",
    });
  }
}

function considerRule(rule: TlsRule, snapshot: FirewallSnapshot, drafts: Draft[], filtered: FilteredEntry[]) {
  if (rule.action !== "doNotDecrypt") {
    filtered.push({
      kind: "ssl-tls-rule",
      ruleName: rule.name,
      raw: rule.action,
      reason:
        rule.action === "decrypt"
          ? "Rule decrypts matching traffic, so it is not an exclusion."
          : "Rule does not skip decryption.",
    });
    return;
  }

  const source = (detail: string): SiteSource => ({
    kind: "ssl-tls-rule",
    ruleId: rule.id,
    ruleName: rule.name,
    enabled: rule.enabled,
    detail,
  });

  let found = false;
  const websites = rule.websites;
  if (websites && !isAnySelector(websites)) {
    for (const groupRef of websites.urlGroups ?? []) {
      const group = findByRef(snapshot.urlGroups, groupRef);
      if (!group) {
        filtered.push({
          kind: "ssl-tls-rule",
          ruleName: rule.name,
          raw: groupRef.name,
          reason: `URL group ${groupRef.name} was not found, so its sites could not be read.`,
        });
        continue;
      }
      if (group.urls.length === 0) {
        filtered.push({
          kind: "ssl-tls-rule",
          ruleName: rule.name,
          raw: group.name,
          reason: `URL group ${group.name} has no URL entries.`,
        });
        continue;
      }
      for (const url of group.urls) {
        found = true;
        pushDraft(drafts, url, source(`URL group ${group.name}`));
      }
    }
    for (const category of websites.categories ?? []) {
      filtered.push({
        kind: "ssl-tls-rule",
        ruleName: rule.name,
        raw: category.name,
        reason: "Web category is not a website, so it was left out.",
      });
    }
  }

  const destination = rule.destinationNetworks;
  if (destination && !isAnySelector(destination)) {
    for (const ref of destination.fqdnAddresses ?? []) {
      const host = findHost(snapshot.fqdnHosts, ref);
      if (!host) {
        filtered.push({
          kind: "ssl-tls-rule",
          ruleName: rule.name,
          raw: ref.name,
          reason: `FQDN host ${ref.name} was not found.`,
        });
        continue;
      }
      found = true;
      pushDraft(drafts, host.fqdn, source(`FQDN ${host.name}`));
    }
    for (const ref of destination.fqdnGroups ?? []) {
      const group = findByRef(snapshot.fqdnGroups, ref);
      if (!group) {
        filtered.push({
          kind: "ssl-tls-rule",
          ruleName: rule.name,
          raw: ref.name,
          reason: `FQDN group ${ref.name} was not found.`,
        });
        continue;
      }
      for (const member of group.fqdns) {
        const host = snapshot.fqdnHosts.find((item) => item.name === member.name);
        if (!host) {
          filtered.push({
            kind: "ssl-tls-rule",
            ruleName: rule.name,
            raw: member.name,
            reason: `FQDN group ${group.name} names ${member.name}, which has no domain.`,
          });
          continue;
        }
        found = true;
        pushDraft(drafts, host.fqdn, source(`FQDN group ${group.name}`));
      }
    }
    for (const mac of destination.macAddresses ?? []) {
      filtered.push({
        kind: "ssl-tls-rule",
        ruleName: rule.name,
        raw: mac.name,
        reason: "MAC address is not a website.",
      });
    }
  }

  if (!found) {
    filtered.push({
      kind: "ssl-tls-rule",
      ruleName: rule.name,
      raw: rule.name,
      reason: "Rule skips decryption without a specific website, URL group, or domain.",
    });
  }
}

function pushDraft(drafts: Draft[], raw: string, source: SiteSource) {
  const normalized = toEndpointValue(raw);
  drafts.push({
    site: normalized.value ?? raw.trim(),
    raw,
    valid: Boolean(normalized.value),
    derived: normalized.derived,
    invalidReason: normalized.reason,
    source,
  });
}

function groupDrafts(drafts: Draft[]): Candidate[] {
  const grouped = new Map<string, Candidate>();
  for (const draft of drafts) {
    const key = draft.valid ? `v:${draft.site}` : `i:${draft.raw}`;
    const existing = grouped.get(key);
    if (!existing) {
      grouped.set(key, {
        id: crypto.randomUUID(),
        site: draft.valid ? draft.site : draft.raw,
        rawValues: [draft.raw],
        sources: [draft.source],
        selected: false,
        valid: draft.valid,
        derived: draft.derived,
        invalidReason: draft.invalidReason,
      });
      continue;
    }
    existing.sources.push(draft.source);
    if (!existing.rawValues.includes(draft.raw)) existing.rawValues.push(draft.raw);
    existing.derived = existing.derived || draft.derived;
  }

  const candidates = [...grouped.values()].map(annotate);
  candidates.sort((a, b) => {
    if (a.selected !== b.selected) return a.selected ? -1 : 1;
    if (a.valid !== b.valid) return a.valid ? -1 : 1;
    return a.site.localeCompare(b.site);
  });
  return candidates;
}

function annotate(candidate: Candidate): Candidate {
  const enabled = candidate.sources.some((source) => source.enabled);
  const notes: string[] = [];
  if (!candidate.valid && candidate.invalidReason) notes.push(candidate.invalidReason);
  if (!enabled) notes.push("Disabled on the firewall. Left unselected.");
  if (candidate.derived) {
    const raw = candidate.rawValues.find((value) => value !== candidate.site) ?? candidate.rawValues[0];
    notes.push(
      `Adjusted from ${raw}. Endpoint exclusions are a domain, IP, or range, with no wildcard.`,
    );
  }
  return {
    ...candidate,
    selected: candidate.valid && enabled,
    note: notes.join(" ") || undefined,
  };
}

function isAnySelector(value: { any: true } | object): value is { any: true } {
  return "any" in value && value.any === true;
}

function findByRef<T extends { id: string; name: string }>(items: T[], ref: Reference): T | undefined {
  return items.find((item) => (ref.id && item.id === ref.id) || item.name === ref.name);
}

function findHost(items: FqdnHost[], ref: Reference): FqdnHost | undefined {
  return findByRef(items, ref);
}
