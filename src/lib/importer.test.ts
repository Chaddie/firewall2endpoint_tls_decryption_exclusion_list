import assert from "node:assert/strict";
import test from "node:test";

import { toEndpointValue } from "./endpoint-value";
import { extractSnapshot } from "./extract";
import { sampleEndpointSites, sampleSnapshot } from "./fixtures";
import { planImport } from "./plan-import";
import { resolveFirewallTarget } from "./safe-firewall";

test("normalizes firewall patterns to Endpoint website values", () => {
  assert.deepEqual(toEndpointValue("login.microsoftonline.com"), {
    value: "login.microsoftonline.com",
    derived: false,
  });
  assert.equal(toEndpointValue(".*\\.office\\.com").value, "office.com");
  assert.equal(toEndpointValue(".*\\.office\\.com").derived, true);
  assert.equal(toEndpointValue("https://intranet.corp.example/payroll").value, "intranet.corp.example");
  assert.equal(toEndpointValue("10.20.30.0/24").value, "10.20.30.0/24");
  assert.equal(toEndpointValue("not_a_domain").value, null);
  assert.equal(toEndpointValue("^/healthcheck$").value, null);
  assert.equal(toEndpointValue("Finance").value, null);
});

test("sample firewall data keeps websites and drops everything else", () => {
  const { candidates, filtered } = extractSnapshot(sampleSnapshot());
  const bySite = new Map(candidates.map((candidate) => [candidate.site, candidate]));

  const bank = bySite.get("online.bank.example");
  assert.ok(bank);
  assert.equal(bank.selected, true);
  assert.equal(bank.sources.length, 2);
  assert.ok(bank.sources.some((source) => source.kind === "web-exception"));
  assert.ok(bank.sources.some((source) => source.kind === "ssl-tls-rule"));

  assert.equal(bySite.get("login.microsoftonline.com")?.selected, true);
  assert.equal(bySite.get("office.com")?.derived, true);
  assert.equal(bySite.get("partner.example.net")?.sources.length, 2);
  assert.equal(bySite.get("status.vendor.example")?.sources[0]?.detail, "FQDN group Vendor SaaS");
  assert.equal(bySite.get("lab.corp.example")?.selected, false);
  assert.equal(bySite.get("not_a_domain")?.valid, false);
  assert.equal(bySite.has("news.example"), false);
  assert.equal(bySite.has("updates.vendor.example"), false);

  const reasons = filtered.map((entry) => entry.reason).join(" ");
  assert.match(reasons, /does not skip HTTPS decryption/);
  assert.match(reasons, /Web category/);
  assert.match(reasons, /source address/);
  assert.match(reasons, /decrypts matching traffic/);
  assert.match(reasons, /MAC address/);
  assert.match(reasons, /without a specific website/);
});

test("firewall URL rejects loopback, metadata, and non-HTTPS", async () => {
  await assert.rejects(() => resolveFirewallTarget("http://firewall.example:4444"), /HTTPS/);
  await assert.rejects(() => resolveFirewallTarget("https://127.0.0.1:4444"), /not allowed/);
  await assert.rejects(() => resolveFirewallTarget("https://169.254.169.254"), /not allowed/);
  await assert.rejects(() => resolveFirewallTarget("https://user:secret@firewall.example"), /API key/);
});

test("merge adds missing sites and replace also removes Endpoint-only sites", () => {
  const { candidates } = extractSnapshot(sampleSnapshot());
  const existing = sampleEndpointSites();
  const merge = planImport({ candidates, existing, mode: "merge" });
  assert.equal(merge.remove.length, 0);
  assert.ok(merge.alreadyPresent.includes("login.microsoftonline.com"));
  assert.ok(merge.alreadyPresent.includes("10.50.100.100"));
  assert.ok(merge.add.some((site) => site.value === "office.com"));
  assert.equal(merge.add.some((site) => site.value === "login.microsoftonline.com"), false);

  const replace = planImport({ candidates, existing, mode: "replace" });
  assert.deepEqual(
    replace.remove.map((site) => site.value),
    ["calendar.corp.example"],
  );
});
