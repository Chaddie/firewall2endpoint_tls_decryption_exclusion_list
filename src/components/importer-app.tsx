"use client";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Loader2, Search } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { toEndpointValue } from "@/lib/endpoint-value";
import { batchPlan, planImport } from "@/lib/plan-import";
import type { Candidate, ExclusionLoad, ImportMode, ImportResult } from "@/lib/types";
import { DATA_REGIONS as REGIONS } from "@/lib/types";

type Defaults = {
  firewallUrl: string;
  firewallUser: string;
  clientId: string;
  tenantId: string;
  dataRegion: string;
  hasFirewallApiKey: boolean;
  hasClientSecret: boolean;
};

type FormState = {
  mode: "sample" | "live";
  firewallUrl: string;
  firewallUser: string;
  firewallApiKey: string;
  useEnvFirewallKey: boolean;
  allowInsecureTls: boolean;
  clientId: string;
  clientSecret: string;
  useEnvClientSecret: boolean;
  tenantId: string;
  dataRegion: string;
};

const emptyForm: FormState = {
  mode: "sample",
  firewallUrl: "",
  firewallUser: "",
  firewallApiKey: "",
  useEnvFirewallKey: false,
  allowInsecureTls: false,
  clientId: "",
  clientSecret: "",
  useEnvClientSecret: false,
  tenantId: "",
  dataRegion: "",
};

export function ImporterApp() {
  const [form, setForm] = useState<FormState>(emptyForm);
  const [defaults, setDefaults] = useState<Defaults | null>(null);
  const [load, setLoad] = useState<ExclusionLoad | null>(null);
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [query, setQuery] = useState("");
  const [importMode, setImportMode] = useState<ImportMode>("merge");
  const [loading, setLoading] = useState(false);
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [confirmReplace, setConfirmReplace] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/defaults")
      .then((response) => response.json())
      .then((data: Defaults) => {
        if (cancelled) return;
        setDefaults(data);
        setForm((current) => ({
          ...current,
          firewallUrl: data.firewallUrl || current.firewallUrl,
          firewallUser: data.firewallUser || current.firewallUser,
          clientId: data.clientId || current.clientId,
          tenantId: data.tenantId || current.tenantId,
          dataRegion: data.dataRegion || current.dataRegion,
          useEnvFirewallKey: data.hasFirewallApiKey,
          useEnvClientSecret: data.hasClientSecret,
          mode: data.firewallUrl ? "live" : current.mode,
        }));
      })
      .catch(() => {
        if (!cancelled) setDefaults(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return candidates;
    return candidates.filter((candidate) => {
      const haystack = [
        candidate.site,
        candidate.note ?? "",
        ...candidate.rawValues,
        ...candidate.sources.flatMap((source) => [source.ruleName, source.detail, source.kind]),
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(needle);
    });
  }, [candidates, query]);

  const plan = load?.endpointSites
    ? planImport({
        candidates,
        existing: load.endpointSites,
        mode: importMode,
        operator: form.firewallUser,
      })
    : null;
  const payloads = plan ? batchPlan(plan) : null;

  const selectedCount = candidates.filter((candidate) => candidate.selected && candidate.valid).length;

  async function loadExclusions() {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const response = await fetch("/api/exclusions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form.mode === "sample" ? { mode: "sample" } : form),
      });
      const data = (await response.json()) as ExclusionLoad & { error?: string };
      if (!response.ok) throw new Error(data.error || "The firewall lists could not be read.");
      setLoad(data);
      setCandidates(data.candidates);
      setQuery("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The firewall lists could not be read.");
    } finally {
      setLoading(false);
    }
  }

  async function runImport() {
    setImporting(true);
    setError(null);
    setConfirmReplace(false);
    try {
      const response = await fetch("/api/import", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(
          form.mode === "sample"
            ? { mode: "sample", importMode, candidates, firewallUser: form.firewallUser }
            : {
                mode: form.mode,
                importMode,
                candidates,
                firewallUser: form.firewallUser,
                clientId: form.clientId,
                clientSecret: form.clientSecret,
                useEnvClientSecret: form.useEnvClientSecret,
                tenantId: form.tenantId,
                dataRegion: form.dataRegion,
              },
        ),
      });
      const data = (await response.json()) as ImportResult & { error?: string };
      if (!response.ok) throw new Error(data.error || "The Endpoint update failed.");
      setResult(data);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The Endpoint update failed.");
    } finally {
      setImporting(false);
    }
  }

  function updateCandidate(id: string, patch: Partial<Candidate>) {
    setCandidates((current) => current.map((candidate) => (candidate.id === id ? { ...candidate, ...patch } : candidate)));
  }

  function dedupe() {
    setCandidates((current) => {
      const grouped = new Map<string, Candidate>();
      const leftovers: Candidate[] = [];
      for (const candidate of current) {
        const normalized = toEndpointValue(candidate.site);
        if (!normalized.value) {
          leftovers.push(candidate);
          continue;
        }
        const existing = grouped.get(normalized.value);
        if (!existing) {
          grouped.set(normalized.value, { ...candidate, site: normalized.value, valid: true, invalidReason: undefined });
          continue;
        }
        existing.sources = [...existing.sources, ...candidate.sources];
        existing.rawValues = [...new Set([...existing.rawValues, ...candidate.rawValues, candidate.site])];
        existing.selected = existing.selected || candidate.selected;
        existing.derived = existing.derived || candidate.derived;
      }
      return [...grouped.values(), ...leftovers];
    });
  }

  function setVisibleSelection(selected: boolean) {
    const ids = new Set(visible.filter((candidate) => candidate.valid).map((candidate) => candidate.id));
    setCandidates((current) =>
      current.map((candidate) => (ids.has(candidate.id) ? { ...candidate, selected } : candidate)),
    );
  }

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6 px-4 py-6 sm:py-10">
      <header className="flex flex-col gap-3">
        <p className="text-sm font-medium tracking-wide text-primary">Sophos Firewall to Endpoint</p>
        <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">TLS decryption exclusion import</h1>
        <p className="max-w-3xl text-base text-muted-foreground">
          Read websites that Sophos Firewall skips for HTTPS decryption, review them, and add the ones you keep
          to the Sophos Endpoint excluded-websites list.
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Connection</CardTitle>
          <CardDescription>
            Sample data walks the whole path with no credentials. Live mode calls Sophos from this server, so the
            browser never talks to the firewall or Central directly. Keys stay in this tab and are cleared on reload.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-6">
          <div className="grid grid-cols-2 gap-2 rounded-xl bg-muted p-1 sm:max-w-md">
            <Button
              type="button"
              variant={form.mode === "sample" ? "default" : "ghost"}
              onClick={() => setForm({ ...form, mode: "sample" })}
            >
              Sample data
            </Button>
            <Button
              type="button"
              variant={form.mode === "live" ? "default" : "ghost"}
              onClick={() => setForm({ ...form, mode: "live" })}
            >
              Live Sophos
            </Button>
          </div>

          {form.mode === "sample" ? (
            <Alert>
              <AlertTitle>Sample data</AlertTitle>
              <AlertDescription>
                A few web exceptions and SSL/TLS rules, including overlaps, a category, a source-only exception,
                and a decrypt rule. Import shows the payload that would be sent and does not call Sophos.
              </AlertDescription>
            </Alert>
          ) : (
            <div className="grid gap-6 lg:grid-cols-2">
              <fieldset className="flex flex-col gap-4">
                <legend className="text-sm font-medium">Firewall</legend>
                <Field label="Base URL" id="firewall-url">
                  <Input
                    id="firewall-url"
                    value={form.firewallUrl}
                    placeholder="https://firewall.example:4444"
                    autoComplete="off"
                    onChange={(event) => setForm({ ...form, firewallUrl: event.target.value })}
                  />
                </Field>
                <Field label="API user" id="firewall-user" hint="Recorded on the import comment. The configuration API authenticates with the key below.">
                  <Input
                    id="firewall-user"
                    value={form.firewallUser}
                    autoComplete="off"
                    onChange={(event) => setForm({ ...form, firewallUser: event.target.value })}
                  />
                </Field>
                <Field
                  label="API key"
                  id="firewall-key"
                  hint="Bearer token from Administration, API access. Environment name: SOPHOS_FIREWALL_PASSWORD."
                >
                  <Input
                    id="firewall-key"
                    type="password"
                    value={form.firewallApiKey}
                    autoComplete="off"
                    placeholder={defaults?.hasFirewallApiKey ? "Using the server environment unless you type a key" : ""}
                    onChange={(event) => setForm({ ...form, firewallApiKey: event.target.value })}
                  />
                </Field>
                {defaults?.hasFirewallApiKey ? (
                  <Toggle
                    id="use-env-key"
                    label="Use the API key from the server environment when the field is empty"
                    checked={form.useEnvFirewallKey}
                    onCheckedChange={(checked) => setForm({ ...form, useEnvFirewallKey: checked })}
                  />
                ) : null}
                <Toggle
                  id="insecure-tls"
                  label="Trust this firewall's certificate"
                  checked={form.allowInsecureTls}
                  onCheckedChange={(checked) => setForm({ ...form, allowInsecureTls: checked })}
                />
                <p className="text-xs text-muted-foreground">
                  Certificate checks stay on unless you turn this on for an appliance you trust.
                </p>
              </fieldset>

              <fieldset className="flex flex-col gap-4">
                <legend className="text-sm font-medium">Sophos Central</legend>
                <Field label="Client ID" id="client-id">
                  <Input
                    id="client-id"
                    value={form.clientId}
                    autoComplete="off"
                    onChange={(event) => setForm({ ...form, clientId: event.target.value })}
                  />
                </Field>
                <Field label="Client secret" id="client-secret" hint="Environment name: SOPHOS_CLIENT_SECRET.">
                  <Input
                    id="client-secret"
                    type="password"
                    value={form.clientSecret}
                    autoComplete="off"
                    placeholder={defaults?.hasClientSecret ? "Using the server environment unless you type a secret" : ""}
                    onChange={(event) => setForm({ ...form, clientSecret: event.target.value })}
                  />
                </Field>
                {defaults?.hasClientSecret ? (
                  <Toggle
                    id="use-env-secret"
                    label="Use the client secret from the server environment when the field is empty"
                    checked={form.useEnvClientSecret}
                    onCheckedChange={(checked) => setForm({ ...form, useEnvClientSecret: checked })}
                  />
                ) : null}
                <Field label="Tenant ID" id="tenant-id" hint="Leave blank to use the tenant returned by Who am I.">
                  <Input
                    id="tenant-id"
                    value={form.tenantId}
                    autoComplete="off"
                    onChange={(event) => setForm({ ...form, tenantId: event.target.value })}
                  />
                </Field>
                <Field label="Data region" id="data-region" hint="Leave on automatic to use the data region from Who am I.">
                  <select
                    id="data-region"
                    className="h-9 w-full rounded-lg border border-input bg-background px-3 text-sm"
                    value={form.dataRegion}
                    onChange={(event) => setForm({ ...form, dataRegion: event.target.value })}
                  >
                    <option value="">Automatic from Who am I</option>
                    {REGIONS.map((region) => (
                      <option key={region} value={region}>
                        {region}
                      </option>
                    ))}
                  </select>
                </Field>
              </fieldset>
            </div>
          )}

          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <Button type="button" size="lg" onClick={loadExclusions} disabled={loading}>
              {loading ? <Loader2 className="animate-spin" /> : null}
              {loading ? "Reading exclusions" : form.mode === "sample" ? "Load sample exclusions" : "Load firewall exclusions"}
            </Button>
            {load ? (
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setLoad(null);
                  setCandidates([]);
                  setResult(null);
                  setError(null);
                }}
              >
                Clear results
              </Button>
            ) : null}
          </div>
        </CardContent>
      </Card>

      {error ? (
        <Alert variant="destructive">
          <AlertTitle>Something needs attention</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      {!load && !loading ? (
        <Card>
          <CardHeader>
            <CardTitle>Nothing loaded yet</CardTitle>
            <CardDescription>
              Load sample data to review overlapping banking sites, or connect to a firewall. Web categories, source
              addresses, MAC addresses, and rules that still decrypt traffic are left out of the import list.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3 text-sm text-muted-foreground sm:grid-cols-3">
            <Step n="1" title="Read the firewall" body="Web exceptions and SSL/TLS inspection rules." />
            <Step n="2" title="Review the sites" body="Search, edit, drop, and dedupe before anything is sent." />
            <Step n="3" title="Update Endpoint" body="Merge adds sites. Replace also removes ones you did not keep." />
          </CardContent>
        </Card>
      ) : null}

      {loading ? (
        <Card>
          <CardHeader>
            <CardTitle>Reading firewall exclusions</CardTitle>
            <CardDescription>
              Web exceptions, SSL/TLS inspection rules, and the URL groups or domains those rules point at.
            </CardDescription>
          </CardHeader>
        </Card>
      ) : null}

      {load ? (
        <>
          <section className="flex flex-col gap-3">
            {load.sample ? (
              <Alert>
                <AlertTitle>Sample data</AlertTitle>
                <AlertDescription>
                  These rules are fixtures. The Endpoint list in this preview already contains
                  login.microsoftonline.com, 10.50.100.100, and calendar.corp.example.
                </AlertDescription>
              </Alert>
            ) : (
              <Alert>
                <AlertTitle>Loaded from the firewall</AlertTitle>
                <AlertDescription>
                  {load.summary.webExceptions} web exceptions and {load.summary.tlsRules} SSL/TLS rules.
                  {load.endpointWarning
                    ? ` The current Endpoint list was not read: ${load.endpointWarning}`
                    : load.endpointSites
                      ? ` ${load.endpointSites.length} sites are already excluded on Endpoint.`
                      : " Add Central credentials and load again to compare with the current Endpoint list."}
                </AlertDescription>
              </Alert>
            )}
            <div className="flex flex-wrap gap-2 text-sm">
              <Badge variant="secondary">{candidates.length} sites</Badge>
              <Badge variant="secondary">{selectedCount} selected</Badge>
              <Badge variant="outline">{load.filtered.length} left out</Badge>
            </div>
          </section>

          <Card>
            <CardHeader>
              <CardTitle>Review</CardTitle>
              <CardDescription>
                The same website from a web exception and an SSL/TLS rule is one row. Edit a site before import, or
                remove it. Values that are not a domain, IP, or range stay unselected.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
                <div className="relative flex-1">
                  <Search className="pointer-events-none absolute top-2.5 left-3 size-4 text-muted-foreground" />
                  <Input
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    placeholder="Search sites, rules, or raw values"
                    className="pl-9"
                    aria-label="Search sites"
                  />
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button type="button" variant="outline" size="sm" onClick={() => setVisibleSelection(true)}>
                    Select visible
                  </Button>
                  <Button type="button" variant="outline" size="sm" onClick={() => setVisibleSelection(false)}>
                    Clear visible
                  </Button>
                  <Button type="button" variant="outline" size="sm" onClick={dedupe}>
                    Dedupe
                  </Button>
                </div>
              </div>

              {visible.length === 0 ? (
                <p className="rounded-lg border border-dashed px-4 py-8 text-center text-sm text-muted-foreground">
                  No sites match that search.
                </p>
              ) : (
                <>
                  <div className="hidden md:block">
                    <table className="w-full text-sm">
                      <thead className="border-b text-left text-muted-foreground">
                        <tr>
                          <th className="w-10 py-2 pr-2"> </th>
                          <th className="py-2 pr-3 font-medium">Site</th>
                          <th className="py-2 pr-3 font-medium">Source</th>
                          <th className="py-2 font-medium">Raw value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {visible.map((candidate) => (
                          <tr key={candidate.id} className="border-b align-top">
                            <td className="py-3 pr-2">
                              <Checkbox
                                checked={candidate.selected}
                                disabled={!candidate.valid}
                                onCheckedChange={(checked) =>
                                  updateCandidate(candidate.id, { selected: checked === true })
                                }
                                aria-label={`Select ${candidate.site}`}
                              />
                            </td>
                            <td className="py-3 pr-3">
                              <SiteEditor
                                candidate={candidate}
                                onSite={(site) => updateCandidate(candidate.id, { site })}
                                onBlurNormalize={(value) => {
                                  const normalized = toEndpointValue(value);
                                  updateCandidate(candidate.id, {
                                    site: normalized.value ?? value,
                                    valid: Boolean(normalized.value),
                                    derived: normalized.derived,
                                    invalidReason: normalized.reason,
                                    selected: Boolean(normalized.value) && candidate.selected,
                                  });
                                }}
                                onRemove={() => setCandidates((current) => current.filter((item) => item.id !== candidate.id))}
                              />
                            </td>
                            <td className="py-3 pr-3">
                              <SourceList candidate={candidate} />
                            </td>
                            <td className="py-3 font-mono text-xs break-all text-muted-foreground">
                              {candidate.rawValues.join(", ")}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="flex flex-col gap-3 md:hidden">
                    {visible.map((candidate) => (
                      <article key={candidate.id} className="rounded-xl border p-3">
                        <div className="mb-3 flex items-start gap-3">
                          <Checkbox
                            checked={candidate.selected}
                            disabled={!candidate.valid}
                            onCheckedChange={(checked) => updateCandidate(candidate.id, { selected: checked === true })}
                            aria-label={`Select ${candidate.site}`}
                          />
                          <div className="min-w-0 flex-1">
                            <SiteEditor
                              candidate={candidate}
                              onSite={(site) => updateCandidate(candidate.id, { site })}
                              onBlurNormalize={(value) => {
                                const normalized = toEndpointValue(value);
                                updateCandidate(candidate.id, {
                                  site: normalized.value ?? value,
                                  valid: Boolean(normalized.value),
                                  derived: normalized.derived,
                                  invalidReason: normalized.reason,
                                  selected: Boolean(normalized.value) && candidate.selected,
                                });
                              }}
                              onRemove={() =>
                                setCandidates((current) => current.filter((item) => item.id !== candidate.id))
                              }
                            />
                          </div>
                        </div>
                        <SourceList candidate={candidate} />
                        <p className="mt-2 font-mono text-xs break-all text-muted-foreground">
                          {candidate.rawValues.join(", ")}
                        </p>
                      </article>
                    ))}
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          {load.filtered.length > 0 ? (
            <details className="rounded-xl border px-4 py-3">
              <summary className="cursor-pointer text-sm font-medium">
                Left out ({load.filtered.length})
              </summary>
              <ul className="mt-3 flex flex-col gap-2 text-sm text-muted-foreground">
                {load.filtered.map((entry, index) => (
                  <li key={`${entry.ruleName}-${entry.raw}-${index}`}>
                    <span className="text-foreground">{entry.ruleName}</span>
                    {entry.raw !== entry.ruleName ? ` · ${entry.raw}` : ""} — {entry.reason}
                  </li>
                ))}
              </ul>
            </details>
          ) : null}

          <Card>
            <CardHeader>
              <CardTitle>Import to Endpoint</CardTitle>
              <CardDescription>
                The update is a PATCH that adds and removes websites. It does not replace the list on its own.
                Merge, the default, only adds sites that are not already there. Replace also removes current
                Endpoint exclusions that are not in your selection.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <div className="grid grid-cols-2 gap-2 rounded-xl bg-muted p-1 sm:max-w-md">
                <Button type="button" variant={importMode === "merge" ? "default" : "ghost"} onClick={() => setImportMode("merge")}>
                  Merge
                </Button>
                <Button
                  type="button"
                  variant={importMode === "replace" ? "destructive" : "ghost"}
                  onClick={() => setImportMode("replace")}
                >
                  Replace
                </Button>
              </div>

              {load.endpointSites ? (
                <div>
                  <p className="mb-2 text-sm font-medium">Already on Endpoint</p>
                  <ul className="flex flex-col gap-1 font-mono text-xs">
                    {load.endpointSites.map((site) => (
                      <li key={site.value}>{site.value}</li>
                    ))}
                  </ul>
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">
                  The current Endpoint list is not loaded yet. A live import reads it before sending, and stops if
                  that read fails, so a merge cannot wipe sites that are already there.
                </p>
              )}

              <div>
                <p className="mb-2 text-sm font-medium">Payload</p>
                <pre className="overflow-x-auto rounded-lg bg-muted p-3 text-xs">
                  {JSON.stringify(
                    payloads ?? {
                      note: "Endpoint list not loaded. The server builds this payload after reading the current exclusions.",
                    },
                    null,
                    2,
                  )}
                </pre>
                {plan ? (
                  <p className="text-xs text-muted-foreground">
                    {plan.add.length} to add, {plan.alreadyPresent.length} already present, {plan.remove.length} to
                    remove, {plan.skipped.length} skipped.
                  </p>
                ) : null}
              </div>

              <div className="flex flex-col gap-2 sm:flex-row">
                {importMode === "merge" ? (
                  <Button type="button" size="lg" onClick={runImport} disabled={importing || selectedCount === 0}>
                    {importing ? <Loader2 className="animate-spin" /> : null}
                    Add selected sites
                  </Button>
                ) : (
                  <Button
                    type="button"
                    size="lg"
                    variant="destructive"
                    onClick={() => setConfirmReplace(true)}
                    disabled={importing || (selectedCount === 0 && (load.endpointSites?.length ?? 0) === 0)}
                  >
                    Replace Endpoint list
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>

          {result ? <ResultPanel result={result} /> : null}
        </>
      ) : null}

      <Dialog open={confirmReplace} onOpenChange={setConfirmReplace}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Replace the Endpoint exclusion list?</DialogTitle>
            <DialogDescription>
              Sites already on Endpoint that you did not select will be removed. Sophos applies that as a removal
              list plus the sites you are adding. Merge is the safer update if you only want to add firewall sites.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setConfirmReplace(false)}>
              Keep the current list
            </Button>
            <Button type="button" variant="destructive" onClick={runImport} disabled={importing}>
              Remove the others and add the selection
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function ResultPanel({ result }: { result: ImportResult }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{result.sample ? "Sample result" : "Endpoint result"}</CardTitle>
        <CardDescription>
          {result.sample
            ? "Nothing was sent to Sophos. This is the payload and the outcome the live call would report."
            : result.importMode === "replace"
              ? "Replace sent additions and removals."
              : "Merge sent additions only."}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4 text-sm">
        <div className="flex flex-wrap gap-2">
          <Badge>{result.added.length} added</Badge>
          <Badge variant="secondary">{result.alreadyPresent.length} already present</Badge>
          <Badge variant="outline">{result.removed.length} removed</Badge>
          <Badge variant="outline">{result.skipped.length} skipped</Badge>
        </div>
        {result.errors.length > 0 ? (
          <Alert variant="destructive">
            <AlertTitle>Endpoint returned an error</AlertTitle>
            <AlertDescription>{result.errors.map((item) => item.message).join(" ")}</AlertDescription>
          </Alert>
        ) : null}
        <ResultList title="Added" values={result.added.map((site) => site.value)} />
        <ResultList title="Already present" values={result.alreadyPresent} />
        <ResultList title="Removed" values={result.removed.map((site) => site.value)} />
        {result.skipped.length > 0 ? (
          <div>
            <p className="font-medium">Skipped</p>
            <ul className="mt-1 text-muted-foreground">
              {result.skipped.map((item) => (
                <li key={item.value}>
                  {item.value}: {item.reason}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        <Separator />
        <div>
          <p className="mb-2 font-medium">Request body</p>
          <pre className="overflow-x-auto rounded-lg bg-muted p-3 text-xs">{JSON.stringify(result.payloads, null, 2)}</pre>
        </div>
      </CardContent>
    </Card>
  );
}

function ResultList({ title, values }: { title: string; values: string[] }) {
  if (values.length === 0) return null;
  return (
    <div>
      <p className="font-medium">{title}</p>
      <ul className="mt-1 font-mono text-xs">
        {values.map((value) => (
          <li key={value}>{value}</li>
        ))}
      </ul>
    </div>
  );
}

function SiteEditor({
  candidate,
  onSite,
  onBlurNormalize,
  onRemove,
}: {
  candidate: Candidate;
  onSite: (site: string) => void;
  onBlurNormalize: (value: string) => void;
  onRemove: () => void;
}) {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-col gap-2 sm:flex-row">
        <Input
          value={candidate.site}
          aria-label={`Site ${candidate.site}`}
          onChange={(event) => onSite(event.target.value)}
          onBlur={(event) => onBlurNormalize(event.target.value)}
          className="font-mono"
        />
        <Button type="button" variant="ghost" size="sm" onClick={onRemove}>
          Remove
        </Button>
      </div>
      <div className="flex flex-wrap gap-1">
        {!candidate.valid ? <Badge variant="destructive">Needs a fix</Badge> : null}
        {candidate.derived ? <Badge variant="outline">Adjusted</Badge> : null}
        {!candidate.sources.some((source) => source.enabled) ? <Badge variant="outline">Disabled rule</Badge> : null}
      </div>
      {candidate.note ? <p className="text-xs text-muted-foreground">{candidate.note}</p> : null}
    </div>
  );
}

function SourceList({ candidate }: { candidate: Candidate }) {
  return (
    <ul className="flex flex-col gap-1">
      {candidate.sources.map((source, index) => (
        <li key={`${source.ruleId}-${source.detail}-${index}`} className="text-xs">
          <Badge variant="secondary" className="mr-1">
            {source.kind === "web-exception" ? "Web exception" : "SSL/TLS rule"}
          </Badge>
          <span className="font-medium">{source.ruleName}</span>
          <span className="text-muted-foreground"> · {source.detail}</span>
        </li>
      ))}
    </ul>
  );
}

function Field({
  id,
  label,
  hint,
  children,
}: {
  id: string;
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      {children}
      {hint ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
    </div>
  );
}

function Toggle({
  id,
  label,
  checked,
  onCheckedChange,
}: {
  id: string;
  label: string;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
}) {
  return (
    <div className="flex items-center gap-3">
      <Switch id={id} checked={checked} onCheckedChange={onCheckedChange} />
      <Label htmlFor={id} className="font-normal">
        {label}
      </Label>
    </div>
  );
}

function Step({ n, title, body }: { n: string; title: string; body: string }) {
  return (
    <div className="rounded-lg border bg-card p-3">
      <p className="text-xs font-medium text-primary">Step {n}</p>
      <p className="mt-1 font-medium text-foreground">{title}</p>
      <p className="mt-1">{body}</p>
    </div>
  );
}
