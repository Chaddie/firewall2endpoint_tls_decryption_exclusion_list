# TLS exclusion import

Copies websites that Sophos Firewall skips for HTTPS decryption into the Sophos Endpoint TLS decryption exclusion list.

The browser talks only to this app. Route handlers call the firewall and Sophos Central. Sample data exercises the full review and import path without credentials.

## Run locally

```bash
npm install
cp .env.example .env.local
npm run dev
```

Open http://127.0.0.1:3847.

Leave the env file empty and choose **Sample data**, then **Load sample exclusions**. Select or edit sites and import. Sample mode shows the Endpoint request body and does not call Sophos.

For a live firewall and tenant, fill in `.env.local` or type the values in **Live Sophos**. Secrets stay in the tab and are not written to the repository. If a secret is set only in the environment, leave the field blank and keep “use the server environment” on. The firewall URL can be the appliance origin (`https://firewall.example:4444`) or the API base ending in `/api/firewall-config/v1`.

Certificate checks for the firewall stay on unless you turn on “Trust this firewall's certificate” for an appliance you trust.

## What gets imported

Web exceptions are included when they skip HTTPS decryption and name a URL, domain, or destination address. SSL/TLS rules are included when their action is `doNotDecrypt` and they point at a URL group, FQDN host, or FQDN group. Categories, source-only exceptions, MAC addresses, and rules that still decrypt traffic are listed under “Left out”.

The Endpoint update is `PATCH` with `add` and `remove`. It does not replace the list by itself. **Merge** (the default) only adds sites that are not already excluded. **Replace** also removes current Endpoint exclusions that are not in the selection. The current list is read first. If that read fails, nothing is changed.

## Checks

```bash
npm test
npm run lint
```
