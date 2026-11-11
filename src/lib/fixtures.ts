import type { EndpointSite, FirewallSnapshot } from "./types";

/**
 * Realistic firewall objects, including overlaps and entries that are not
 * websites. Labeled as sample data in the UI. Nothing here is a credential.
 */
export function sampleSnapshot(): FirewallSnapshot {
  return {
    exceptions: [
      {
        id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
        name: "Online banking bypass",
        enabled: true,
        skip: { httpsDecryption: true },
        conditions: {
          sourceIpOrNetworks: { enabled: false },
          destinationIpOrNetworks: {
            enabled: false,
            ipv4Networks: [],
            ipv6Networks: [],
          },
          urlRegexPatterns: {
            enabled: true,
            values: [
              ".*\\.online\\.bank\\.example",
              "https://intranet.corp.example/payroll",
            ],
          },
          webCategories: { enabled: false, values: [] },
        },
      },
      {
        id: "a3bb189e-8bf9-3888-9912-ace4e6543002",
        name: "Microsoft 365 decrypt skip",
        enabled: true,
        skip: { httpsDecryption: true },
        conditions: {
          sourceIpOrNetworks: { enabled: false },
          destinationIpOrNetworks: {
            enabled: false,
            ipv4Networks: [],
            ipv6Networks: [],
          },
          urlRegexPatterns: {
            enabled: true,
            values: ["login.microsoftonline.com", ".*\\.office\\.com"],
          },
          webCategories: { enabled: false, values: [] },
        },
      },
      {
        id: "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        name: "Scanner bypass only",
        enabled: true,
        skip: { httpsDecryption: false },
        conditions: {
          sourceIpOrNetworks: { enabled: false },
          destinationIpOrNetworks: {
            enabled: false,
            ipv4Networks: [],
            ipv6Networks: [],
          },
          urlRegexPatterns: {
            enabled: true,
            values: ["updates.vendor.example"],
          },
          webCategories: { enabled: false, values: [] },
        },
      },
      {
        id: "6ba7b811-9dad-11d1-80b4-00c04fd430c8",
        name: "Finance category skip",
        enabled: true,
        skip: { httpsDecryption: true },
        conditions: {
          sourceIpOrNetworks: { enabled: false },
          destinationIpOrNetworks: {
            enabled: false,
            ipv4Networks: [],
            ipv6Networks: [],
          },
          urlRegexPatterns: { enabled: false, values: [] },
          webCategories: {
            enabled: true,
            values: [
              { id: "550e8400-e29b-41d4-a716-446655440010", name: "Finance" },
            ],
          },
        },
      },
      {
        id: "6ba7b812-9dad-11d1-80b4-00c04fd430c8",
        name: "Branch source addresses",
        enabled: true,
        skip: { httpsDecryption: true },
        conditions: {
          sourceIpOrNetworks: { enabled: true },
          destinationIpOrNetworks: {
            enabled: false,
            ipv4Networks: [],
            ipv6Networks: [],
          },
          urlRegexPatterns: { enabled: false, values: [] },
          webCategories: { enabled: false, values: [] },
        },
      },
      {
        id: "6ba7b813-9dad-11d1-80b4-00c04fd430c8",
        name: "Partner network",
        enabled: true,
        skip: { httpsDecryption: true },
        conditions: {
          sourceIpOrNetworks: { enabled: false },
          destinationIpOrNetworks: {
            enabled: true,
            ipv4Networks: [
              { ipv4Address: "10.50.100.100", cidr: 32 },
              { ipv4Address: "10.20.30.0", cidr: 24 },
            ],
            ipv6Networks: [],
          },
          urlRegexPatterns: {
            enabled: true,
            values: ["partner.example.net"],
          },
          webCategories: { enabled: false, values: [] },
        },
      },
      {
        id: "6ba7b814-9dad-11d1-80b4-00c04fd430c8",
        name: "Disabled lab",
        enabled: false,
        skip: { httpsDecryption: true },
        conditions: {
          sourceIpOrNetworks: { enabled: false },
          destinationIpOrNetworks: {
            enabled: false,
            ipv4Networks: [],
            ipv6Networks: [],
          },
          urlRegexPatterns: { enabled: true, values: ["lab.corp.example"] },
          webCategories: { enabled: false, values: [] },
        },
      },
      {
        id: "6ba7b815-9dad-11d1-80b4-00c04fd430c8",
        name: "Healthcheck paths",
        enabled: true,
        skip: { httpsDecryption: true },
        conditions: {
          sourceIpOrNetworks: { enabled: false },
          destinationIpOrNetworks: {
            enabled: false,
            ipv4Networks: [],
            ipv6Networks: [],
          },
          urlRegexPatterns: { enabled: true, values: ["^/healthcheck$"] },
          webCategories: { enabled: false, values: [] },
        },
      },
    ],
    tlsRules: [
      {
        id: "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
        name: "Do not decrypt finance portals",
        enabled: true,
        action: "doNotDecrypt",
        websites: {
          urlGroups: [
            { id: "3f4a1c2e-7b8d-4e9f-a1b2-c3d4e5f60718", name: "Finance portals" },
          ],
          categories: [
            { id: "550e8400-e29b-41d4-a716-446655440099", name: "Streaming media" },
          ],
        },
        destinationNetworks: { any: true },
      },
      {
        id: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
        name: "Decrypt general web",
        enabled: true,
        action: "decrypt",
        websites: {
          urlGroups: [
            { id: "8c6d7e1a-2b3c-4d5e-9f01-23456789abcd", name: "General web" },
          ],
        },
      },
      {
        id: "6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b",
        name: "Do not decrypt partner name",
        enabled: true,
        action: "doNotDecrypt",
        websites: { any: true },
        destinationNetworks: {
          fqdnAddresses: [
            { id: "f47ac10b-58cc-4372-a567-0e02b2c3d479", name: "Partner portal" },
          ],
          fqdnGroups: [
            { id: "9a8b7c6d-5e4f-3210-aaaa-bbbbccccdddd", name: "Vendor SaaS" },
          ],
          macAddresses: [
            { id: "11111111-2222-3333-4444-555555555555", name: "Lobby printer" },
          ],
        },
      },
      {
        id: "123e4567-e89b-12d3-a456-426614174000",
        name: "Do not decrypt everything",
        enabled: true,
        action: "doNotDecrypt",
        websites: { any: true },
        destinationNetworks: { any: true },
      },
    ],
    urlGroups: [
      {
        id: "3f4a1c2e-7b8d-4e9f-a1b2-c3d4e5f60718",
        name: "Finance portals",
        urls: ["online.bank.example", "secure.payroll.example", "not_a_domain"],
      },
      {
        id: "8c6d7e1a-2b3c-4d5e-9f01-23456789abcd",
        name: "General web",
        urls: ["news.example"],
      },
    ],
    fqdnHosts: [
      {
        id: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        name: "Partner portal",
        fqdn: "partner.example.net",
      },
      {
        id: "0e7a1c44-9c1a-4b5d-8e2f-111111111111",
        name: "Vendor status",
        fqdn: "status.vendor.example",
      },
    ],
    fqdnGroups: [
      {
        id: "9a8b7c6d-5e4f-3210-aaaa-bbbbccccdddd",
        name: "Vendor SaaS",
        fqdns: [{ name: "Vendor status" }],
      },
    ],
  };
}

export function sampleEndpointSites(): EndpointSite[] {
  return [
    { value: "login.microsoftonline.com", comment: "Already excluded in Endpoint" },
    { value: "10.50.100.100", comment: "Already excluded in Endpoint" },
    { value: "calendar.corp.example", comment: "Endpoint-only exclusion" },
  ];
}
