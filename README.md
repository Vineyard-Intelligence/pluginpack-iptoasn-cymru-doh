# IP to ASN (Team Cymru - DoH Based)

A Vineyard **plugin pack** that enriches `infrastructure.ip_address` nodes using **Team Cymru's
IP-to-ASN service over DNS-over-HTTPS (DoH)** — no server, no API key, no data download.

Two plugins, both triggered when one or more **IP Address** nodes are selected:

- **IP → ASN** — resolves the announcing AS (number + name) via Cymru over DoH, adds/reuses the
  `autonomous_system` node, links it with an `announced by` edge, and fills the IP's `asn` field.
  De-dups the AS lookup per ASN within a run (one query + one node per AS).
- **IP → Country** — fills the IP's `country_code` from its announcing prefix (no new node).

## How it works

The browser can't do raw DNS, but DoH turns a TXT lookup into a CORS-enabled HTTPS `fetch`
(`cloudflare-dns.com`, falling back to `dns.google`):

```
IPv4 a.b.c.d -> d.c.b.a.origin.asn.cymru.com   TXT -> "<asn> | <prefix> | <cc> | <registry> | <date>"
IPv6         -> <nibble-reversed>.origin6.asn.cymru.com
AS name      -> AS<n>.asn.cymru.com            TXT -> "... | <NAME>"
```

Team Cymru recommends the DNS interface for recurring lookups; Cloudflare's resolver caches
(~4 h, matching Cymru's update cycle), so repeats don't hit Cymru.

## Layout

- `plugins/iptoasn-cymru-doh.manifest.json` — the pack manifest (catalog entry source).
- `dist/` — runnable bundle (see note; not built yet — plugins run as built-ins in-app today).

Data: Team Cymru IP-to-ASN mapping service — <https://www.team-cymru.com/ip-asn-mapping>.
