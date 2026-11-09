// IP Intelligence — IP → ASN and IP → Country, via Team Cymru over DNS-over-HTTPS (DoH).
//
// No Cloudflare Worker needed: the lookup is a DNS TXT query, and DoH turns it into a CORS-enabled
// HTTPS fetch (cloudflare-dns.com / dns.google both send access-control-allow-origin: *). Team Cymru
// publishes IP→ASN over DNS and RECOMMENDS the DNS interface for recurring lookups; Cloudflare's
// resolver caches (~4 h TTL, matching Cymru's update cycle) so repeats don't hit Cymru.
//
//   IPv4 a.b.c.d -> d.c.b.a.origin.asn.cymru.com           TXT -> "<asn> | <prefix> | <cc> | <reg> | <date>"
//   IPv6         -> <nibble-reversed>.origin6.asn.cymru.com TXT -> (same shape)
//   AS name      -> AS<n>.asn.cymru.com                     TXT -> "<asn> | <cc> | <reg> | <date> | <NAME>"
import { definePlugin, definePluginPack } from './sdk';
import type { HostContext, RunResult, GraphNode } from './sdk';

const DOH_ENDPOINTS = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];

// Cymru registry token -> the autonomous_system typepack's `registry` enum.
const REGISTRY: Record<string, string> = {
    arin: 'ARIN',
    ripencc: 'RIPE',
    ripe: 'RIPE',
    apnic: 'APNIC',
    lacnic: 'LACNIC',
    afrinic: 'AFRINIC',
};
const regEnum = (r: string): string | undefined => REGISTRY[(r || '').toLowerCase()];

interface OriginInfo {
    asn: number;
    prefix: string;
    country: string;
    registry: string;
}
interface AsInfo {
    asn: number;
    name: string;
    country: string;
    registry: string;
}

// ---- IP -> reversed Cymru query name ------------------------------------------------------
function v4Query(ip: string): string | null {
    const o = ip.split('.');
    if (o.length !== 4) return null;
    for (const x of o) if (!/^\d{1,3}$/.test(x) || Number(x) > 255) return null;
    return `${o[3]}.${o[2]}.${o[1]}.${o[0]}.origin.asn.cymru.com`;
}
function v6Query(ip: string): string | null {
    const addr = ip.split('%')[0];
    if (!addr.includes(':')) return null;
    let groups: string[];
    if (addr.includes('::')) {
        const [h, t] = addr.split('::');
        const head = h ? h.split(':') : [];
        const tail = t ? t.split(':') : [];
        const missing = 8 - head.length - tail.length;
        if (missing < 0) return null;
        groups = [...head, ...Array(missing).fill('0'), ...tail];
    } else {
        groups = addr.split(':');
    }
    if (groups.length !== 8) return null;
    let full = '';
    for (const g of groups) {
        if (!/^[0-9a-fA-F]{0,4}$/.test(g)) return null;
        full += g.padStart(4, '0');
    }
    full = full.toLowerCase();
    if (full.length !== 32) return null;
    return full.split('').reverse().join('.') + '.origin6.asn.cymru.com';
}
function queryFor(ip: string): { name: string; version: 'ipv4' | 'ipv6' } | null {
    const t = ip.trim();
    if (t.includes(':')) {
        const n = v6Query(t);
        return n ? { name: n, version: 'ipv6' } : null;
    }
    const n = v4Query(t);
    return n ? { name: n, version: 'ipv4' } : null;
}

// ---- DoH TXT query (through ctx.net; Cloudflare then Google) -------------------------------
async function dohTxt(ctx: HostContext, name: string): Promise<string[]> {
    for (const base of DOH_ENDPOINTS) {
        try {
            const res = await ctx.net!.fetch!(`${base}?name=${encodeURIComponent(name)}&type=TXT`, {
                method: 'GET',
                headers: { accept: 'application/dns-json' },
            });
            if (!res.ok) continue;
            const data = (await res.json()) as { Answer?: Array<{ type: number; data: string }> };
            if (Array.isArray(data.Answer)) {
                return data.Answer.flatMap((a) => (a.type === 16 ? [String(a.data).replace(/"/g, '').trim()] : []));
            }
            return []; // NXDOMAIN / no TXT
        } catch {
            /* try next resolver */
        }
    }
    return [];
}

function parseOrigin(txt: string): OriginInfo | null {
    // "15169 | 8.8.4.0/24 | US | arin | 2023-12-28"  (asn field may list several on MOAS — take first)
    const p = txt.split('|').map((s) => s.trim());
    if (p.length < 3) return null;
    const asn = Number(p[0].split(/\s+/)[0] || '0');
    if (!Number.isInteger(asn) || asn < 1 || asn > 4294967295) return null;
    return { asn, prefix: p[1] || '', country: (p[2] || '').toUpperCase(), registry: p[3] || '' };
}
function parseAsName(txt: string): { name: string; country: string; registry: string } {
    // "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"
    const p = txt.split('|').map((s) => s.trim());
    const last = p[p.length - 1] || '';
    return { name: last.replace(/,\s*[A-Za-z]{2}$/, ''), country: (p[1] || '').toUpperCase(), registry: p[2] || '' };
}

const isIp = (n: GraphNode) => n.type === 'infrastructure.ip_address';
const ipOf = (n: GraphNode) => String((n.data as any).ip_address ?? '').trim();

/** Resolve an IP's origin (per-prefix) + AS info, caching AS-level data by ASN for this run. */
async function lookupAs(
    ctx: HostContext,
    ip: string,
    asCache: Map<number, AsInfo>,
): Promise<{ origin: OriginInfo; as: AsInfo } | null> {
    const q = queryFor(ip);
    if (!q) return null;
    let origin: OriginInfo | null = null;
    for (const t of await dohTxt(ctx, q.name)) {
        origin = parseOrigin(t);
        if (origin) break;
    }
    if (!origin) return null;
    let as = asCache.get(origin.asn);
    if (!as) {
        const txts = await dohTxt(ctx, `AS${origin.asn}.asn.cymru.com`);
        const n = txts.length ? parseAsName(txts[0]) : { name: '', country: origin.country, registry: origin.registry };
        as = {
            asn: origin.asn,
            name: n.name,
            country: n.country || origin.country,
            registry: n.registry || origin.registry,
        };
        asCache.set(origin.asn, as); // AS number/name/registry are AS-level & stable → cache once per run
    }
    return { origin, as };
}

// ---- Plugin: IP → ASN ----------------------------------------------------------------------
const ipToAsn = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.ip_to_asn',
        content_type: 'vineyard:plugin',
        name: 'IP → ASN',
        version: '1.1.0',
        description:
            'Resolves the autonomous system announcing each selected IP Address (Team Cymru). Creates an Autonomous System node (number, name, country, registry) linked "announced by" and sets the IP\'s asn (e.g. 15169).',
        icon: 'waypoints',
        author: { name: 'VINEYARD', url: 'https://vineyard.run' },
        license: 'MIT',
        platforms: { primary: 'web', web: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' } },
        io: {
            consumes: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'ip_address' },
            ],
            produces: [
                {
                    typepack: 'run.vineyard.typepacks.infrastructure',
                    category: 'infrastructure',
                    name: 'autonomous_system',
                },
            ],
        },
        scopes: {
            graph: ['node:read', 'node:create', 'node:update', 'edge:create'],
            network: [
                {
                    endpoint: 'https://cloudflare-dns.com/dns-query',
                    methods: ['GET'],
                    purpose: "Look up the AS announcing each selected IP in Team Cymru's IP-to-ASN data.",
                },
                {
                    endpoint: 'https://dns.google/resolve',
                    methods: ['GET'],
                    purpose: 'Same lookup, used when cloudflare-dns.com fails.',
                },
            ],
        },
        lifecycle: { persistence: 'opt-in', controls: ['progress', 'cancel'], progress: 'determinate' },
    },
    async run(ctx): Promise<RunResult> {
        if (!ctx.net?.fetch)
            return { summary: 'Network capability not granted to this plugin', counts: { resolved: 0 } };
        const ids = ctx.input.selection;
        if (!ids.length) return { summary: 'Select one or more IP Address nodes first', counts: { resolved: 0 } };

        const asCache = new Map<number, AsInfo>(); // asn -> AS info (queried once per run)
        const asNodeByAsn = new Map<number, string>(); // asn -> the AS node id (created/reused once)
        let resolved = 0;
        let links = 0;
        for (let i = 0; i < ids.length; i++) {
            if (ctx.signal?.aborted) break;
            const node = await ctx.graph!.get!(ids[i]);
            if (!node || !isIp(node)) continue;
            const ip = ipOf(node);
            if (!ip) continue;
            ctx.progress?.set?.({ percent: Math.round(((i + 1) / ids.length) * 100), message: `Resolving ${ip}` });
            const r = await lookupAs(ctx, ip, asCache);
            if (!r) continue;
            resolved++;

            const asn = r.as.asn;
            let asId = asNodeByAsn.get(asn);
            if (!asId) {
                const asNode = await ctx.graph!.createNode!({
                    type: 'infrastructure.autonomous_system',
                    data: {
                        autonomous_system_number: asn,
                        ...(r.as.name ? { autonomous_system_name: r.as.name } : {}),
                        ...(r.as.country ? { country_code: r.as.country } : {}),
                        ...(regEnum(r.as.registry) ? { registry: regEnum(r.as.registry) } : {}),
                    },
                });
                asId = String(asNode.id);
                asNodeByAsn.set(asn, asId);
            }
            // Pass ONLY the field we filled — updateNode takes a delta. Spreading ...node.data
            // here would re-send a stale snapshot of every other field, which the fill-merge on
            // apply then writes back over live, clobbering whatever another run set in the meantime.
            await ctx.graph!.updateNode!(ids[i], { asn: r.origin.asn });
            await ctx.graph!.createEdge!({ from: ids[i], to: asId, label: 'announced by' });
            links++;
        }
        return {
            summary: `${resolved}/${ids.length} IP(s) resolved → ${asNodeByAsn.size} unique AS(es)`,
            counts: { resolved, autonomous_systems: asNodeByAsn.size, links },
        };
    },
});

// ---- Plugin: IP → Country ------------------------------------------------------------------
const ipToCountry = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.ip_to_country',
        content_type: 'vineyard:plugin',
        name: 'IP → Country',
        version: '1.0.2',
        description:
            "Sets each selected IP Address's country_code from Team Cymru's IP-to-ASN data for its announcing prefix. Creates no nodes.",
        icon: 'flag',
        author: { name: 'VINEYARD', url: 'https://vineyard.run' },
        license: 'MIT',
        platforms: { primary: 'web', web: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' } },
        io: {
            consumes: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'ip_address' },
            ],
            produces: [],
        },
        scopes: {
            graph: ['node:read', 'node:update'],
            network: [
                {
                    endpoint: 'https://cloudflare-dns.com/dns-query',
                    methods: ['GET'],
                    purpose:
                        "Look up the country of each selected IP's announcing prefix in Team Cymru's IP-to-ASN data.",
                },
                {
                    endpoint: 'https://dns.google/resolve',
                    methods: ['GET'],
                    purpose: 'Same lookup, used when cloudflare-dns.com fails.',
                },
            ],
        },
        lifecycle: { persistence: 'opt-in', controls: ['progress', 'cancel'], progress: 'determinate' },
    },
    async run(ctx): Promise<RunResult> {
        if (!ctx.net?.fetch)
            return { summary: 'Network capability not granted to this plugin', counts: { updated: 0 } };
        const ids = ctx.input.selection;
        if (!ids.length) return { summary: 'Select one or more IP Address nodes first', counts: { updated: 0 } };

        let updated = 0;
        for (let i = 0; i < ids.length; i++) {
            if (ctx.signal?.aborted) break;
            const node = await ctx.graph!.get!(ids[i]);
            if (!node || !isIp(node)) continue;
            const ip = ipOf(node);
            const q = ip ? queryFor(ip) : null;
            if (!q) continue;
            ctx.progress?.set?.({ percent: Math.round(((i + 1) / ids.length) * 100), message: `Resolving ${ip}` });
            let origin: OriginInfo | null = null;
            for (const t of await dohTxt(ctx, q.name)) {
                origin = parseOrigin(t);
                if (origin) break;
            }
            if (!origin || !origin.country) continue;
            // Delta only — see the note on the ASN update above.
            await ctx.graph!.updateNode!(ids[i], { country_code: origin.country });
            updated++;
        }
        return { summary: `${updated}/${ids.length} IP(s) updated with country`, counts: { updated } };
    },
});

// The pack's page in the marketplace drawer, in Markdown. `summary` is the card's one line and must
// equal the registry entry's. Images are never loaded and links are shown, not followed, so sources
// are named by plain URL.
const PACK_PAGE = [
    'For when the question is who routes an address rather than who registered it: the autonomous system that announces each IPv4 or IPv6 address, and the country recorded for its announcing prefix. Registration, exposure and location are in the IP Recon pack.',
    '',
    '**Needs:** no API key, account or data download.',
    '',
    "**Who sees it:** each lookup is a DNS TXT query sent over DNS-over-HTTPS to Cloudflare (cloudflare-dns.com), or to Google (dns.google) when Cloudflare fails. The query name encodes the IP address being looked up, reversed, or the AS number for a name lookup. Team Cymru's DNS servers receive the query from the resolver, not from the analyst, and Cloudflare caches answers for about four hours, matching Cymru's update cycle, so repeated lookups do not all reach Cymru. The addresses themselves are never contacted.",
    '',
    '**Read results with care:** when Cymru lists more than one origin AS for a prefix, only the first is used.',
    '',
    "**Data and licences:** Team Cymru's IP-to-ASN mapping service, https://www.team-cymru.com/ip-asn-mapping, read through the DNS interface Cymru recommends for recurring lookups; this repository does not restate the service's terms.",
    '',
    '**Source:** https://github.com/Vineyard-Intelligence/pluginpack-iptoasn-cymru-doh (MIT)',
].join('\n');

export default definePluginPack({
    identifier: 'run.vineyard.pluginpacks.iptoasn_cymru_doh',
    content_type: 'vineyard:pluginpack',
    name: 'IP to ASN (Team Cymru - DoH Based)',
    version: '1.2.1',
    summary: "IP → ASN and IP → Country enrichment for IP Address nodes from Team Cymru's IP-to-ASN mapping.",
    description: PACK_PAGE,
    plugins: [ipToAsn, ipToCountry],
});
