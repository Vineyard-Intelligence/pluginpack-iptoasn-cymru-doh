# dist/

`pack.mjs` is the published artifact: a single self-contained ES module (esbuild, minified, no
imports) that the Vineyard plugin worker fetches from this repo at the commit the registry pins
and runs in its sandbox. The catalog manifest `plugins/iptoasn-cymru-doh.manifest.json` points
every member at it (`platforms.web.entry: "dist/pack.mjs"`), and the bundle embeds its own copy of
the manifest — the registry check refuses a pin whose bundle and manifest disagree on version or
licence, so edit both together.

The TypeScript source this bundle was built from (`ip-intel-pack.ts`, with the plugin SDK it
imports and the `build-packs.mjs` script that bundled it) no longer lives in the Vineyard app
repo. It was archived, outside any git repo, at:

    vineyard/_archive/frontend-reference-packs-2026-10-10/

That folder's README names the frontend commit the sources were taken from (frontend git history
still has them) and how to rebuild. Until the source is given a home of its own, treat
`pack.mjs` here as the authoritative copy of the code.
