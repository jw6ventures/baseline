# Global search

The box in the top bar finds a record by name from any page. Press
<kbd>Ctrl</kbd> <kbd>K</kbd> (<kbd>⌘</kbd> <kbd>K</kbd> on a Mac), or <kbd>/</kbd>
when not typing in a field, to open the palette; type, move with the arrow
keys, and press Enter to open the selected result (Ctrl or ⌘ Enter opens it
in a new tab). Esc closes it. The code is `internal/server/search.go`,
`web/static/search.js` and `web/templates/pages/search.html`.

## What it finds

| Kind | Matched on | Shown with |
|---|---|---|
| Pages | The side nav's links and group names (in the browser) | Group |
| Hosts | Hostname, FQDN | FQDN |
| Containers | Name, Compose stack | Host |
| Compose stacks | Project name | Host |
| Virtual machines | Name, VMID or UUID | Hypervisor |
| Other CIs | Name, for CIs without a page of their own kind (agentless CIs, Kubernetes clusters, UniFi devices...) | Type |
| Work items | Reference (`OPS-12`), title | Status |
| Changes | Reference (`CHG-000042`), title | State |
| Projects | Key, name | |

Matching is a case-insensitive substring. Each kind shows its best five:
the exact name first, then names that start with the text, then names with
a word that does, then the rest, with missing and retired records last.
When a kind has more, "All matching ..." opens its list with the same quick
search (`?q=`), which also matches the list's other search fields.

## Scope

Each kind is a list engine table ([lists.md](lists.md)) searched on the
fields above, so search applies the same `Scope` as the list: a record is
found only by someone whose list would show it, and a host outside the
user's groups never appears. Agentless CIs and work items are everyone's,
as on their lists.

## Without JavaScript

The top bar's box is a plain GET form to `/search?q=`, which renders the
same results as a page. The palette asks `/search.json?q=`, which returns
`{"query", "groups": [{"key", "label", "results": [{"ref", "title",
"detail", "url", "dim"}], "more", "all"}]}`. Requests are debounced and a
newer one aborts the last; the text is capped at 100 bytes.
