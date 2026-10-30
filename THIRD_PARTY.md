# Third-party front-end files

Vendored as single files under `web/static/vendor/`, with no build step
(docs/architecture.md §6). Go modules are listed in `go.mod` and vendored
under `vendor/`.

| File | Project | Version | License | SHA-256 |
|---|---|---|---|---|
| `uPlot.iife.min.js` | [uPlot](https://github.com/leeoniya/uPlot) | 1.6.32 | MIT (`uPlot.LICENSE`) | `19c8d4c6ad88929a79f4ae49d6f7161566dfd0ba3d15cc495e974f787eb78f1f` |
| `uPlot.min.css` | uPlot | 1.6.32 | MIT | `df630c6a8d6f8eeaff264b50f73ce5b114f646ffd9a0bb74f049b0a00135fa04` |
| `htmx.min.js` | [htmx](https://github.com/bigskysoftware/htmx) | 2.0.4 | 0BSD (`htmx.LICENSE`) | `e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447` |

The uPlot files come from the npm tarball `uplot-1.6.32.tgz` (`dist/`), whose registry
integrity is
`sha512-KIMVnG68zvu5XXUbC4LQEPnhwOxBuLyW1AHtpm6IKTXImkbLgkMy+jabjLgSLMasNuGGzQm/ep3tOkyTxpiQIw==`.
`htmx.min.js` is `dist/htmx.min.js` from `htmx.org-2.0.4.tgz`, whose registry
integrity is
`sha512-HLxMCdfXDOJirs3vBZl/ZLoY+c7PfM4Ahr2Ad4YXh6d22T5ltbTXFFkpx9Tgb2vvmWFMbIc3LqN2ToNkZJvyYQ==`.

To upgrade, replace the files from a newer tarball and update this table.
