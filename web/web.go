// Package web holds the UI's templates and static files, embedded into the
// server binary.
package web

import "embed"

//go:embed templates static install.sh.tmpl
var FS embed.FS
