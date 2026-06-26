// Package mcp — OpenAPI schema embed and HTTP handler.
//
// openapi.json is embedded from docs/openapi.json (canonical source).
// The file is embedded here because Go's //go:embed only allows paths
// within or below the package directory; the canonical docs/ location is
// at the module root, so we embed a copy placed in this directory.
//
// When docs/openapi.json is updated, this file must be kept in sync.
// The plan 08-04 artifact is docs/openapi.json; this file is the embed source.
package mcp

import (
	_ "embed"
	"net/http"
)

// openAPISchemaBytes holds the embedded OpenAPI 3.1.0 schema for the MCP HTTP endpoint.
// The schema is served unauthenticated at /openapi.json (T-08-04-04: schema contains no secrets).
//
//go:embed openapi.json
var openAPISchemaBytes []byte

// serveOpenAPISchema is the net/http handler for GET /openapi.json.
// Served unauthenticated — the schema contains only endpoint descriptions
// and input schemas, no secret values (T-08-04-04 accepted risk).
func serveOpenAPISchema(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(openAPISchemaBytes)
}
