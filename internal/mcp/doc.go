// Package mcp implements the reconFTW MCP server.
//
// The MCP server exposes reconFTW's recon modes as MCP tools via the official
// github.com/modelcontextprotocol/go-sdk (D-01). It supports both stdio and
// HTTP/Streamable transports, per-session scope sandboxing (MCP-10), and
// resource subscriptions for live JSONL findings (MCP-03).
//
// Phase 8 Wave 0 establishes the SDK as a dependency and verifies the six
// runtime assumptions (A1-A6) the implementation relies on. See
// sdk_assumptions_test.go for the verification results.
package mcp
