// Package sdk holds the Ziro OS API's OpenAPI description; the client, types and schemas are in
// its subpackages.
package sdk

import _ "embed"

// OpenAPI is sdk/openapi.yaml, the REST API's specification (served at GET /api/v1/openapi.yaml).
//
//go:embed openapi.yaml
var OpenAPI []byte
