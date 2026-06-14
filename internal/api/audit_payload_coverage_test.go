package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEveryEventPayloadSecretFieldCovered is the self-discovering, fail-closed
// guard for finding 1 (WS11). It AST-walks EVERY exported struct in
// internal/eventtypes/payloads and, for any string-ish field whose JSON tag
// looks secret (isSensitiveParamField), asserts a redaction path exists in
// eventRedactionSchemas for an event whose name matches the struct.
//
// By convention the payload struct name IS the event-type string, so coverage
// is checked against the event's ACTUAL schema (scanned across all streams)
// without a hardcoded struct->stream map that could fail open. This generalises
// the TOTP-specific guard (audit_totp_redaction_test.go) to the whole payload
// surface: a secret field added to ANY future payload struct without a matching
// redaction schema fails here. require.Positive(scanned) prevents the scan
// matching zero and passing open.
//
// A pure-stdlib AST walk (not go/packages) matches the project's archtest
// convention and avoids the runtime-reflection problem that there is no
// registry enumerating payload types.
func TestEveryEventPayloadSecretFieldCovered(t *testing.T) {
	const payloadsDir = "../eventtypes/payloads"

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, payloadsDir, func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	require.NoError(t, err)
	require.NotEmpty(t, pkgs, "no packages parsed under %s", payloadsDir)

	// event-type name -> set of redaction paths (union across all streams).
	covered := map[string]map[string]bool{}
	for _, streamSchemas := range eventRedactionSchemas {
		for eventType, schema := range streamSchemas {
			if covered[eventType] == nil {
				covered[eventType] = map[string]bool{}
			}
			for _, p := range schema.paths {
				covered[eventType][p] = true
			}
		}
	}

	scanned := 0
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.TYPE {
					continue
				}
				for _, spec := range gd.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok || !ts.Name.IsExported() {
						continue
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok {
						continue
					}
					structName := ts.Name.Name
					for _, field := range st.Fields.List {
						if field.Tag == nil || !isStringishType(field.Type) {
							continue
						}
						tag := reflect.StructTag(strings.Trim(field.Tag.Value, "`"))
						jsonName := strings.Split(tag.Get("json"), ",")[0]
						if jsonName == "" || jsonName == "-" {
							continue
						}
						if !isSensitiveParamField(jsonName) {
							continue
						}
						scanned++
						require.Truef(t, covered[structName][jsonName],
							"payload %s field %s (json:%q) looks secret but no redaction schema covers event %q path %q — add it to eventRedactionSchemas in audit_handler.go",
							structName, astFieldName(field), jsonName, structName, jsonName)
					}
				}
			}
		}
	}
	require.Positive(t, scanned,
		"self-discovering payload scan matched zero secret fields — isSensitiveParamField or the AST walk is broken")
}

// isStringishType reports whether an AST field type is string / *string /
// []string / []*string (and deeper nestings thereof). Non-string types
// (bool, int, time.Time, json.RawMessage, maps) are excluded so a secret-LOOKING
// name on a bool field (e.g. ssh_allow_password) is not flagged.
func isStringishType(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name == "string"
	case *ast.StarExpr:
		return isStringishType(t.X)
	case *ast.ArrayType:
		return isStringishType(t.Elt)
	}
	return false
}

// astFieldName returns the first declared name of a struct field for error
// messages (or a placeholder for an embedded field).
func astFieldName(f *ast.Field) string {
	if len(f.Names) > 0 {
		return f.Names[0].Name
	}
	return "<embedded>"
}
