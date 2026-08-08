package store_test

// The durable half of dispatch, and the placeholder-numbering rule it depends
// on.
//
// sqlc expands sqlc.slice into bare `?` placeholders at run time. SQLite
// numbers a bare `?` one above the highest parameter index assigned so far, so
// any numbered parameter written after a slice collides with the slice's own
// expansion as soon as the slice carries more than one element. The statement
// then declares fewer parameters than the generated Go supplies and every call
// fails. These tests exercise the sweep at one, two and three connected
// devices, and then hold the whole generated slice-bearing corpus to the same
// rule.

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/testdb"
)

// seedDueDelivery inserts one PENDING delivery whose availability the caller
// chooses, which the shared seedDelivery helper pins to the insert instant.
func seedDueDelivery(t *testing.T, raw *testdb.DB, deviceID string, availableAt time.Time) string {
	t.Helper()
	deliveryID := newID()
	_, err := raw.Exec(context.Background(), `
		INSERT INTO deliveries
			(delivery_id, device_id, manifest_id, manifest, state, created_at, available_at)
		VALUES ($1, $2, $3, '{}', 'PENDING', $4, $5)`,
		deliveryID, deviceID, newID(), availableAt, availableAt)
	require.NoError(t, err)
	return deliveryID
}

// TestListDueDeliveries_SweepsEveryConnectedDevice drives the sweep exactly as
// delivery.Dispatcher.queueDue does: one bounded page covering every currently
// connected device. One device is the degenerate case; two and three are the
// ordinary fleet.
func TestListDueDeliveries_SweepsEveryConnectedDevice(t *testing.T) {
	for _, connectedCount := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("%d connected devices", connectedCount), func(t *testing.T) {
			st, raw := setupSQLite(t)
			ctx := context.Background()
			now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

			connected := make([]string, 0, connectedCount)
			due := make([]string, 0, connectedCount)
			for range connectedCount {
				device := seedDevice(t, raw)
				connected = append(connected, device)
				due = append(due, seedDueDelivery(t, raw, device, now.Add(-time.Minute)))
				// Scheduled for later. Its exclusion is what proves the sweep
				// instant reached the available_at comparison rather than a
				// device id shifted into that slot by the expanded slice.
				seedDueDelivery(t, raw, device, now.Add(time.Hour))
			}
			// Durable work for a device that is not connected stays behind; a
			// reconnect queues it directly.
			offline := seedDueDelivery(t, raw, seedDevice(t, raw), now.Add(-time.Minute))

			rows, err := st.ListDueDeliveries(ctx, connected, now, 100)
			require.NoError(t, err)

			got := make([]string, 0, len(rows))
			for _, row := range rows {
				got = append(got, row.DeliveryID)
			}
			assert.ElementsMatch(t, due, got)
			assert.NotContains(t, got, offline, "an offline device's due row is not swept")
		})
	}
}

// TestListDueDeliveries_BoundsThePage pins the page-size argument, the last
// parameter of the statement and the one the expanded slice overruns first.
func TestListDueDeliveries_BoundsThePage(t *testing.T) {
	st, raw := setupSQLite(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

	connected := make([]string, 0, 3)
	oldest := make([]string, 0, 3)
	for i := range 3 {
		device := seedDevice(t, raw)
		connected = append(connected, device)
		oldest = append(oldest, seedDueDelivery(t, raw, device, now.Add(-time.Duration(3-i)*time.Hour)))
	}

	rows, err := st.ListDueDeliveries(ctx, connected, now, 2)
	require.NoError(t, err)
	require.Len(t, rows, 2, "the sweep page is bounded by the requested size")
	assert.Equal(t, oldest[0], rows[0].DeliveryID)
	assert.Equal(t, oldest[1], rows[1].DeliveryID)
}

// sliceStatement is one generated statement that expands at least one
// sqlc.slice at run time.
type sliceStatement struct {
	name    string
	sql     string
	markers int
	// scalars counts every parameter the generated Go supplies besides the
	// slice elements: the distinct numbered placeholders plus any bare one.
	scalars int
}

var (
	sliceMarkerPattern   = regexp.MustCompile(`/\*SLICE:[A-Za-z0-9_]+\*/\?`)
	numberedParamPattern = regexp.MustCompile(`\?\d+`)
	parameterPattern     = regexp.MustCompile(`\?\d*`)
	stringLiteralPattern = regexp.MustCompile(`'(?:[^']|'')*'`)
)

// expand mirrors the substitution the generated wrapper performs, and returns
// the arguments that wrapper would supply alongside it. Every argument is the
// integer one so that each is legal wherever it lands — including a LIMIT,
// which rejects a NULL or a string outright.
func (s sliceStatement) expand(elements int) (string, []any) {
	expanded := sliceMarkerPattern.ReplaceAllString(s.sql, strings.Repeat(",?", elements)[1:])
	args := make([]any, s.scalars+s.markers*elements)
	for i := range args {
		args[i] = int64(1)
	}
	return expanded, args
}

// TestGeneratedSliceQueries_NumberEveryArgument holds every generated
// slice-bearing statement to the rule the delivery sweep broke: expanded with
// two and three slice elements, the statement must declare exactly as many
// placeholders as the generated wrapper supplies arguments, numbered 1..N with
// none claimed twice.
//
// The placeholder count, not the execution, is the discriminator. The SQLite
// driver reports no fixed parameter count to database/sql, so a surplus
// argument is discarded in silence and a statement whose numbered parameter
// collides with an expanded slice still runs — against whichever value landed
// in that slot. Execution is kept because it proves the expanded statement is
// valid against the real schema at that argument count.
func TestGeneratedSliceQueries_NumberEveryArgument(t *testing.T) {
	statements := discoverSliceStatements(t)
	require.NotEmpty(t, statements,
		"discovery found no generated slice statement: the discovery is broken, not the queries")

	discovered := 0
	for _, statement := range statements {
		discovered += statement.markers
	}
	require.Equal(t, countQuerySliceDirectives(t), discovered,
		"every sqlc.slice in queries/ must reach the generated corpus this test covers")

	_, raw := setupSQLite(t)
	ctx := context.Background()
	for _, statement := range statements {
		t.Run(statement.name, func(t *testing.T) {
			for _, elements := range []int{2, 3} {
				expanded, args := statement.expand(elements)
				distinct, highest := sqliteParameterIndexes(expanded)
				assert.Equalf(t, len(args), distinct,
					"%s with %d slice elements binds %d arguments to %d placeholders",
					statement.name, elements, len(args), distinct)
				assert.Equalf(t, len(args), highest,
					"%s with %d slice elements numbers placeholders beyond its argument list",
					statement.name, elements)
				_, err := raw.Exec(ctx, expanded, args...)
				require.NoErrorf(t, err, "%s with %d slice elements", statement.name, elements)
			}
		})
	}
}

// sqliteParameterIndexes applies SQLite's numbering rule to a statement: `?N`
// claims index N, and a bare `?` claims one above the highest index assigned so
// far. It returns how many distinct indexes the statement declares and the
// highest of them. Both equal the supplied argument count only when every
// argument reaches a placeholder of its own.
func sqliteParameterIndexes(query string) (distinct, highest int) {
	stripped := stringLiteralPattern.ReplaceAllString(query, "''")
	indexes := make(map[int]struct{})
	for _, placeholder := range parameterPattern.FindAllString(stripped, -1) {
		index := highest + 1
		if digits := strings.TrimPrefix(placeholder, "?"); digits != "" {
			parsed, err := strconv.Atoi(digits)
			if err != nil {
				continue
			}
			index = parsed
		}
		indexes[index] = struct{}{}
		if index > highest {
			highest = index
		}
	}
	return len(indexes), highest
}

// discoverSliceStatements reads the generated package source and returns every
// query constant carrying a slice marker. Parsing the emitted constants rather
// than listing query names keeps the sweep honest as queries come and go.
func discoverSliceStatements(t *testing.T) []sliceStatement {
	t.Helper()
	sources, err := filepath.Glob(filepath.Join("generated", "*.go"))
	require.NoError(t, err)
	require.NotEmpty(t, sources, "no generated sources found")

	fileSet := token.NewFileSet()
	statements := make([]sliceStatement, 0)
	for _, source := range sources {
		file, err := parser.ParseFile(fileSet, source, nil, 0)
		require.NoError(t, err)
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.CONST {
				continue
			}
			for _, spec := range general.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
					continue
				}
				literal, ok := value.Values[0].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				query, err := strconv.Unquote(literal.Value)
				require.NoError(t, err)
				markers := len(sliceMarkerPattern.FindAllString(query, -1))
				if markers == 0 {
					continue
				}
				statements = append(statements, sliceStatement{
					name: value.Names[0].Name, sql: query,
					markers: markers, scalars: countScalarParameters(query),
				})
			}
		}
	}
	return statements
}

// countScalarParameters counts the parameters a slice-bearing statement binds
// besides its slice elements. Numbered placeholders are counted once per
// distinct index because sqlc reuses one index for a repeated named argument.
func countScalarParameters(query string) int {
	stripped := sliceMarkerPattern.ReplaceAllString(stringLiteralPattern.ReplaceAllString(query, "''"), "")
	indexes := make(map[string]struct{})
	for _, numbered := range numberedParamPattern.FindAllString(stripped, -1) {
		indexes[numbered] = struct{}{}
	}
	bare := strings.Count(numberedParamPattern.ReplaceAllString(stripped, ""), "?")
	return len(indexes) + bare
}

// countQuerySliceDirectives counts sqlc.slice across the query sources, giving
// the generated-corpus discovery an independent expectation to meet.
func countQuerySliceDirectives(t *testing.T) int {
	t.Helper()
	sources, err := filepath.Glob(filepath.Join("queries", "*.sql"))
	require.NoError(t, err)
	require.NotEmpty(t, sources, "no query sources found")

	directives := 0
	for _, source := range sources {
		content, err := os.ReadFile(source)
		require.NoError(t, err)
		directives += strings.Count(string(content), "sqlc.slice(")
	}
	return directives
}
