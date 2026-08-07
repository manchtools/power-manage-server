package store

// A single-entity search-document refresh runs inside the process-wide writer
// lock on every audited mutation, so its query plan is an availability
// property rather than a micro-optimization: if SQLite drives the outermost
// loop with a scan, every mutation costs O(that table) and the executions
// scope, which is never pruned, makes that cost grow without bound.
//
// The plan is asserted against SQLite's real planner and the real baseline
// schema because only a measured plan decides whether a predicate is sargable.
// Statement text alone cannot show it.

import (
	"database/sql"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The outermost FROM is the only one that begins a line; every correlated
// subquery in these statements is written inline.
var searchDocumentSourceExpression = regexp.MustCompile(`(?m)^FROM\s+(\w+)\s+(\w+)`)

// SQLite renders a seek as "SEARCH <alias> USING [COVERING ]INDEX <name>
// (<column>=?)". A trailing qualifier such as " LEFT-JOIN" may follow, so the
// expression is deliberately unanchored at the end.
var indexSeekExpression = regexp.MustCompile(`^SEARCH (\w+) USING [^(]*\((\w+)=\?`)

type queryPlanRow struct {
	id     int64
	parent int64
	detail string
}

func TestSearchDocumentStatementsSeekTheSingleEntityByPrimaryKey(t *testing.T) {
	t.Parallel()

	require.NotEmpty(t, searchDocumentStatements,
		"matches-zero guard: no search-document statements were discovered")

	db := openSearchPlanDatabase(t)

	for scope, statement := range searchDocumentStatements {
		t.Run(scope, func(t *testing.T) {
			table, alias := searchDocumentSource(t, statement)
			key := primaryKeyColumn(t, db, table)

			plan := explainQueryPlan(t, db, statement)
			require.NotEmpty(t, plan,
				"matches-zero guard: EXPLAIN QUERY PLAN returned no rows for scope %q", scope)

			outer := make([]queryPlanRow, 0, len(plan))
			for _, row := range plan {
				if row.parent == 0 {
					outer = append(outer, row)
				}
			}
			require.NotEmpty(t, outer,
				"matches-zero guard: EXPLAIN QUERY PLAN reported no outer loop for scope %q", scope)

			seeksEntity := false
			for _, row := range outer {
				assert.Falsef(t, strings.HasPrefix(row.detail, "SCAN "),
					"scope %q scans a joined table in the outer loop; the refresh predicate is not sargable: %s",
					scope, row.detail)
				match := indexSeekExpression.FindStringSubmatch(row.detail)
				if match != nil && match[1] == alias && match[2] == key {
					seeksEntity = true
				}
			}
			assert.Truef(t, seeksEntity,
				"scope %q must seek %s.%s (%s) from the bound entity id; plan was:\n%s",
				scope, alias, key, table, formatQueryPlan(plan))
		})
	}
}

// searchDocumentSource reports the table and alias the statement's outermost
// FROM names. Requiring exactly one match keeps a reformatted statement from
// silently retargeting the assertion at a subquery.
func searchDocumentSource(t *testing.T, statement string) (table, alias string) {
	t.Helper()
	matches := searchDocumentSourceExpression.FindAllStringSubmatch(statement, -1)
	require.Lenf(t, matches, 1,
		"expected exactly one line-leading FROM clause, found %d", len(matches))
	return matches[0][1], matches[0][2]
}

// primaryKeyColumn reads the target table's single-column primary key from the
// live catalog, so the assertion follows the schema instead of a copied list.
func primaryKeyColumn(t *testing.T, db *sql.DB, table string) string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(),
		`SELECT name FROM pragma_table_info(?) WHERE pk > 0 ORDER BY pk`, table)
	require.NoError(t, err)
	defer func() { require.NoError(t, rows.Close()) }()

	columns := make([]string, 0, 1)
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		columns = append(columns, name)
	}
	require.NoError(t, rows.Err())
	require.Lenf(t, columns, 1,
		"matches-zero guard: table %q must have a single-column primary key, got %v", table, columns)
	return columns[0]
}

func explainQueryPlan(t *testing.T, db *sql.DB, statement string) []queryPlanRow {
	t.Helper()
	// Binding is arity-driven so the assertion holds for whatever parameter
	// shape the statement uses. SQLite plans at prepare time, so the bound
	// values do not influence the result.
	arguments := make([]any, strings.Count(statement, "?"))
	for i := range arguments {
		arguments[i] = ""
	}
	rows, err := db.QueryContext(t.Context(), "EXPLAIN QUERY PLAN "+statement, arguments...)
	require.NoError(t, err)
	defer func() { require.NoError(t, rows.Close()) }()

	names, err := rows.Columns()
	require.NoError(t, err)
	require.Len(t, names, 4, "EXPLAIN QUERY PLAN shape changed")

	plan := make([]queryPlanRow, 0, 8)
	for rows.Next() {
		var row queryPlanRow
		var unused int64
		require.NoError(t, rows.Scan(&row.id, &row.parent, &unused, &row.detail))
		plan = append(plan, row)
	}
	require.NoError(t, rows.Err())
	return plan
}

func formatQueryPlan(plan []queryPlanRow) string {
	var out strings.Builder
	for _, row := range plan {
		out.WriteString("  ")
		out.WriteString(row.detail)
		out.WriteString("\n")
	}
	return out.String()
}

func openSearchPlanDatabase(t *testing.T) *sql.DB {
	t.Helper()
	store, err := New(t.Context(), filepath.Join(t.TempDir(), "control.sqlite"))
	require.NoError(t, err)
	t.Cleanup(store.Close)
	return store.db
}
