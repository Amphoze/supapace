// Package store holds the control-plane database: schema, migrations, locks,
// placement and queries.
package store

// The blank import keeps the module requirement in go.mod until the package
// body that uses the pool exists.
import _ "github.com/jackc/pgx/v5/pgxpool"
