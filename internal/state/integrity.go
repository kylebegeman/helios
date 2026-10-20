package state

import (
	"context"
	"database/sql"
	"fmt"
)

// integrityLimit is how many problems one integrity check reports.
const integrityLimit = 10

// IntegrityCheck runs SQLite's integrity check on the database at path,
// which needn't be Helios's own, and returns the problems it found: none
// when the database is sound. The file is opened for writing so that a
// write-ahead log or hot journal beside it is read as the database's own
// program would read it; the connection itself writes nothing.
func IntegrityCheck(ctx context.Context, path string) ([]string, error) {
	db, err := sql.Open("sqlite", "file:"+dsnPath.Replace(path)+"?_pragma=busy_timeout(5000)&_pragma=query_only(ON)")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	rows, err := db.QueryContext(ctx, fmt.Sprintf("PRAGMA integrity_check(%d)", integrityLimit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var problems []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return nil, err
		}
		if line != "ok" {
			problems = append(problems, line)
		}
	}
	return problems, rows.Err()
}
