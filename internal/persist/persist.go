// Package persist provides persistent storage for scan sessions,
// findings, and agent execution traces using SQLite.
package persist

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps a SQLite connection with domain-specific methods.
type DB struct {
	conn *sql.DB
}

// ScanSession represents a stored scan session.
type ScanSession struct {
	ID          string     `json:"id"`
	Target      string     `json:"target"`
	Intent      string     `json:"intent"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Summary     string     `json:"summary,omitempty"`
	Config      string     `json:"config,omitempty"` // JSON blob
}

// StoredFinding represents a persisted finding.
type StoredFinding struct {
	ID           string    `json:"id"`
	SessionID    string    `json:"session_id"`
	Type         string    `json:"type"`
	Severity     string    `json:"severity"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	Evidence     string    `json:"evidence"`
	Target       string    `json:"target"`
	ToolName     string    `json:"tool_name"`
	DiscoveredAt time.Time `json:"discovered_at"`
	Metadata     string    `json:"metadata,omitempty"` // JSON blob
}

// Open creates or opens a SQLite database at the given path.
func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	conn.SetMaxOpenConns(1) // SQLite is single-writer

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return db, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// migrate creates tables if they don't exist.
func (db *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS scan_sessions (
		id TEXT PRIMARY KEY,
		target TEXT NOT NULL,
		intent TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'running',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		completed_at DATETIME,
		summary TEXT,
		config TEXT
	);

	CREATE TABLE IF NOT EXISTS findings (
		id TEXT PRIMARY KEY,
		session_id TEXT NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
		type TEXT NOT NULL DEFAULT 'unknown',
		severity TEXT NOT NULL DEFAULT 'info',
		title TEXT NOT NULL,
		description TEXT,
		evidence TEXT,
		target TEXT,
		tool_name TEXT,
		discovered_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		metadata TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
	CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
	CREATE INDEX IF NOT EXISTS idx_sessions_target ON scan_sessions(target);

	CREATE TABLE IF NOT EXISTS agent_runs (
		id TEXT PRIMARY KEY,
		session_id TEXT REFERENCES scan_sessions(id),
		goal TEXT,
		plan_json TEXT,
		result_json TEXT,
		started_at DATETIME,
		completed_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS completed_operations (
		target_id TEXT NOT NULL,
		operation TEXT NOT NULL,
		completed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (target_id, operation)
	);

	CREATE INDEX IF NOT EXISTS idx_completed_ops_target ON completed_operations(target_id);
	`

	_, err := db.conn.Exec(schema)
	return err
}

// ── Scan Sessions ──────────────────────────────────────────────────

// CreateSession inserts a new scan session.
func (db *DB) CreateSession(session *ScanSession) error {
	_, err := db.conn.Exec(
		`INSERT INTO scan_sessions (id, target, intent, status, created_at, config)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		session.ID, session.Target, session.Intent, session.Status,
		session.CreatedAt, session.Config,
	)
	return err
}

// UpdateSession updates a scan session's status and summary.
func (db *DB) UpdateSession(id, status, summary string) error {
	now := time.Now()
	_, err := db.conn.Exec(
		`UPDATE scan_sessions SET status = ?, summary = ?, completed_at = ? WHERE id = ?`,
		status, summary, now, id,
	)
	return err
}

// GetSession retrieves a scan session by ID.
func (db *DB) GetSession(id string) (*ScanSession, error) {
	row := db.conn.QueryRow(
		`SELECT id, target, intent, status, created_at, completed_at, summary, config
		 FROM scan_sessions WHERE id = ?`, id,
	)

	var s ScanSession
	var completedAt sql.NullTime
	var summary sql.NullString
	var config sql.NullString

	err := row.Scan(&s.ID, &s.Target, &s.Intent, &s.Status,
		&s.CreatedAt, &completedAt, &summary, &config)
	if err != nil {
		return nil, err
	}

	if completedAt.Valid {
		s.CompletedAt = &completedAt.Time
	}
	if summary.Valid {
		s.Summary = summary.String
	}
	if config.Valid {
		s.Config = config.String
	}

	return &s, nil
}

// ListSessions returns all scan sessions, most recent first.
func (db *DB) ListSessions(limit int) ([]*ScanSession, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := db.conn.Query(
		`SELECT id, target, intent, status, created_at, completed_at, summary, config
		 FROM scan_sessions ORDER BY created_at DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*ScanSession
	for rows.Next() {
		var s ScanSession
		var completedAt sql.NullTime
		var summary sql.NullString
		var config sql.NullString

		if err := rows.Scan(&s.ID, &s.Target, &s.Intent, &s.Status,
			&s.CreatedAt, &completedAt, &summary, &config); err != nil {
			return nil, err
		}

		if completedAt.Valid {
			s.CompletedAt = &completedAt.Time
		}
		if summary.Valid {
			s.Summary = summary.String
		}
		if config.Valid {
			s.Config = config.String
		}

		sessions = append(sessions, &s)
	}

	return sessions, rows.Err()
}

// ListSessionsByTarget returns sessions for a specific target.
func (db *DB) ListSessionsByTarget(target string, limit int) ([]*ScanSession, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := db.conn.Query(
		`SELECT id, target, intent, status, created_at, completed_at, summary, config
		 FROM scan_sessions WHERE target = ? ORDER BY created_at DESC LIMIT ?`,
		target, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*ScanSession
	for rows.Next() {
		var s ScanSession
		var completedAt sql.NullTime
		var summary sql.NullString
		var config sql.NullString

		if err := rows.Scan(&s.ID, &s.Target, &s.Intent, &s.Status,
			&s.CreatedAt, &completedAt, &summary, &config); err != nil {
			return nil, err
		}

		if completedAt.Valid {
			s.CompletedAt = &completedAt.Time
		}
		if summary.Valid {
			s.Summary = summary.String
		}
		if config.Valid {
			s.Config = config.String
		}

		sessions = append(sessions, &s)
	}

	return sessions, rows.Err()
}

// ── Findings ───────────────────────────────────────────────────────

// SaveFinding stores a single finding.
func (db *DB) SaveFinding(f *StoredFinding) error {
	_, err := db.conn.Exec(
		`INSERT OR REPLACE INTO findings (id, session_id, type, severity, title, description, evidence, target, tool_name, discovered_at, metadata)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.SessionID, f.Type, f.Severity, f.Title, f.Description,
		f.Evidence, f.Target, f.ToolName, f.DiscoveredAt, f.Metadata,
	)
	return err
}

// SaveFindings bulk-inserts findings.
func (db *DB) SaveFindings(findings []*StoredFinding) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		`INSERT OR REPLACE INTO findings (id, session_id, type, severity, title, description, evidence, target, tool_name, discovered_at, metadata)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, f := range findings {
		if _, err := stmt.Exec(f.ID, f.SessionID, f.Type, f.Severity, f.Title,
			f.Description, f.Evidence, f.Target, f.ToolName, f.DiscoveredAt, f.Metadata); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetFindings retrieves all findings for a session.
func (db *DB) GetFindings(sessionID string) ([]*StoredFinding, error) {
	rows, err := db.conn.Query(
		`SELECT id, session_id, type, severity, title, description, evidence, target, tool_name, discovered_at, metadata
		 FROM findings WHERE session_id = ? ORDER BY severity, discovered_at DESC`, sessionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []*StoredFinding
	for rows.Next() {
		var f StoredFinding
		var metadata sql.NullString
		if err := rows.Scan(&f.ID, &f.SessionID, &f.Type, &f.Severity, &f.Title,
			&f.Description, &f.Evidence, &f.Target, &f.ToolName, &f.DiscoveredAt, &metadata); err != nil {
			return nil, err
		}
		if metadata.Valid {
			f.Metadata = metadata.String
		}
		findings = append(findings, &f)
	}

	return findings, rows.Err()
}

// CountFindingsBySeverity counts findings grouped by severity for a session.
func (db *DB) CountFindingsBySeverity(sessionID string) (map[string]int, error) {
	rows, err := db.conn.Query(
		`SELECT severity, COUNT(*) FROM findings WHERE session_id = ? GROUP BY severity`, sessionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var sev string
		var count int
		if err := rows.Scan(&sev, &count); err != nil {
			return nil, err
		}
		counts[sev] = count
	}

	return counts, rows.Err()
}

// ── Agent Runs ─────────────────────────────────────────────────────

// SaveAgentRun stores an agent execution trace.
func (db *DB) SaveAgentRun(id, sessionID, goal string, plan, result interface{}) error {
	planJSON, _ := json.Marshal(plan)
	resultJSON, _ := json.Marshal(result)

	_, err := db.conn.Exec(
		`INSERT OR REPLACE INTO agent_runs (id, session_id, goal, plan_json, result_json, started_at, completed_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, sessionID, goal, string(planJSON), string(resultJSON), time.Now(), time.Now(),
	)
	return err
}

// ── Statistics ─────────────────────────────────────────────────────

// Stats holds aggregate statistics.
type Stats struct {
	TotalSessions int            `json:"total_sessions"`
	TotalFindings int            `json:"total_findings"`
	FindingsBySev map[string]int `json:"findings_by_severity"`
	RecentTargets []string       `json:"recent_targets"`
}

// GetStats returns aggregate statistics.
func (db *DB) GetStats() (*Stats, error) {
	stats := &Stats{}

	db.conn.QueryRow(`SELECT COUNT(*) FROM scan_sessions`).Scan(&stats.TotalSessions)
	db.conn.QueryRow(`SELECT COUNT(*) FROM findings`).Scan(&stats.TotalFindings)

	rows, err := db.conn.Query(`SELECT severity, COUNT(*) FROM findings GROUP BY severity`)
	if err == nil {
		stats.FindingsBySev = make(map[string]int)
		defer rows.Close()
		for rows.Next() {
			var sev string
			var count int
			rows.Scan(&sev, &count)
			stats.FindingsBySev[sev] = count
		}
	}

	rows2, err := db.conn.Query(`SELECT DISTINCT target FROM scan_sessions ORDER BY created_at DESC LIMIT 5`)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var target string
			rows2.Scan(&target)
			stats.RecentTargets = append(stats.RecentTargets, target)
		}
	}

	return stats, nil
}

// ── Completed Operations (session.Store) ────────────────────────────

// HasCompletedOperation checks if an operation has been completed for a target.
func (db *DB) HasCompletedOperation(targetID string, op string) (bool, error) {
	var count int
	err := db.conn.QueryRow(
		`SELECT COUNT(*) FROM completed_operations WHERE target_id = ? AND operation = ?`,
		targetID, op,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// MarkOperationComplete records that an operation has been completed for a target.
func (db *DB) MarkOperationComplete(targetID string, op string) error {
	_, err := db.conn.Exec(
		`INSERT OR REPLACE INTO completed_operations (target_id, operation, completed_at)
		 VALUES (?, ?, ?)`,
		targetID, op, time.Now(),
	)
	return err
}

// ListCompletedOperations returns all operations completed for a target.
func (db *DB) ListCompletedOperations(targetID string) ([]string, error) {
	rows, err := db.conn.Query(
		`SELECT operation FROM completed_operations WHERE target_id = ? ORDER BY completed_at DESC`,
		targetID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ops []string
	for rows.Next() {
		var op string
		if err := rows.Scan(&op); err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	return ops, rows.Err()
}
