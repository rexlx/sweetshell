package internal

import (
	"database/sql"
	"encoding/json"
	"time"

	_ "github.com/lib/pq"
)

var DB *sql.DB

func InitDB(connStr string) error {
	var err error
	DB, err = sql.Open("postgres", connStr)
	if err != nil {
		return err
	}

	// Optimized for high concurrency
	DB.SetMaxOpenConns(100)
	DB.SetMaxIdleConns(25)
	DB.SetConnMaxLifetime(time.Hour)

	if err = DB.Ping(); err != nil {
		return err
	}

	return setupSchema()
}

func setupSchema() error {
	// Idempotent table creation
	schema := `
	CREATE TABLE IF NOT EXISTS honeypots (
		id SERIAL PRIMARY KEY,
		name VARCHAR(255) UNIQUE NOT NULL,
		type VARCHAR(50)
	);
	CREATE TABLE IF NOT EXISTS activity_logs (
		id BIGSERIAL PRIMARY KEY,
		honeypot_id INTEGER REFERENCES honeypots(id),
		transaction_id TEXT NOT NULL,
		value TEXT NOT NULL,
		event_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		payload JSONB 
	);
	CREATE TABLE IF NOT EXISTS indicators (
		id SERIAL PRIMARY KEY,
		value TEXT UNIQUE NOT NULL,        
		reputation VARCHAR(20) DEFAULT 'unknown',
		occurrence_count INT DEFAULT 1,
		last_seen TIMESTAMP WITH TIME ZONE,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_logs_value ON activity_logs(value);
	`
	_, err := DB.Exec(schema)
	return err
}

func StoreActivity(honeypotName string, stat Stat) error {
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. Ensure the honeypot is registered
	var hpID int
	err = tx.QueryRow("INSERT INTO honeypots (name, type) VALUES ($1, 'generic') ON CONFLICT (name) DO UPDATE SET name=EXCLUDED.name RETURNING id", honeypotName).Scan(&hpID)
	if err != nil {
		return err
	}

	// 2. Insert raw log
	payloadBytes, _ := json.Marshal(stat.Payload)
	_, err = tx.Exec(`INSERT INTO activity_logs (honeypot_id, transaction_id, value, event_time, payload) VALUES ($1, $2, $3, $4, $5)`,
		hpID, stat.TransactionID, stat.Value, stat.Time, payloadBytes)
	if err != nil {
		return err
	}

	// 3. Inference Logic: Update reputation based on occurrence count
	_, err = tx.Exec(`
		INSERT INTO indicators (value, last_seen, occurrence_count)
		VALUES ($1, $2, 1)
		ON CONFLICT (value) DO UPDATE SET
			occurrence_count = indicators.occurrence_count + 1,
			last_seen = EXCLUDED.last_seen,
			reputation = CASE 
				WHEN indicators.occurrence_count + 1 > 10 THEN 'malicious'
				WHEN indicators.occurrence_count + 1 > 3 THEN 'suspicious'
				ELSE 'unknown'
			END,
			updated_at = CURRENT_TIMESTAMP`,
		stat.Value, stat.Time)

	return tx.Commit()
}
