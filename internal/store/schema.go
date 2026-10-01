package store

import (
	"context"
	"database/sql"
	"fmt"
)

// schemaVersion is bumped with every migration appended to migrations.
const schemaVersion = 1

// migrations[i] upgrades the schema from version i to i+1.
//
// Times are unix milliseconds (UTC). Large BLOB columns are declared last so
// that quota scans over fixed-size columns never touch overflow pages.
var migrations = []string{
	`
CREATE TABLE mailboxes (
  mailbox_id   TEXT PRIMARY KEY,
  pubkey       BLOB NOT NULL,
  created_at   INTEGER NOT NULL,
  delete_after INTEGER,           -- set when rotated away (grace period end)
  successor_id TEXT,
  quota_bytes  INTEGER,           -- reserved: per-mailbox override (NULL = relay default)
  quota_msgs   INTEGER
);

CREATE TABLE messages (
  msg_id       TEXT PRIMARY KEY,  -- ULID, arrival order within a mailbox
  mailbox_id   TEXT NOT NULL REFERENCES mailboxes(mailbox_id) ON DELETE CASCADE,
  size         INTEGER NOT NULL,
  deposited_at INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  leased_until INTEGER,           -- visibility timeout
  sender_sub   TEXT NOT NULL,     -- abuse attribution
  payload      BLOB NOT NULL
);
CREATE INDEX idx_messages_collect ON messages(mailbox_id, msg_id);
CREATE INDEX idx_messages_expiry  ON messages(expires_at);

CREATE TABLE denylist (
  mailbox_id TEXT NOT NULL REFERENCES mailboxes(mailbox_id) ON DELETE CASCADE,
  kind       TEXT NOT NULL CHECK (kind IN ('jti','sub')),
  value      TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (mailbox_id, kind, value)
);
CREATE INDEX idx_denylist_expiry ON denylist(expires_at);

CREATE TABLE token_usage (
  mailbox_id TEXT NOT NULL REFERENCES mailboxes(mailbox_id) ON DELETE CASCADE,
  jti        TEXT NOT NULL,
  msgs       INTEGER NOT NULL,
  bytes      INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,     -- token exp; counters are useless afterwards
  PRIMARY KEY (mailbox_id, jti)
);
CREATE INDEX idx_token_usage_expiry ON token_usage(expires_at);

CREATE TABLE blobs (
  blob_id    TEXT PRIMARY KEY,     -- ULID
  mailbox_id TEXT NOT NULL REFERENCES mailboxes(mailbox_id) ON DELETE CASCADE,
  size       INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  sender_sub TEXT NOT NULL,
  data       BLOB NOT NULL
);
CREATE INDEX idx_blobs_mailbox ON blobs(mailbox_id);
CREATE INDEX idx_blobs_expiry  ON blobs(expires_at);
`,
}

func migrate(ctx context.Context, db *sql.DB) error {
	var v int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if v > schemaVersion {
		return fmt.Errorf("database schema version %d is newer than this binary (%d)", v, schemaVersion)
	}
	for ; v < schemaVersion; v++ {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[v]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", v+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", v+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
