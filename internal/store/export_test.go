package store

import "context"

// PlantLifetimeMark stores raw as the lifetime mark as it is, past every
// check (a mark stored by hand or by an older version). SQLite keeps it
// with the column's integer affinity: an integer, else a real or text.
func PlantLifetimeMark(s *Store, raw string) error {
	_, err := s.w.ExecContext(context.Background(),
		`INSERT INTO lifetime_mark (id, lifetime_ms) VALUES (1, ?)
		 ON CONFLICT(id) DO UPDATE SET lifetime_ms=excluded.lifetime_ms`, raw)
	return err
}
