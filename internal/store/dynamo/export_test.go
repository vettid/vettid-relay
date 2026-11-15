package dynamo

// SetBeforeRevive sets a hook that runs between Register's read of a dead
// mailbox and its revive (tests only).
func SetBeforeRevive(s *Store, f func()) { s.beforeRevive = f }
