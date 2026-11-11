// Package journal defines the backend-neutral transaction contract for the
// M0 host lifecycle journal. It deliberately supplies no database driver or
// storage implementation. A concrete adapter must satisfy the transaction,
// generation-fencing, append-only, and durability requirements in the M0
// supervisor/journal implementation contract before it can be enabled.
package journal
