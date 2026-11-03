package secrets

import (
	"context"

	"github.com/jackc/pgx/v5"

	"coffer/internal/audit"
)

// ApplyAudited runs a direct write and its audit event in one transaction.
//
// The value and the record that it was written commit together: a crash cannot leave a value
// without its audit row, or an audit row describing a value that was never stored.
func (s *Store) ApplyAudited(ctx context.Context, w WriteRequest, writer audit.Writer, ev audit.Event) (Applied, error) {
	var out Applied
	err := s.InTx(ctx, func(tx pgx.Tx) error {
		applied, err := s.ApplyTx(ctx, tx, w)
		if err != nil {
			return err
		}
		out = applied
		return appendAudit(ctx, tx, writer, ev, actionForOp(w.Op),
			SecretTarget(w.Scope.ProjectID, w.Scope.EnvID, w.Key), audit.ResultSuccess)
	})
	if err != nil {
		return Applied{}, err
	}
	return out, nil
}

// CreateChangeAudited creates a pending change and its change.created event in one transaction.
func (s *Store) CreateChangeAudited(ctx context.Context, p Proposal, writer audit.Writer, ev audit.Event) (Change, error) {
	var ch Change
	err := s.InTx(ctx, func(tx pgx.Tx) error {
		created, err := s.CreateChangeTx(ctx, tx, p)
		if err != nil {
			return err
		}
		ch = created
		return appendAudit(ctx, tx, writer, ev, audit.ActionChangeCreated,
			ChangeTarget(created.ID), audit.ResultSuccess)
	})
	if err != nil {
		return Change{}, err
	}
	return ch, nil
}

// AuditRead records one secret.read for one key. Values leave the server through a single-key get,
// an export or run, and each of those writes exactly one event per key read.
//
// It is deliberately a plain append rather than a transaction: the read has already happened by the
// time a value is returned, so there is no state for the event to be atomic with. A nil writer is a
// no-op.
func AuditRead(ctx context.Context, writer audit.Writer, ev audit.Event, projectID, envID, key string) error {
	if writer == nil {
		return nil
	}
	ev.Action = audit.ActionSecretRead
	ev.Target = SecretTarget(projectID, envID, key)
	ev.Result = audit.ResultSuccess
	_, err := writer.Append(ctx, ev)
	return err
}
