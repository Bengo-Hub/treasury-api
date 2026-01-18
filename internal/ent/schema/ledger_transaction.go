package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// LedgerTransaction holds the schema definition for ledger transactions (double-entry).
type LedgerTransaction struct {
	ent.Schema
}

// Fields of the LedgerTransaction.
func (LedgerTransaction) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("tenant_id", uuid.UUID{}).
			Comment("Tenant identifier"),
		field.UUID("account_id", uuid.UUID{}).
			Comment("Account identifier"),
		field.UUID("journal_entry_id", uuid.UUID{}).
			Optional().
			Comment("Journal entry identifier"),
		field.Float("debit_amount").
			GoType(decimal.Decimal{}).
			Default(0).
			Comment("Debit amount"),
		field.Float("credit_amount").
			GoType(decimal.Decimal{}).
			Default(0).
			Comment("Credit amount"),
		field.String("currency").
			Default("KES").
			Comment("ISO currency code"),
		field.Float("exchange_rate").
			GoType(decimal.Decimal{}).
			Default(1.0).
			Comment("FX rate for multi-currency"),
		field.String("reference_type").
			Optional().
			Comment("Reference entity type (invoice, bill, payment)"),
		field.UUID("reference_id", uuid.UUID{}).
			Optional().
			Comment("Reference entity ID"),
		field.Time("transaction_date").
			Comment("Transaction date"),
		field.Text("description").
			Optional(),
		field.JSON("metadata", map[string]any{}).
			Default(map[string]any{}),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

// Edges of the LedgerTransaction.
func (LedgerTransaction) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("account", ChartOfAccount.Type).
			Field("account_id").
			Required().
			Unique(),
	}
}

// Indexes of the LedgerTransaction.
func (LedgerTransaction) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id"),
		index.Fields("account_id"),
		index.Fields("journal_entry_id"),
		index.Fields("transaction_date"),
		index.Fields("reference_type", "reference_id"),
		index.Fields("created_at"),
	}
}

