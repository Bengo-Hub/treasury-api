package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// PaymentTransaction holds the schema definition for payment transactions.
type PaymentTransaction struct {
	ent.Schema
}

// Fields of the PaymentTransaction.
func (PaymentTransaction) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("tenant_id", uuid.UUID{}).
			Comment("Tenant identifier"),
		field.UUID("payment_intent_id", uuid.UUID{}).
			Comment("Payment intent identifier"),
		field.String("transaction_type").
			NotEmpty().
			Comment("Transaction type: payment, refund, chargeback, adjustment"),
		field.Float("amount").
			GoType(decimal.Decimal{}).
			Comment("Transaction amount"),
		field.String("currency").
			Default("KES").
			Comment("ISO currency code"),
		field.String("provider").
			NotEmpty().
			Comment("Payment provider: mpesa, stripe, paypal, blockchain"),
		field.String("provider_reference").
			NotEmpty().
			Comment("Provider transaction reference"),
		field.String("status").
			Default("pending").
			Comment("Status: pending, processing, succeeded, failed, cancelled"),
		field.Time("processed_at").
			Optional().
			Comment("Processing timestamp"),
		field.JSON("metadata", map[string]any{}).
			Default(map[string]any{}),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Indexes of the PaymentTransaction.
func (PaymentTransaction) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id"),
		index.Fields("payment_intent_id"),
		index.Fields("provider_reference"),
		index.Fields("status"),
		index.Fields("processed_at"),
		index.Fields("tenant_id", "status"),
	}
}
