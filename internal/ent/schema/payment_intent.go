package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// PaymentIntent holds the schema definition for payment intents.
type PaymentIntent struct {
	ent.Schema
}

// Fields of the PaymentIntent.
func (PaymentIntent) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("tenant_id", uuid.UUID{}).
			Comment("Tenant identifier"),
		field.String("reference_id").
			NotEmpty().
			Comment("External reference ID (e.g., order_id)"),
		field.String("reference_type").
			NotEmpty().
			Comment("Reference type (order, subscription, invoice)"),
		field.String("payment_method").
			NotEmpty().
			Comment("Payment method (mpesa, stripe, cash, bank_transfer)"),
		field.String("currency").
			Default("KES").
			Comment("ISO currency code"),
		field.Float("amount").
			GoType(decimal.Decimal{}).
			Comment("Payment amount"),
		field.String("status").
			Default("pending").
			Comment("Status: pending, processing, succeeded, failed, cancelled"),
		field.JSON("metadata", map[string]any{}).
			Default(map[string]any{}).
			Comment("Additional metadata"),
		field.UUID("customer_id", uuid.UUID{}).
			Optional().
			Comment("Customer identifier (from auth-service)"),
		field.String("description").
			Optional().
			Comment("Payment description"),
		field.Time("expires_at").
			Optional().
			Comment("Payment intent expiry time"),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Indexes of the PaymentIntent.
func (PaymentIntent) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id"),
		index.Fields("tenant_id", "reference_id").Unique(), // Unique per tenant
		index.Fields("status"),
		index.Fields("payment_method"),
		index.Fields("created_at"),
		index.Fields("tenant_id", "status"),
		index.Fields("customer_id"),
	}
}
