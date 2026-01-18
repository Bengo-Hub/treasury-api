package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// Invoice holds the schema definition for invoices.
type Invoice struct {
	ent.Schema
}

// Fields of the Invoice.
func (Invoice) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("tenant_id", uuid.UUID{}).
			Comment("Tenant identifier"),
		field.String("invoice_number").
			NotEmpty().
			Comment("Sequential invoice number"),
		field.UUID("customer_id", uuid.UUID{}).
			Optional().
			Comment("Customer identifier (from auth-service)"),
		field.String("invoice_type").
			Default("standard").
			Comment("Invoice type: standard, tax, proforma, recurring, credit_note, debit_note"),
		field.Time("invoice_date").
			Comment("Invoice date"),
		field.Time("due_date").
			Comment("Due date"),
		field.Float("subtotal").
			GoType(decimal.Decimal{}).
			Comment("Subtotal amount"),
		field.Float("tax_amount").
			GoType(decimal.Decimal{}).
			Default(0).
			Comment("Tax amount"),
		field.Float("total_amount").
			GoType(decimal.Decimal{}).
			Comment("Total amount"),
		field.String("currency").
			Default("KES").
			Comment("ISO currency code"),
		field.String("status").
			Default("draft").
			Comment("Status: draft, sent, paid, overdue, cancelled"),
		field.String("payment_status").
			Default("unpaid").
			Comment("Payment status: unpaid, partial, paid, overpaid"),
		field.UUID("reference_id", uuid.UUID{}).
			Optional().
			Comment("Reference ID (e.g., order_id, subscription_id)"),
		field.String("reference_type").
			Optional().
			Comment("Reference type (order, subscription)"),
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

// Indexes of the Invoice.
func (Invoice) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id"),
		index.Fields("tenant_id", "invoice_number").Unique(),
		index.Fields("customer_id"),
		index.Fields("status"),
		index.Fields("payment_status"),
		index.Fields("invoice_date"),
		index.Fields("due_date"),
		index.Fields("tenant_id", "status"),
	}
}

