package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// ChartOfAccount holds the schema definition for chart of accounts.
type ChartOfAccount struct {
	ent.Schema
}

// Fields of the ChartOfAccount.
func (ChartOfAccount) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("tenant_id", uuid.UUID{}).
			Comment("Tenant identifier"),
		field.String("account_code").
			NotEmpty().
			Comment("Account code (e.g., 1000, 2000)"),
		field.String("account_name").
			NotEmpty().
			Comment("Account name"),
		field.String("account_type").
			NotEmpty().
			Comment("Account type: asset, liability, equity, revenue, expense"),
		field.UUID("parent_id", uuid.UUID{}).
			Optional().
			Comment("Parent account for hierarchy"),
		field.Bool("is_active").
			Default(true),
		field.Text("description").
			Optional(),
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

// Edges of the ChartOfAccount.
func (ChartOfAccount) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("children", ChartOfAccount.Type).From("parent").Field("parent_id").Unique(),
	}
}

// Indexes of the ChartOfAccount.
func (ChartOfAccount) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id"),
		index.Fields("tenant_id", "account_code").Unique(),
		index.Fields("account_type"),
		index.Fields("parent_id"),
		index.Fields("is_active"),
	}
}

