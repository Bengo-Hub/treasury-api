package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// TreasuryPermission holds the schema definition for treasury service permissions.
type TreasuryPermission struct {
	ent.Schema
}

// Fields of the TreasuryPermission.
func (TreasuryPermission) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.String("permission_code").
			NotEmpty().
			Unique().
			Comment("Permission code: treasury.payments.create, etc."),
		field.String("name").
			NotEmpty().
			Comment("Display name"),
		field.String("module").
			NotEmpty().
			Comment("Module: payments, invoices, ledger, banking, expenses"),
		field.String("action").
			NotEmpty().
			Comment("Action: create, edit, approve, view, delete"),
		field.String("resource").
			Optional().
			Comment("Resource: payments, invoices, etc."),
		field.Text("description").
			Optional(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

// Edges of the TreasuryPermission.
func (TreasuryPermission) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("roles", TreasuryRole.Type).Ref("permissions").Through("role_permissions", RolePermission.Type),
	}
}

// Indexes of the TreasuryPermission.
func (TreasuryPermission) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("permission_code").Unique(),
		index.Fields("module"),
		index.Fields("action"),
		index.Fields("module", "action"),
	}
}
