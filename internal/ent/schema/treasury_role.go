package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// TreasuryRole holds the schema definition for treasury service roles.
type TreasuryRole struct {
	ent.Schema
}

// Fields of the TreasuryRole.
func (TreasuryRole) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("tenant_id", uuid.UUID{}).
			Comment("Tenant identifier"),
		field.String("role_code").
			NotEmpty().
			Comment("Role code: finance_admin, accountant, cashier, approver, viewer"),
		field.String("name").
			NotEmpty().
			Comment("Display name"),
		field.Text("description").
			Optional(),
		field.Bool("is_system_role").
			Default(false).
			Comment("System roles cannot be deleted"),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Edges of the TreasuryRole.
func (TreasuryRole) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("permissions", TreasuryPermission.Type).Through("role_permissions", RolePermission.Type),
		edge.To("user_assignments", UserRoleAssignment.Type),
	}
}

// Indexes of the TreasuryRole.
func (TreasuryRole) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id"),
		index.Fields("tenant_id", "role_code").Unique(),
		index.Fields("is_system_role"),
	}
}

