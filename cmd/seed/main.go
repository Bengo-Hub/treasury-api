package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	"github.com/bengobox/treasury-app/internal/config"
	"github.com/bengobox/treasury-app/internal/ent"
	"github.com/bengobox/treasury-app/internal/ent/treasurypermission"
	"github.com/bengobox/treasury-app/internal/ent/treasuryrole"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("seed failed: %v", err)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Connect to database
	sqlDB, err := sql.Open("pgx", cfg.Postgres.URL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer sqlDB.Close()

	drv := entsql.OpenDB(dialect.Postgres, sqlDB)
	client := ent.NewClient(ent.Driver(drv))
	defer client.Close()

	ctx := context.Background()

	// Seed permissions
	if err := seedPermissions(ctx, client); err != nil {
		return fmt.Errorf("seed permissions: %w", err)
	}

	// Seed roles and assign permissions
	if err := seedRoles(ctx, client); err != nil {
		return fmt.Errorf("seed roles: %w", err)
	}

	log.Println("✅ Treasury Service seed data created successfully")
	return nil
}

func seedPermissions(ctx context.Context, client *ent.Client) error {
	permissions := []struct {
		code        string
		name        string
		module      string
		action      string
		resource    string
		description string
	}{
		// Payment permissions
		{"treasury.payments.create", "Create Payment Intent", "payments", "create", "payments", "Create payment intents"},
		{"treasury.payments.process", "Process Payments", "payments", "process", "payments", "Process payment transactions"},
		{"treasury.payments.refund", "Process Refunds", "payments", "refund", "payments", "Process refunds"},
		{"treasury.payments.approve", "Approve Payments", "payments", "approve", "payments", "Approve payments and refunds"},
		{"treasury.payments.view", "View Payments", "payments", "view", "payments", "View payment records"},

		// Invoice permissions
		{"treasury.invoices.create", "Create Invoices", "invoices", "create", "invoices", "Create invoices"},
		{"treasury.invoices.edit", "Edit Invoices", "invoices", "edit", "invoices", "Edit invoices"},
		{"treasury.invoices.approve", "Approve Invoices", "invoices", "approve", "invoices", "Approve invoices"},
		{"treasury.invoices.send", "Send Invoices", "invoices", "send", "invoices", "Send invoices to customers"},
		{"treasury.invoices.view", "View Invoices", "invoices", "view", "invoices", "View invoices"},

		// Ledger permissions
		{"treasury.ledger.create", "Create Journal Entries", "ledger", "create", "ledger", "Create journal entries"},
		{"treasury.ledger.approve", "Approve Journal Entries", "ledger", "approve", "ledger", "Approve journal entries"},
		{"treasury.ledger.post", "Post Journal Entries", "ledger", "post", "ledger", "Post journal entries"},
		{"treasury.ledger.reverse", "Reverse Entries", "ledger", "reverse", "ledger", "Reverse journal entries"},
		{"treasury.ledger.view", "View Ledger", "ledger", "view", "ledger", "View ledger entries"},

		// Banking permissions
		{"treasury.banking.reconcile", "Reconcile Accounts", "banking", "reconcile", "banking", "Reconcile bank accounts"},
		{"treasury.banking.import", "Import Bank Statements", "banking", "import", "banking", "Import bank statements"},
		{"treasury.banking.view", "View Bank Accounts", "banking", "view", "banking", "View bank accounts"},

		// Expense permissions
		{"treasury.expenses.create", "Create Expenses", "expenses", "create", "expenses", "Create expenses"},
		{"treasury.expenses.approve", "Approve Expenses", "expenses", "approve", "expenses", "Approve expenses"},
		{"treasury.expenses.view", "View Expenses", "expenses", "view", "expenses", "View expenses"},

		// Configuration permissions
		{"treasury.config.view", "View Configuration", "config", "view", "config", "View configuration"},
		{"treasury.config.manage", "Manage Configuration", "config", "manage", "config", "Manage configuration"},
		{"treasury.users.manage", "Manage Users", "users", "manage", "users", "Manage users and roles"},
	}

	for _, perm := range permissions {
		_, err := client.TreasuryPermission.Query().
			Where(treasurypermission.PermissionCode(perm.code)).
			Only(ctx)

		if err != nil {
			// Permission doesn't exist, create it
			builder := client.TreasuryPermission.Create().
				SetPermissionCode(perm.code).
				SetName(perm.name).
				SetModule(perm.module).
				SetAction(perm.action).
				SetDescription(perm.description)

			if perm.resource != "" {
				builder.SetResource(perm.resource)
			}

			if err := builder.Exec(ctx); err != nil {
				log.Printf("⚠️  Failed to create permission %s: %v", perm.code, err)
			} else {
				log.Printf("✅ Created permission: %s", perm.code)
			}
		}
	}

	return nil
}

func seedRoles(ctx context.Context, client *ent.Client) error {
	// Note: Roles are tenant-specific, so they should be seeded per tenant
	// This is a template that can be used in a tenant-specific seed function

	log.Println("⚠️  Roles are tenant-specific and should be seeded per tenant")
	log.Println("   Use this template to create roles for each tenant during onboarding")

	return nil
}

func seedTenantRoles(ctx context.Context, client *ent.Client, tenantID uuid.UUID) error {
	roles := []struct {
		code        string
		name        string
		description string
		permissions []string // permission codes
	}{
		{
			code:        "finance_admin",
			name:        "Finance Administrator",
			description: "Full access to all financial operations",
			permissions: []string{
				"treasury.payments.*",
				"treasury.invoices.*",
				"treasury.ledger.*",
				"treasury.banking.*",
				"treasury.expenses.*",
				"treasury.config.*",
				"treasury.users.manage",
			},
		},
		{
			code:        "accountant",
			name:        "Accountant",
			description: "Can create/edit invoices, bills, journal entries and process payments",
			permissions: []string{
				"treasury.payments.create",
				"treasury.payments.process",
				"treasury.payments.refund",
				"treasury.payments.view",
				"treasury.invoices.create",
				"treasury.invoices.edit",
				"treasury.invoices.view",
				"treasury.ledger.create",
				"treasury.ledger.view",
				"treasury.banking.reconcile",
				"treasury.banking.view",
				"treasury.expenses.create",
				"treasury.expenses.view",
			},
		},
		{
			code:        "cashier",
			name:        "Cashier",
			description: "Can process payments and issue receipts",
			permissions: []string{
				"treasury.payments.create",
				"treasury.payments.process",
				"treasury.payments.view",
				"treasury.invoices.view",
			},
		},
		{
			code:        "approver",
			name:        "Approver",
			description: "Can approve invoices, bills, expenses and journal entries",
			permissions: []string{
				"treasury.payments.approve",
				"treasury.payments.view",
				"treasury.invoices.approve",
				"treasury.invoices.view",
				"treasury.ledger.approve",
				"treasury.ledger.post",
				"treasury.ledger.view",
				"treasury.expenses.approve",
				"treasury.expenses.view",
			},
		},
		{
			code:        "viewer",
			name:        "Finance Viewer",
			description: "Read-only access to financial data",
			permissions: []string{
				"treasury.payments.view",
				"treasury.invoices.view",
				"treasury.ledger.view",
				"treasury.banking.view",
				"treasury.expenses.view",
				"treasury.config.view",
			},
		},
	}

	for _, roleData := range roles {
		// Check if role exists
		_, err := client.TreasuryRole.Query().
			Where(
				treasuryrole.TenantID(tenantID),
				treasuryrole.RoleCode(roleData.code),
			).
			Only(ctx)

		if err != nil {
			// Role doesn't exist, create it
			role, err := client.TreasuryRole.Create().
				SetTenantID(tenantID).
				SetRoleCode(roleData.code).
				SetName(roleData.name).
				SetDescription(roleData.description).
				SetIsSystemRole(true).
				Save(ctx)
			if err != nil {
				return fmt.Errorf("create role %s: %w", roleData.code, err)
			}

			// Assign permissions to role
			for _, permCode := range roleData.permissions {
				// Handle wildcard permissions (e.g., "treasury.payments.*")
				if permCode[len(permCode)-1] == '*' {
					prefix := permCode[:len(permCode)-2] // Remove ".*"
					permissions, err := client.TreasuryPermission.Query().
						Where(treasurypermission.PermissionCodeHasPrefix(prefix)).
						All(ctx)
					if err != nil {
						log.Printf("⚠️  Failed to find permissions for %s: %v", permCode, err)
						continue
					}
					for _, perm := range permissions {
						_, err := client.RolePermission.Create().
							SetRoleID(role.ID).
							SetPermissionID(perm.ID).
							Save(ctx)
						if err != nil {
							log.Printf("⚠️  Failed to assign permission %s to role %s: %v", perm.PermissionCode, roleData.code, err)
						}
					}
				} else {
					perm, err := client.TreasuryPermission.Query().
						Where(treasurypermission.PermissionCode(permCode)).
						Only(ctx)
					if err != nil {
						log.Printf("⚠️  Failed to find permission %s: %v", permCode, err)
						continue
					}
					_, err = client.RolePermission.Create().
						SetRoleID(role.ID).
						SetPermissionID(perm.ID).
						Save(ctx)
					if err != nil {
						log.Printf("⚠️  Failed to assign permission %s to role %s: %v", permCode, roleData.code, err)
					}
				}
			}

			log.Printf("✅ Created role: %s (%s)", roleData.name, roleData.code)
		}
	}

	return nil
}
