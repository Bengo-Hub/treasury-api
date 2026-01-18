# Sprint 1 – Authentication, RBAC & User Management

**Status**: ⏳ Not Started  
**Priority**: **CRITICAL - MUST BE FIRST SPRINT**  
**Start Date**: TBD  
**Duration**: 2-3 weeks

## Overview

Sprint 1 focuses on implementing service-level authentication, RBAC, permissions, and user management integrated with auth-service SSO. This is the foundation that all other features depend on - endpoints cannot be authenticated without this.

---

## Goals

1. Integrate auth-service SSO (JWT validation via `shared-auth-client`)
2. Implement service-specific RBAC for financial operations
3. Create user sync with auth-service
4. Define financial roles and permissions
5. Implement permission checking middleware
6. Create role assignment APIs

---

## Financial Roles & Permissions

### Roles

**1. Finance Admin**
- Full access to all financial operations
- Can manage users, roles, configurations
- Can approve/reject financial transactions

**2. Accountant**
- Can create/edit invoices, bills, journal entries
- Can process payments and refunds
- Can reconcile accounts
- Cannot approve high-value transactions

**3. Cashier**
- Can process payments
- Can issue receipts
- Can create payment intents
- Read-only access to financial reports

**4. Approver**
- Can approve invoices, bills, expenses
- Can approve journal entries
- Can approve refunds
- Cannot create transactions

**5. Finance Viewer**
- Read-only access to financial data
- Can view reports, invoices, payments
- Cannot modify any data

### Permissions

**Payment Permissions:**
- `treasury.payments.create` - Create payment intents
- `treasury.payments.process` - Process payments
- `treasury.payments.refund` - Process refunds
- `treasury.payments.approve` - Approve payments/refunds
- `treasury.payments.view` - View payment records

**Invoice Permissions:**
- `treasury.invoices.create` - Create invoices
- `treasury.invoices.edit` - Edit invoices
- `treasury.invoices.approve` - Approve invoices
- `treasury.invoices.send` - Send invoices
- `treasury.invoices.view` - View invoices

**Ledger Permissions:**
- `treasury.ledger.create` - Create journal entries
- `treasury.ledger.approve` - Approve journal entries
- `treasury.ledger.post` - Post journal entries
- `treasury.ledger.reverse` - Reverse entries
- `treasury.ledger.view` - View ledger

**Banking Permissions:**
- `treasury.banking.reconcile` - Reconcile accounts
- `treasury.banking.import` - Import bank statements
- `treasury.banking.view` - View bank accounts

**Expense Permissions:**
- `treasury.expenses.create` - Create expenses
- `treasury.expenses.approve` - Approve expenses
- `treasury.expenses.view` - View expenses

**Configuration Permissions:**
- `treasury.config.view` - View configuration
- `treasury.config.manage` - Manage configuration
- `treasury.users.manage` - Manage users and roles

---

## User Stories

### US-1.1: Auth-Service SSO Integration
**As a** system  
**I want** all requests validated via auth-service JWT tokens  
**So that** only authenticated users can access treasury endpoints

**Acceptance Criteria**:
- [ ] JWT validation middleware configured via `shared-auth-client`
- [ ] All `/api/v1/{tenantID}` routes protected
- [ ] Tenant ID extracted from JWT claims
- [ ] User ID extracted from JWT claims
- [ ] Unauthorized requests return 401

### US-1.2: User Synchronization
**As a** system  
**I want** users synced from auth-service  
**So that** treasury service has user references for financial operations

**Acceptance Criteria**:
- [ ] User sync service implemented (similar to logistics-service)
- [ ] Local user reference table (`treasury_users`)
- [ ] User sync on login/first access
- [ ] Consume `auth.user.created`, `auth.user.updated` events
- [ ] `auth_service_user_id` stored for reference

### US-1.3: Financial RBAC Implementation
**As a** finance administrator  
**I want** financial-specific roles and permissions  
**So that** users have appropriate access to financial operations

**Acceptance Criteria**:
- [ ] Ent schema for `treasury_roles` table
- [ ] Ent schema for `treasury_permissions` table
- [ ] Ent schema for `role_permissions` junction table
- [ ] Ent schema for `user_role_assignments` table
- [ ] Seed data for 5 default roles (Finance Admin, Accountant, Cashier, Approver, Viewer)
- [ ] Seed data for all financial permissions
- [ ] Role-permission mappings defined

### US-1.4: Permission Middleware
**As a** system  
**I want** permission checking middleware  
**So that** endpoints enforce RBAC

**Acceptance Criteria**:
- [ ] `RequirePermission(permission string)` middleware
- [ ] `RequireRole(role string)` middleware
- [ ] Permission check against user's assigned roles
- [ ] Forbidden (403) response for unauthorized access
- [ ] Superuser bypass (from JWT claims)

### US-1.5: Role Assignment API
**As a** finance administrator  
**I want** to assign roles to users  
**So that** users have appropriate permissions

**Acceptance Criteria**:
- [ ] `POST /api/v1/{tenantID}/rbac/assignments` - Assign role
- [ ] `GET /api/v1/{tenantID}/rbac/assignments` - List assignments
- [ ] `DELETE /api/v1/{tenantID}/rbac/assignments/{id}` - Revoke role
- [ ] Only Finance Admin can assign roles
- [ ] Audit log for role assignments

### US-1.6: User Management API
**As a** finance administrator  
**I want** to view treasury users  
**So that** I can manage access

**Acceptance Criteria**:
- [ ] `GET /api/v1/{tenantID}/users` - List users
- [ ] `GET /api/v1/{tenantID}/users/{id}` - Get user details
- [ ] `GET /api/v1/{tenantID}/users/{id}/roles` - Get user roles
- [ ] User sync status visible

---

## Database Schema

### treasury_users
- `id` (UUID, PK)
- `tenant_id` (UUID, FK → tenants)
- `auth_service_user_id` (UUID, UNIQUE) - Reference to auth-service
- `email` (VARCHAR) - Denormalized for convenience
- `status` (VARCHAR) - active, inactive, suspended
- `sync_status` (VARCHAR) - synced, pending, failed
- `last_sync_at` (TIMESTAMPTZ)
- `created_at`, `updated_at` (TIMESTAMPTZ)

### treasury_roles
- `id` (UUID, PK)
- `tenant_id` (UUID, FK → tenants)
- `role_code` (VARCHAR) - finance_admin, accountant, cashier, approver, viewer
- `name` (VARCHAR) - Display name
- `description` (TEXT)
- `is_system_role` (BOOLEAN) - System roles cannot be deleted
- `created_at`, `updated_at` (TIMESTAMPTZ)

### treasury_permissions
- `id` (UUID, PK)
- `permission_code` (VARCHAR, UNIQUE) - treasury.payments.create, etc.
- `name` (VARCHAR)
- `module` (VARCHAR) - payments, invoices, ledger, banking, expenses
- `action` (VARCHAR) - create, edit, approve, view, delete
- `resource` (VARCHAR) - payments, invoices, etc.
- `description` (TEXT)
- `created_at` (TIMESTAMPTZ)

### role_permissions
- `role_id` (UUID, FK → treasury_roles)
- `permission_id` (UUID, FK → treasury_permissions)
- Composite PK: (role_id, permission_id)

### user_role_assignments
- `id` (UUID, PK)
- `tenant_id` (UUID, FK → tenants)
- `user_id` (UUID, FK → treasury_users)
- `role_id` (UUID, FK → treasury_roles)
- `assigned_by` (UUID, FK → treasury_users)
- `assigned_at` (TIMESTAMPTZ)
- `expires_at` (TIMESTAMPTZ, Optional)
- Unique constraint: (tenant_id, user_id, role_id)

---

## API Endpoints

### User Management
- `GET /api/v1/{tenantID}/users` - List treasury users
- `GET /api/v1/{tenantID}/users/{id}` - Get user details
- `GET /api/v1/{tenantID}/users/{id}/roles` - Get user roles

### RBAC Management
- `GET /api/v1/{tenantID}/roles` - List all roles
- `GET /api/v1/{tenantID}/roles/{id}` - Get role details
- `GET /api/v1/{tenantID}/permissions` - List all permissions
- `POST /api/v1/{tenantID}/rbac/assignments` - Assign role to user
- `GET /api/v1/{tenantID}/rbac/assignments` - List role assignments
- `DELETE /api/v1/{tenantID}/rbac/assignments/{id}` - Revoke role

---

## Integration Points

### Auth Service
- **JWT Validation**: Via `shared-auth-client` middleware
- **User Sync**: Via `shared-service-client` HTTP calls
- **Event Consumption**: `auth.user.*`, `auth.tenant.*` events

### User Sync Service
- Uses `shared-service-client` for HTTP calls
- Syncs users on first access
- Stores `auth_service_user_id` reference only

---

## Implementation Tasks

- [x] Create Ent schemas for RBAC (treasury_users, treasury_roles, treasury_permissions, role_permissions, user_role_assignments)
- [x] Implement user sync service (similar to logistics-service)
- [x] Create RBAC service layer
- [x] Create RBAC repository layer
- [x] Implement permission middleware
- [x] Create role assignment handlers
- [x] Create user management handlers
- [x] Wire RBAC handlers to router
- [ ] Run Ent code generation (`go generate ./internal/ent`)
- [ ] Seed default roles and permissions (seed script)
- [ ] Add event listeners for auth.user.* events
- [ ] Test permission enforcement on endpoints

---

## Dependencies

- Ent ORM (for schemas)
- `shared-auth-client` (JWT validation)
- `shared-service-client` (user sync HTTP calls)
- `shared-events` (event consumption)

---

## Next Sprint

- Sprint 2: Payment Intents & Basic Payments (can only proceed after auth/RBAC is complete)

