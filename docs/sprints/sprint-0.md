# Sprint 0 – Foundation & Bootstrap

**Status**: ✅ Completed  
**Start Date**: 2025-01-17  
**Completion Date**: 2025-01-17

## Goals

- Bootstrap treasury service with proper structure
- Set up Ent ORM for schema-as-code migrations
- Integrate shared libraries (auth-client, service-client, events)
- Configure outbox pattern for reliable event publishing
- Set up health checks and observability

## Completed Tasks

### Infrastructure Setup
- [x] Go module configuration (`go.mod`)
- [x] Configuration loading (`internal/config/config.go`)
- [x] Logger setup (`internal/shared/logger`)
- [x] Database connection pool (`internal/platform/database`)
- [x] Redis client (`internal/platform/cache`)
- [x] NATS connection (`internal/platform/events`)
- [x] HTTP server bootstrap (`internal/app/app.go`)
- [x] Router setup with middleware (`internal/http/router/router.go`)
- [x] Health checks (`internal/http/handlers/health.go`)
- [x] Auth middleware integration (`shared-auth-client`)

### Ent ORM Setup
- [x] Added `entgo.io/ent` dependency
- [x] Created `internal/ent/generate.go`
- [x] Configured Ent code generation

### Shared Libraries Integration
- [x] `shared-auth-client` for JWT validation
- [x] `shared-service-client` for service-to-service HTTP calls
- [x] `shared-events` for outbox pattern event publishing

### Outbox Pattern
- [x] Created `internal/ent/schema/outboxevent.go`
- [x] Created `internal/modules/outbox/repository.go`
- [x] Integrated outbox publisher in `app.go`
- [x] Background publisher worker started

## Implementation Progress (2025-01-17)

### Ent ORM Setup
- [x] Created payment_intent schema
- [x] Created payment_transaction schema  
- [x] Created invoice schema
- [x] Created chart_of_accounts schema
- [x] Created ledger_transaction schema
- [x] Created repository interface for payments
- [x] Started Ent repository implementation
- [ ] Ent code generation (pending go generate after dependency fixes)
- [ ] Ent client initialization in app.go (pending)

### Next Steps

- **Sprint 1 (CRITICAL)**: Authentication, RBAC & User Management (MUST BE FIRST)
  - Auth-service SSO integration
  - Service-specific financial RBAC
  - User sync and role assignment
- Sprint 2: Payment Intents & Basic Payments (service layer, handlers)
- Sprint 2: M-Pesa Integration
- Sprint 3: Stripe Integration
- Sprint 4: Invoice Generation (complete implementation)
- Sprint 5: General Ledger (complete implementation)
- Sprint 6: Billing Event Consumption

