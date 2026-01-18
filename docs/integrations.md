# Treasury Service - Integration Guide

## Overview

This document provides detailed integration information for all external services and systems integrated with the Treasury service.

---

## Table of Contents

1. [Internal BengoBox Service Integrations](#internal-bengobox-service-integrations)
2. [External Third-Party Integrations](#external-third-party-integrations)
3. [Integration Patterns](#integration-patterns)
4. [Two-Tier Configuration Management](#two-tier-configuration-management)
5. [Event-Driven Architecture](#event-driven-architecture)
6. [Integration Security](#integration-security)
7. [Error Handling & Resilience](#error-handling--resilience)

---

## Internal BengoBox Service Integrations

### Auth Service

**Integration Type**: OAuth2/OIDC + Events + REST

**Use Cases**:
- User authentication and authorization
- JWT token validation
- User identity synchronization
- Tenant/outlet discovery

**Architecture**:
- Uses `shared/auth-client` v0.1.0 library for JWT validation
- All protected `/api/v1/{tenantID}` routes require valid Bearer tokens

**Events Consumed**:
- `auth.tenant.created` - Initialize tenant in treasury system
- `auth.tenant.updated` - Update tenant metadata
- `auth.outlet.created` - Create outlet reference
- `auth.outlet.updated` - Update outlet metadata

### Cafe Backend

**Integration Type**: REST API + Events (NATS) + Webhooks

**Use Cases**:
- Order payment processing
- Invoice generation
- Payment status updates
- Subscription billing

**REST API Usage**:
- `POST /api/v1/payments/intents` - Create payment intent
- `POST /api/v1/payments/confirm` - Confirm payment
- `POST /api/v1/invoices` - Create invoice

**Webhooks Consumed**:
- Payment status callbacks from gateways

**Events Published**:
- `treasury.payment.success` - Payment successful
- `treasury.payment.failed` - Payment failed
- `treasury.invoice.created` - Invoice created
- `treasury.invoice.due` - Invoice due
- `treasury.payment_link.generated` - Payment link generated

**Events Consumed**:
- `cafe.order.created` - Create invoice
- `cafe.subscription.usage.metered` - Usage-based billing

### POS Service

**Integration Type**: REST API + Events (NATS) + Webhooks

**Use Cases**:
- Sales payment processing
- Settlement reconciliation
- Cash drawer reconciliation

**REST API Usage**:
- `POST /api/v1/payments/intents` - Create payment intent
- `GET /api/v1/settlements` - Get settlement data

**Events Published**:
- `treasury.payment.success` - Payment successful
- `treasury.settlement.generated` - Settlement generated

**Events Consumed**:
- `pos.order.completed` - Process payment
- `pos.cash.drawer.closed` - Reconcile cash

### Logistics Service

**Integration Type**: REST API + Events (NATS)

**Use Cases**:
- Expense import (fuel, toll, parking, maintenance)
- Payout calculations
- Earnings statement export

**REST API Usage**:
- `POST /api/v1/{tenant}/expenses` - Import expense
- `POST /api/v1/{tenant}/bills` - Create bill
- `POST /api/v1/{tenant}/journals` - Post journal entry
- `POST /api/v1/{tenant}/payouts` - Create payout

**Events Consumed**:
- `logistics.expense.created` - Import expense
- `logistics.earnings.calculated` - Process earnings
- `logistics.payout.requested` - Create payout

**Events Published**:
- `treasury.payout.completed` - Payout processed
- `treasury.expense.approved` - Expense approved

### Inventory Service

**Integration Type**: REST API + Events (NATS)

**Use Cases**:
- Purchase order invoice matching
- Cost accounting
- Supplier invoice processing

**REST API Usage**:
- `GET /api/v1/{tenant}/invoices` - Get supplier invoices
- `POST /api/v1/{tenant}/expenses` - Import inventory costs

**Events Consumed**:
- `inventory.po.received` - Match supplier invoice
- `inventory.cost.allocated` - Post cost allocation

### Notifications Service

**Integration Type**: Events (NATS) + REST API

**Use Cases**:
- Invoice delivery
- Payment reminders
- Dunning sequences
- Payment confirmations

**REST API Usage**:
- `POST /v1/{tenantId}/notifications/messages` - Send notification

**Events Published**:
- `treasury.invoice.created` - Send invoice
- `treasury.invoice.due` - Send reminder
- `treasury.payment.success` - Send receipt
- `treasury.payment.failed` - Send failure notification

### Projects Service

**Integration Type**: REST API + Events (NATS)

**Use Cases**:
- Project invoicing
- Expense allocation to projects
- Budget tracking

**REST API Usage**:
- `POST /api/v1/{tenant}/invoices` - Create project invoice
- `POST /api/v1/{tenant}/expenses` - Allocate expense to project

**Events Consumed**:
- `projects.expense.created` - Allocate expense
- `projects.milestone.completed` - Generate invoice

---

## External Third-Party Integrations

### M-Pesa Daraja API

**Purpose**: Mobile money payments (STK Push, C2B, B2C, B2B)

**Configuration** (Tier 1 - Developer Only):
- Consumer Key: Stored encrypted at rest
- Consumer Secret: Stored encrypted at rest
- Passkey: Stored encrypted at rest
- Short Code: Configured per tenant (Tier 2)

**Use Cases**:
- STK Push payments
- C2B payments
- B2C payouts
- B2B payments

**API Endpoints**:
- STK Push: `/mpesa/stkpush/v1/processrequest`
- C2B: `/mpesa/c2b/v1/simulate`
- B2C: `/mpesa/b2c/v1/paymentrequest`
- B2B: `/mpesa/b2b/v1/paymentrequest`

### Stripe

**Purpose**: Card payments and payouts

**Configuration** (Tier 1):
- API Key: Stored encrypted at rest
- Webhook Secret: Stored encrypted at rest

**Use Cases**:
- Card payment processing
- Payouts
- Subscription billing

### PayPal

**Purpose**: PayPal payments

**Configuration** (Tier 1):
- Client ID: Stored encrypted at rest
- Client Secret: Stored encrypted at rest

**Use Cases**:
- PayPal payment processing
- Payouts

### KRA iTax API

**Purpose**: Tax compliance and filing

**Configuration** (Tier 1):
- API credentials: Stored encrypted at rest
- Certificate: Stored encrypted at rest

**Use Cases**:
- Tax return submission
- Tax compliance checks
- Tax certificate generation

### Bank APIs

**Purpose**: Bank account integration and auto-reconciliation

**Configuration** (Tier 1):
- API credentials: Stored encrypted at rest
- Account numbers: Configured per tenant (Tier 2)

**Use Cases**:
- Bank balance queries
- Transaction import
- Auto-reconciliation

### Blockchain (Ethereum, Polygon)

**Purpose**: Crypto payments and settlement proofs

**Configuration** (Tier 1):
- RPC URL: Stored encrypted
- Private Key: Stored encrypted
- Wallet Address: Configured per tenant (Tier 2)

**Use Cases**:
- Crypto payment acceptance
- Settlement proof generation
- Auto-conversion to fiat (optional)

---

## Integration Patterns

### 1. REST API Pattern (Synchronous)

**Use Case**: Immediate payment processing, invoice creation

**Implementation**:
- HTTP client with retry logic
- Circuit breaker pattern
- Request timeout (5 seconds default)
- Idempotency keys for mutations

### 2. Event-Driven Pattern (Asynchronous)

**Use Case**: Payment callbacks, invoice events, expense import

**Transport**: NATS JetStream

**Flow**:
1. Service publishes event to NATS
2. Subscriber services consume event
3. Process event and update local state
4. Publish response events if needed

**Reliability**:
- At-least-once delivery
- Event deduplication via event_id
- Retry on failure
- Dead letter queue for failed events

### 3. Webhook Pattern (Callbacks)

**Use Case**: Payment gateway callbacks, bank transaction notifications

**Implementation**:
- Webhook endpoints in treasury service
- Signature verification (HMAC-SHA256)
- Retry logic for failed deliveries
- Idempotency handling

---

## Two-Tier Configuration Management

### Tier 1: Developer/Superuser Configuration

**Visibility**: Only developers and superusers

**Configuration Items**:
- Payment gateway API keys and secrets
- Bank API credentials
- KRA iTax credentials
- Blockchain private keys
- Database credentials
- Encryption keys

**Storage**:
- Encrypted at rest in database (AES-256-GCM)
- K8s secrets for runtime
- Vault for production secrets

### Tier 2: Business User Configuration

**Visibility**: Normal system users (tenant admins)

**Configuration Items**:
- M-Pesa short code
- Bank account numbers
- Wallet addresses (blockchain)
- Tax registration numbers
- Payment preferences

**Storage**:
- Plain text in database (non-sensitive)
- Tenant-specific configuration tables

---

## Event-Driven Architecture

### Event Catalog

#### Outbound Events (Published by Treasury Service)

**treasury.payment.success**
```json
{
  "event_id": "uuid",
  "event_type": "treasury.payment.success",
  "tenant_id": "tenant-uuid",
  "timestamp": "2024-12-05T10:30:00Z",
  "data": {
    "payment_id": "payment-uuid",
    "order_id": "order-uuid",
    "amount": 1500.00,
    "provider_reference": "mpesa-ref-123"
  }
}
```

**treasury.invoice.created**
```json
{
  "event_id": "uuid",
  "event_type": "treasury.invoice.created",
  "tenant_id": "tenant-uuid",
  "timestamp": "2024-12-05T10:30:00Z",
  "data": {
    "invoice_id": "invoice-uuid",
    "customer_id": "customer-uuid",
    "amount": 5000.00,
    "due_date": "2024-12-10"
  }
}
```

#### Inbound Events (Consumed by Treasury Service)

**cafe.order.created**
```json
{
  "event_id": "uuid",
  "event_type": "cafe.order.created",
  "tenant_id": "tenant-uuid",
  "timestamp": "2024-12-05T10:30:00Z",
  "data": {
    "order_id": "order-uuid",
    "customer_id": "customer-uuid",
    "total_amount": 1500.00
  }
}
```

---

## Integration Security

### Authentication

**JWT Tokens**:
- Validated via `shared/auth-client` library
- JWKS from auth-service
- Token claims include tenant_id for scoping

**API Keys** (Service-to-Service):
- Stored in K8s secrets
- Rotated quarterly

### Authorization

**Tenant Isolation**:
- All requests scoped by tenant_id
- Provider credentials isolated per tenant
- Data isolation enforced at database level

### Secrets Management

**Encryption**:
- Secrets encrypted at rest (AES-256-GCM)
- Decrypted only when used
- Key rotation every 90 days

### Webhook Security

**Signature Verification**:
- HMAC-SHA256 signatures
- Secret shared via K8s secret
- Timestamp validation (5-minute window)
- Nonce validation (prevent replay attacks)

---

## Error Handling & Resilience

### Retry Policies

**Exponential Backoff**:
- Initial delay: 1 second
- Max delay: 30 seconds
- Max retries: 3

### Circuit Breaker

**Implementation**:
- Opens after 5 consecutive failures
- Half-open after 60 seconds
- Closes on successful request

### Monitoring

**Metrics**:
- API call latency (p50, p95, p99)
- API call success/failure rates
- Event publishing success rates
- Payment success rates by gateway

**Alerts**:
- High failure rate (>5%)
- Service unavailability
- Event delivery failures
- Payment gateway failures

---

## References

- [Auth Service Integration](../auth-service/auth-service/docs/integrations.md)
- [Cafe Backend Integration](../Cafe/cafe-backend/docs/integrations.md)
- [M-Pesa Daraja API Documentation](../../docs/mpesa-apis/Safaricom%20APIs.postman_collection.json)

