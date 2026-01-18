# Treasury Service - Implementation Plan

## Executive Summary

**System Purpose**: World-class, API-first financial management and payments orchestration platform combining capabilities of Zoho Books, Zoho Invoice, Zoho Billing, and Zoho Finance Plus. Provides comprehensive financial operations including invoicing, billing, expense management, payments processing, bank reconciliation, tax compliance (KRA iTax), and multi-channel payment gateway integrations.

**Key Capabilities**:
- Invoicing and billing (standard, recurring, usage-based)
- Accounts Receivable (AR) management
- Accounts Payable (AP) management
- Banking and reconciliation
- General Ledger and Chart of Accounts
- Financial reporting
- Budgeting and cost control
- Multi-currency and foreign exchange
- Payment gateway integrations (M-Pesa, Stripe, PayPal, Blockchain)
- Tax compliance (KRA iTax)
- Expense management

**Entity Ownership**: This service owns all treasury and financial entities: invoices, bills, payments, ledger entries, bank accounts, reconciliations, expenses, tax records, and financial reports. **Treasury does NOT own**: users (references auth-service via `user_id`), orders (references from cafe/POS services), inventory (references from inventory-service).

---

## Technology Stack

### Core Framework
- **Language**: Go 1.22+
- **Architecture**: Clean Architecture (domain-driven design)
- **HTTP Router**: chi
- **API Documentation**: OpenAPI-first contracts
- **gRPC**: ConnectRPC for high-throughput operations

### Data & Caching
- **Primary Database**: PostgreSQL 16+ with TimescaleDB extension
- **ORM**: Ent (schema-as-code migrations)
- **Caching**: Redis 7+ for caching, rate limiting, idempotency
- **Message Broker**: NATS JetStream
- **Storage**: S3-compatible for documents

### Supporting Libraries
- **Validation**: Custom validators
- **Logging**: zap (structured logging)
- **Tracing**: OpenTelemetry instrumentation
- **Metrics**: Prometheus

### DevOps & Observability
- **Containerization**: Multi-stage Docker builds
- **Orchestration**: Kubernetes (via centralized devops-k8s)
- **CI/CD**: GitHub Actions → ArgoCD
- **Monitoring**: Prometheus + Grafana, OpenTelemetry
- **APM**: Jaeger distributed tracing

---

## Domain Modules & Features

### 1. Invoicing & Billing

**Treasury-Specific Features**:
- Invoice types (standard, tax, proforma, recurring, credit note, debit note)
- Customizable templates with branding
- Multi-currency support
- Tax calculations (VAT, withholding tax, excise duty)
- Payment links and reminders
- Recurring billing and subscriptions
- Usage-based billing

**Entities Owned**:
- `invoices` - Invoice records
- `invoice_lines` - Invoice line items
- `invoice_payments` - Payment applications
- `subscriptions` - Subscription records
- `billing_cycles` - Billing cycle tracking

**Integration Points**:
- **notifications-service**: Invoice delivery, reminders
- **Cafe Backend**: Order invoicing
- **POS Service**: Sales invoicing

### 2. Accounts Receivable (AR)

**Treasury-Specific Features**:
- Customer ledger with aging reports
- Payment application to invoices
- Credit memo application
- Write-offs and bad debt management
- Customer statements
- AR aging analysis

**Entities Owned**:
- `customers` - Customer records
- `customer_ledger` - Customer ledger entries
- `ar_aging` - AR aging records

**Integration Points**:
- **Cafe Backend**: Customer payments
- **POS Service**: Customer payments

### 3. Accounts Payable (AP)

**Treasury-Specific Features**:
- Vendor bill management
- Bill approval workflows
- Purchase order matching
- Vendor credit notes
- Payment scheduling
- AP aging reports

**Entities Owned**:
- `vendors` - Vendor records
- `vendor_bills` - Vendor bill records
- `ap_aging` - AP aging records
- `purchase_orders` - PO records

**Integration Points**:
- **inventory-service**: PO matching
- **logistics-service**: Expense export

### 4. Banking & Reconciliation

**Treasury-Specific Features**:
- Multiple bank account support
- Bank statement import
- Bank API integration
- Automatic matching engine
- Manual reconciliation
- Cash management

**Entities Owned**:
- `bank_accounts` - Bank account records
- `bank_transactions` - Transaction records
- `reconciliations` - Reconciliation records

**Integration Points**:
- **Bank APIs**: Auto-sync transactions
- **External Providers**: Bank API integrations

### 5. General Ledger & Chart of Accounts

**Treasury-Specific Features**:
- Multi-tenant chart of accounts
- Account types and hierarchy
- Double-entry bookkeeping
- Journal entries
- Period-end closing
- Trial balance

**Entities Owned**:
- `chart_of_accounts` - COA records
- `journal_entries` - Journal entry records
- `ledger_transactions` - Ledger transaction records

**Integration Points**:
- **All Services**: Financial event posting

### 6. Payments Processing

**Treasury-Specific Features**:
- Payment intent creation
- Multi-gateway support (M-Pesa, Stripe, PayPal, Blockchain)
- Payment status tracking
- Refund processing
- Payout orchestration

**Entities Owned**:
- `payment_intents` - Payment intent records
- `payment_transactions` - Payment transaction records
- `payment_methods` - Payment method records
- `refunds` - Refund records

**Integration Points**:
- **M-Pesa Daraja**: STK Push, C2B, B2C, B2B
- **Stripe**: Card payments
- **PayPal**: PayPal payments
- **Blockchain**: Crypto payments

### 7. Expense Management

**Treasury-Specific Features**:
- Expense entry with categories
- Receipt capture
- Multi-currency expenses
- Tax code assignment
- Project/cost center tagging
- Approval workflows
- Reimbursement processing

**Entities Owned**:
- `expenses` - Expense records
- `expense_categories` - Category definitions
- `expense_approvals` - Approval workflows

**Integration Points**:
- **logistics-service**: Expense import
- **inventory-service**: Expense import

### 8. Tax Compliance

**Treasury-Specific Features**:
- Tax code management
- Tax calculation engine
- KRA iTax integration
- Tax return generation
- Tax filing automation

**Entities Owned**:
- `tax_codes` - Tax code definitions
- `tax_returns` - Tax return records
- `tax_filings` - Tax filing records

**Integration Points**:
- **KRA iTax API**: Tax filing and compliance

### 9. Financial Reporting

**Treasury-Specific Features**:
- Profit & Loss Statement
- Balance Sheet
- Cash Flow Statement
- Trial Balance
- AR/AP Aging Reports
- Custom report builder

**Entities Owned**:
- `report_jobs` - Report generation jobs
- `report_templates` - Report template definitions

**Integration Points**:
- **Apache Superset**: BI dashboards and analytics

### 10. Budgeting & Cost Control

**Treasury-Specific Features**:
- Budget creation
- Budget vs actual reports
- Budget variance analysis
- Budget alerts
- Rolling budgets

**Entities Owned**:
- `budgets` - Budget records
- `budget_versions` - Budget version tracking

---

## Cross-Cutting Concerns

### Testing
- Go test suites with table-driven tests
- Testcontainers for integration testing
- Pact for contract tests
- Financial accuracy testing

### Observability
- Structured logging (zap)
- Tracing via OpenTelemetry
- Metrics exported via Prometheus
- Distributed tracing via Tempo/Jaeger

### Security
- OWASP ASVS baseline
- TLS everywhere
- Secrets via Vault/Parameter Store
- Rate limiting & anomaly detection middleware
- JWT validation via auth-service
- Financial data encryption

### Scalability
- Stateless HTTP layer
- Background workers via NATS/Redis streams
- Partitioned tables for ledger entries
- Caching strategy for hot data

### Data Modelling
- Ent schemas as single source of truth
- Tenant/outlet discovery webhooks
- Outbox pattern for reliable domain events
- Immutable ledger for audit trail

---

## API & Protocol Strategy

- **REST-first**: Versioned routes (`/api/v1/{tenantID}/invoices`), documented via OpenAPI
- **gRPC**: ConnectRPC for high-throughput operations
- **Webhooks**: Payment callbacks, settlement notifications
- **Idempotency**: Keys, correlation IDs, distributed tracing context propagation

---

## Compliance & Risk Controls

- Align with Kenya Data Protection Act: explicit consent flows, user data export/delete endpoints, audit logging
- Financial compliance: double-entry bookkeeping, audit trails, reconciliation
- Tax compliance: KRA iTax integration, tax reporting
- Disaster recovery playbook, RTO/RPO targets (<1 hour)

---

## Sprint Delivery Plan

See `docs/sprints/` folder for detailed sprint plans:
- Sprint 0: Foundations ✅
- **Sprint 1 (CRITICAL)**: Authentication, RBAC & User Management ⏳ **MUST BE FIRST**
- Sprint 2: Payment Processing (Intents, M-Pesa(refer to bengobox/docs/mpesa apis/Safaricom APIs.postman_collection.json for detailed mpesa api docs), Stripe)
- Sprint 3: Ledger & Chart of Accounts
- Sprint 4: Invoicing & Billing
- Sprint 5: Accounts Receivable
- Sprint 6: Accounts Payable
- Sprint 7: Banking & Reconciliation
- Sprint 8: Expense Management
- Sprint 9: Tax Compliance
- Sprint 10: Financial Reporting
- Sprint 11: Budgeting & Cost Control
- Sprint 12: Launch & Handover

---

## Runtime Ports & Environments

- **Local development**: Service runs on port **4001**
- **Cloud deployment**: All backend services listen on **port 4000** for consistency behind ingress controllers

---

## References

- [Integration Guide](docs/integrations.md)
- [Entity Relationship Diagram](docs/erd.md)
- [Superset Integration](docs/superset-integration.md)
- [Sprint Plans](docs/sprints/)
