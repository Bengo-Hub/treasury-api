# Treasury Service – Comprehensive Entity Relationship Diagram

The treasury service manages all financial operations including invoicing, billing, payments, banking, reconciliation, expenses, and tax compliance. Ent schemas model the domain and power migrations.

> **Conventions**
> - UUID primary keys (`id UUID PRIMARY KEY DEFAULT gen_random_uuid()`).
> - `tenant_id UUID NOT NULL` on all operational tables for multi-tenant isolation.
> - Timestamps are `TIMESTAMPTZ` with timezone awareness.
> - Monetary values use `NUMERIC(18,2)` with decimal precision.
> - Double-entry bookkeeping enforced at application level.
> - Vector columns use `vector(1536)` for AI-powered semantic search (pgvector extension).
> - All tables include `created_at TIMESTAMPTZ DEFAULT NOW()` and `updated_at TIMESTAMPTZ DEFAULT NOW()`.
> - Soft deletes via `deleted_at TIMESTAMPTZ` where applicable.

---

## Database Extensions

- `pgvector` - Vector similarity search for AI-powered queries
- `timescaledb` - Time-series data for financial analytics
- `uuid-ossp` - UUID generation
- `pg_trgm` - Trigram matching for fuzzy search
- `btree_gin` - GIN indexes for composite queries

---

## Ledger & Chart of Accounts

### chart_of_accounts

**Purpose**: Hierarchical chart of accounts (Assets, Liabilities, Equity, Revenue, Expense).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Account identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `account_code` | VARCHAR(50) | NOT NULL, UNIQUE(tenant_id, account_code) | Account code (e.g., "1000", "2000") |
| `account_name` | VARCHAR(255) | NOT NULL | Account name |
| `account_type` | VARCHAR(20) | NOT NULL, CHECK | Asset, Liability, Equity, Revenue, Expense |
| `parent_id` | UUID | FK → chart_of_accounts(id) | Parent account for hierarchy |
| `is_active` | BOOLEAN | DEFAULT true | Active status |
| `description` | TEXT | | Account description |
| `metadata` | JSONB | | Additional account metadata |
| `embedding` | vector(1536) | | Vector embedding for semantic search |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_chart_of_accounts_tenant_id` ON `tenant_id`
- `idx_chart_of_accounts_account_code` ON `account_code`
- `idx_chart_of_accounts_parent_id` ON `parent_id`
- `idx_chart_of_accounts_account_type` ON `account_type`
- `idx_chart_of_accounts_embedding` ON `embedding` USING ivfflat (vector_cosine_ops)

**Relations**:
- `parent_id` → `chart_of_accounts(id)` (self-referential)
- `tenant_id` → `tenants(id)` (via auth-service sync)

### journal_entries

**Purpose**: Journal entry headers for manual adjustments and period-end entries.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Journal entry identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `entry_number` | VARCHAR(50) | NOT NULL, UNIQUE(tenant_id, entry_number) | Sequential entry number |
| `entry_date` | DATE | NOT NULL | Entry date |
| `description` | TEXT | NOT NULL | Entry description |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Draft, Pending, Approved, Posted, Reversed |
| `approved_by` | UUID | FK → users | Approver user ID |
| `approved_at` | TIMESTAMPTZ | | Approval timestamp |
| `reversed_entry_id` | UUID | FK → journal_entries(id) | Reversing entry reference |
| `metadata` | JSONB | | Additional entry metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_journal_entries_tenant_id` ON `tenant_id`
- `idx_journal_entries_entry_number` ON `entry_number`
- `idx_journal_entries_entry_date` ON `entry_date`
- `idx_journal_entries_status` ON `status`
- `idx_journal_entries_approved_by` ON `approved_by`

**Relations**:
- `tenant_id` → `tenants(id)` (via auth-service sync)
- `approved_by` → `users(id)` (via auth-service sync)
- `reversed_entry_id` → `journal_entries(id)` (self-referential)

### ledger_transactions

**Purpose**: Double-entry ledger transactions (immutable audit trail).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Transaction identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `journal_entry_id` | UUID | FK → journal_entries(id) | Source journal entry |
| `account_id` | UUID | NOT NULL, FK → chart_of_accounts(id) | Account identifier |
| `debit_amount` | NUMERIC(18,2) | DEFAULT 0, CHECK (>= 0) | Debit amount |
| `credit_amount` | NUMERIC(18,2) | DEFAULT 0, CHECK (>= 0) | Credit amount |
| `currency` | VARCHAR(3) | NOT NULL, DEFAULT 'KES' | ISO currency code |
| `exchange_rate` | NUMERIC(18,6) | DEFAULT 1.0 | FX rate for multi-currency |
| `reference_type` | VARCHAR(50) | | Reference entity type (invoice, bill, payment, etc.) |
| `reference_id` | UUID | | Reference entity ID |
| `transaction_date` | DATE | NOT NULL | Transaction date |
| `description` | TEXT | | Transaction description |
| `metadata` | JSONB | | Additional transaction metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |

**Indexes**:
- `idx_ledger_transactions_tenant_id` ON `tenant_id`
- `idx_ledger_transactions_account_id` ON `account_id`
- `idx_ledger_transactions_journal_entry_id` ON `journal_entry_id`
- `idx_ledger_transactions_reference` ON `(reference_type, reference_id)`
- `idx_ledger_transactions_transaction_date` ON `transaction_date`
- `idx_ledger_transactions_created_at` ON `created_at` (TimescaleDB hypertable)

**Relations**:
- `journal_entry_id` → `journal_entries(id)`
- `account_id` → `chart_of_accounts(id)`
- `tenant_id` → `tenants(id)` (via auth-service sync)

**Constraints**:
- CHECK: `(debit_amount = 0 AND credit_amount > 0) OR (debit_amount > 0 AND credit_amount = 0)`
- CHECK: `debit_amount >= 0 AND credit_amount >= 0`

### ledger_periods

**Purpose**: Accounting period management for period-end closing.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Period identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `period_start` | DATE | NOT NULL | Period start date |
| `period_end` | DATE | NOT NULL | Period end date |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Open, Pending, Closed, Reopened |
| `closed_at` | TIMESTAMPTZ | | Period close timestamp |
| `closed_by` | UUID | FK → users | User who closed the period |
| `metadata` | JSONB | | Additional period metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_ledger_periods_tenant_id` ON `tenant_id`
- `idx_ledger_periods_period_dates` ON `(period_start, period_end)`
- `idx_ledger_periods_status` ON `status`

**Relations**:
- `tenant_id` → `tenants(id)` (via auth-service sync)
- `closed_by` → `users(id)` (via auth-service sync)

---

## Invoicing & Billing

### invoices

**Purpose**: Invoice records (standard, tax, proforma, recurring, credit note, debit note).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Invoice identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `invoice_number` | VARCHAR(50) | NOT NULL, UNIQUE(tenant_id, invoice_number) | Sequential invoice number |
| `invoice_type` | VARCHAR(20) | NOT NULL, CHECK | Standard, Tax, Proforma, Recurring, CreditNote, DebitNote |
| `customer_id` | UUID | NOT NULL, FK → customers(id) | Customer identifier |
| `issue_date` | DATE | NOT NULL | Invoice issue date |
| `due_date` | DATE | NOT NULL | Payment due date |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Draft, Sent, Paid, PartiallyPaid, Overdue, Cancelled |
| `subtotal` | NUMERIC(18,2) | NOT NULL, DEFAULT 0 | Subtotal before tax |
| `tax_amount` | NUMERIC(18,2) | NOT NULL, DEFAULT 0 | Total tax amount |
| `discount_amount` | NUMERIC(18,2) | NOT NULL, DEFAULT 0 | Discount amount |
| `total_amount` | NUMERIC(18,2) | NOT NULL | Total invoice amount |
| `currency` | VARCHAR(3) | NOT NULL, DEFAULT 'KES' | ISO currency code |
| `exchange_rate` | NUMERIC(18,6) | DEFAULT 1.0 | FX rate for multi-currency |
| `payment_terms` | VARCHAR(50) | | Payment terms (e.g., "Net 30") |
| `notes` | TEXT | | Invoice notes |
| `metadata` | JSONB | | Additional invoice metadata |
| `embedding` | vector(1536) | | Vector embedding for semantic search |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_invoices_tenant_id` ON `tenant_id`
- `idx_invoices_invoice_number` ON `invoice_number`
- `idx_invoices_customer_id` ON `customer_id`
- `idx_invoices_status` ON `status`
- `idx_invoices_due_date` ON `due_date`
- `idx_invoices_issue_date` ON `issue_date`
- `idx_invoices_embedding` ON `embedding` USING ivfflat (vector_cosine_ops)

**Relations**:
- `customer_id` → `customers(id)`
- `tenant_id` → `tenants(id)` (via auth-service sync)

### invoice_lines

**Purpose**: Invoice line items.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Line item identifier |
| `invoice_id` | UUID | NOT NULL, FK → invoices(id) ON DELETE CASCADE | Invoice identifier |
| `line_number` | INTEGER | NOT NULL | Line sequence number |
| `item_description` | TEXT | NOT NULL | Item description |
| `quantity` | NUMERIC(18,6) | NOT NULL, DEFAULT 1 | Quantity |
| `unit_price` | NUMERIC(18,2) | NOT NULL | Unit price |
| `discount_percent` | NUMERIC(5,2) | DEFAULT 0 | Discount percentage |
| `tax_code_id` | UUID | FK → tax_codes(id) | Tax code identifier |
| `line_total` | NUMERIC(18,2) | NOT NULL | Line total (quantity * unit_price - discount) |
| `metadata` | JSONB | | Additional line metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |

**Indexes**:
- `idx_invoice_lines_invoice_id` ON `invoice_id`
- `idx_invoice_lines_tax_code_id` ON `tax_code_id`

**Relations**:
- `invoice_id` → `invoices(id)` ON DELETE CASCADE
- `tax_code_id` → `tax_codes(id)`

### invoice_payments

**Purpose**: Payment applications to invoices.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Payment application identifier |
| `invoice_id` | UUID | NOT NULL, FK → invoices(id) | Invoice identifier |
| `payment_id` | UUID | NOT NULL, FK → payment_transactions(id) | Payment transaction identifier |
| `amount_applied` | NUMERIC(18,2) | NOT NULL | Amount applied to invoice |
| `applied_at` | TIMESTAMPTZ | NOT NULL, DEFAULT NOW() | Application timestamp |
| `metadata` | JSONB | | Additional application metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |

**Indexes**:
- `idx_invoice_payments_invoice_id` ON `invoice_id`
- `idx_invoice_payments_payment_id` ON `payment_id`

**Relations**:
- `invoice_id` → `invoices(id)`
- `payment_id` → `payment_transactions(id)`

### subscriptions

**Purpose**: Subscription records for recurring billing.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Subscription identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `customer_id` | UUID | NOT NULL, FK → customers(id) | Customer identifier |
| `subscription_plan_id` | UUID | FK → subscription_plans(id) | Subscription plan identifier |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Active, Cancelled, Paused, Expired |
| `billing_cycle` | VARCHAR(20) | NOT NULL, CHECK | Daily, Weekly, Monthly, Quarterly, Annually |
| `current_period_start` | DATE | NOT NULL | Current billing period start |
| `current_period_end` | DATE | NOT NULL | Current billing period end |
| `trial_end` | DATE | | Trial period end date |
| `cancelled_at` | TIMESTAMPTZ | | Cancellation timestamp |
| `metadata` | JSONB | | Additional subscription metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_subscriptions_tenant_id` ON `tenant_id`
- `idx_subscriptions_customer_id` ON `customer_id`
- `idx_subscriptions_status` ON `status`
- `idx_subscriptions_current_period` ON `(current_period_start, current_period_end)`

**Relations**:
- `customer_id` → `customers(id)`
- `subscription_plan_id` → `subscription_plans(id)`
- `tenant_id` → `tenants(id)` (via auth-service sync)

### billing_cycles

**Purpose**: Billing cycle tracking for subscriptions.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Billing cycle identifier |
| `subscription_id` | UUID | NOT NULL, FK → subscriptions(id) ON DELETE CASCADE | Subscription identifier |
| `cycle_start` | DATE | NOT NULL | Cycle start date |
| `cycle_end` | DATE | NOT NULL | Cycle end date |
| `invoice_id` | UUID | FK → invoices(id) | Generated invoice identifier |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Pending, Invoiced, Paid, Failed |
| `usage_amount` | NUMERIC(18,2) | DEFAULT 0 | Usage-based billing amount |
| `billing_amount` | NUMERIC(18,2) | NOT NULL | Total billing amount |
| `metadata` | JSONB | | Additional cycle metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_billing_cycles_subscription_id` ON `subscription_id`
- `idx_billing_cycles_invoice_id` ON `invoice_id`
- `idx_billing_cycles_status` ON `status`
- `idx_billing_cycles_cycle_dates` ON `(cycle_start, cycle_end)`

**Relations**:
- `subscription_id` → `subscriptions(id)` ON DELETE CASCADE
- `invoice_id` → `invoices(id)`

---

## Accounts Receivable

### customers

**Purpose**: Customer master data.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Customer identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `customer_code` | VARCHAR(50) | NOT NULL, UNIQUE(tenant_id, customer_code) | Customer code |
| `name` | VARCHAR(255) | NOT NULL | Customer name |
| `email` | VARCHAR(255) | | Customer email |
| `phone` | VARCHAR(50) | | Customer phone |
| `billing_address` | JSONB | | Billing address (structured) |
| `credit_limit` | NUMERIC(18,2) | DEFAULT 0 | Credit limit |
| `payment_terms` | VARCHAR(50) | | Payment terms (e.g., "Net 30") |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Active, Inactive, Suspended |
| `metadata` | JSONB | | Additional customer metadata |
| `embedding` | vector(1536) | | Vector embedding for semantic search |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_customers_tenant_id` ON `tenant_id`
- `idx_customers_customer_code` ON `customer_code`
- `idx_customers_email` ON `email`
- `idx_customers_status` ON `status`
- `idx_customers_embedding` ON `embedding` USING ivfflat (vector_cosine_ops)

**Relations**:
- `tenant_id` → `tenants(id)` (via auth-service sync)

### customer_ledger

**Purpose**: Customer ledger entries for AR tracking.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Ledger entry identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `customer_id` | UUID | NOT NULL, FK → customers(id) | Customer identifier |
| `transaction_type` | VARCHAR(50) | NOT NULL | Invoice, Payment, CreditMemo, WriteOff |
| `invoice_id` | UUID | FK → invoices(id) | Invoice reference |
| `payment_id` | UUID | FK → payment_transactions(id) | Payment reference |
| `debit_amount` | NUMERIC(18,2) | DEFAULT 0 | Debit amount |
| `credit_amount` | NUMERIC(18,2) | DEFAULT 0 | Credit amount |
| `balance` | NUMERIC(18,2) | NOT NULL | Running balance |
| `transaction_date` | DATE | NOT NULL | Transaction date |
| `metadata` | JSONB | | Additional entry metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |

**Indexes**:
- `idx_customer_ledger_tenant_id` ON `tenant_id`
- `idx_customer_ledger_customer_id` ON `customer_id`
- `idx_customer_ledger_invoice_id` ON `invoice_id`
- `idx_customer_ledger_payment_id` ON `payment_id`
- `idx_customer_ledger_transaction_date` ON `transaction_date`
- `idx_customer_ledger_created_at` ON `created_at` (TimescaleDB hypertable)

**Relations**:
- `customer_id` → `customers(id)`
- `invoice_id` → `invoices(id)`
- `payment_id` → `payment_transactions(id)`
- `tenant_id` → `tenants(id)` (via auth-service sync)

### ar_aging

**Purpose**: AR aging analysis for overdue tracking.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Aging record identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `customer_id` | UUID | NOT NULL, FK → customers(id) | Customer identifier |
| `invoice_id` | UUID | NOT NULL, FK → invoices(id) | Invoice identifier |
| `age_bucket` | VARCHAR(20) | NOT NULL, CHECK | Current, 30Days, 60Days, 90Days, 120Plus |
| `amount` | NUMERIC(18,2) | NOT NULL | Outstanding amount |
| `as_of_date` | DATE | NOT NULL | Aging calculation date |
| `metadata` | JSONB | | Additional aging metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_ar_aging_tenant_id` ON `tenant_id`
- `idx_ar_aging_customer_id` ON `customer_id`
- `idx_ar_aging_invoice_id` ON `invoice_id`
- `idx_ar_aging_age_bucket` ON `age_bucket`
- `idx_ar_aging_as_of_date` ON `as_of_date`

**Relations**:
- `customer_id` → `customers(id)`
- `invoice_id` → `invoices(id)`
- `tenant_id` → `tenants(id)` (via auth-service sync)

---

## Accounts Payable

### vendors

**Purpose**: Vendor master data.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Vendor identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `vendor_code` | VARCHAR(50) | NOT NULL, UNIQUE(tenant_id, vendor_code) | Vendor code |
| `name` | VARCHAR(255) | NOT NULL | Vendor name |
| `email` | VARCHAR(255) | | Vendor email |
| `phone` | VARCHAR(50) | | Vendor phone |
| `billing_address` | JSONB | | Billing address (structured) |
| `payment_terms` | VARCHAR(50) | | Payment terms (e.g., "Net 30") |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Active, Inactive, Suspended |
| `metadata` | JSONB | | Additional vendor metadata |
| `embedding` | vector(1536) | | Vector embedding for semantic search |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_vendors_tenant_id` ON `tenant_id`
- `idx_vendors_vendor_code` ON `vendor_code`
- `idx_vendors_email` ON `email`
- `idx_vendors_status` ON `status`
- `idx_vendors_embedding` ON `embedding` USING ivfflat (vector_cosine_ops)

**Relations**:
- `tenant_id` → `tenants(id)` (via auth-service sync)

### vendor_bills

**Purpose**: Vendor bill records.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Vendor bill identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `vendor_id` | UUID | NOT NULL, FK → vendors(id) | Vendor identifier |
| `bill_number` | VARCHAR(50) | NOT NULL, UNIQUE(tenant_id, bill_number) | Vendor bill number |
| `bill_date` | DATE | NOT NULL | Bill date |
| `due_date` | DATE | NOT NULL | Payment due date |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Draft, Received, Approved, Paid, PartiallyPaid, Cancelled |
| `subtotal` | NUMERIC(18,2) | NOT NULL, DEFAULT 0 | Subtotal before tax |
| `tax_amount` | NUMERIC(18,2) | NOT NULL, DEFAULT 0 | Total tax amount |
| `total_amount` | NUMERIC(18,2) | NOT NULL | Total bill amount |
| `currency` | VARCHAR(3) | NOT NULL, DEFAULT 'KES' | ISO currency code |
| `purchase_order_id` | UUID | FK → purchase_orders(id) | Purchase order reference |
| `metadata` | JSONB | | Additional bill metadata |
| `embedding` | vector(1536) | | Vector embedding for semantic search |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_vendor_bills_tenant_id` ON `tenant_id`
- `idx_vendor_bills_vendor_id` ON `vendor_id`
- `idx_vendor_bills_bill_number` ON `bill_number`
- `idx_vendor_bills_status` ON `status`
- `idx_vendor_bills_due_date` ON `due_date`
- `idx_vendor_bills_purchase_order_id` ON `purchase_order_id`
- `idx_vendor_bills_embedding` ON `embedding` USING ivfflat (vector_cosine_ops)

**Relations**:
- `vendor_id` → `vendors(id)`
- `purchase_order_id` → `purchase_orders(id)`
- `tenant_id` → `tenants(id)` (via auth-service sync)

### vendor_bill_lines

**Purpose**: Vendor bill line items.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Line item identifier |
| `vendor_bill_id` | UUID | NOT NULL, FK → vendor_bills(id) ON DELETE CASCADE | Vendor bill identifier |
| `line_number` | INTEGER | NOT NULL | Line sequence number |
| `item_description` | TEXT | NOT NULL | Item description |
| `quantity` | NUMERIC(18,6) | NOT NULL, DEFAULT 1 | Quantity |
| `unit_price` | NUMERIC(18,2) | NOT NULL | Unit price |
| `tax_code_id` | UUID | FK → tax_codes(id) | Tax code identifier |
| `line_total` | NUMERIC(18,2) | NOT NULL | Line total (quantity * unit_price) |
| `metadata` | JSONB | | Additional line metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |

**Indexes**:
- `idx_vendor_bill_lines_vendor_bill_id` ON `vendor_bill_id`
- `idx_vendor_bill_lines_tax_code_id` ON `tax_code_id`

**Relations**:
- `vendor_bill_id` → `vendor_bills(id)` ON DELETE CASCADE
- `tax_code_id` → `tax_codes(id)`

### purchase_orders

**Purpose**: Purchase order records.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Purchase order identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `vendor_id` | UUID | NOT NULL, FK → vendors(id) | Vendor identifier |
| `po_number` | VARCHAR(50) | NOT NULL, UNIQUE(tenant_id, po_number) | Purchase order number |
| `po_date` | DATE | NOT NULL | PO date |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Draft, Sent, Received, PartiallyReceived, Completed, Cancelled |
| `total_amount` | NUMERIC(18,2) | NOT NULL | Total PO amount |
| `currency` | VARCHAR(3) | NOT NULL, DEFAULT 'KES' | ISO currency code |
| `metadata` | JSONB | | Additional PO metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_purchase_orders_tenant_id` ON `tenant_id`
- `idx_purchase_orders_vendor_id` ON `vendor_id`
- `idx_purchase_orders_po_number` ON `po_number`
- `idx_purchase_orders_status` ON `status`

**Relations**:
- `vendor_id` → `vendors(id)`
- `tenant_id` → `tenants(id)` (via auth-service sync)

### ap_aging

**Purpose**: AP aging analysis for overdue tracking.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Aging record identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `vendor_id` | UUID | NOT NULL, FK → vendors(id) | Vendor identifier |
| `vendor_bill_id` | UUID | NOT NULL, FK → vendor_bills(id) | Vendor bill identifier |
| `age_bucket` | VARCHAR(20) | NOT NULL, CHECK | Current, 30Days, 60Days, 90Days, 120Plus |
| `amount` | NUMERIC(18,2) | NOT NULL | Outstanding amount |
| `as_of_date` | DATE | NOT NULL | Aging calculation date |
| `metadata` | JSONB | | Additional aging metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_ap_aging_tenant_id` ON `tenant_id`
- `idx_ap_aging_vendor_id` ON `vendor_id`
- `idx_ap_aging_vendor_bill_id` ON `vendor_bill_id`
- `idx_ap_aging_age_bucket` ON `age_bucket`
- `idx_ap_aging_as_of_date` ON `as_of_date`

**Relations**:
- `vendor_id` → `vendors(id)`
- `vendor_bill_id` → `vendor_bills(id)`
- `tenant_id` → `tenants(id)` (via auth-service sync)

---

## Banking & Reconciliation

### bank_accounts

**Purpose**: Bank account records.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Bank account identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `account_name` | VARCHAR(255) | NOT NULL | Account name |
| `account_number` | VARCHAR(50) | NOT NULL | Bank account number |
| `bank_name` | VARCHAR(255) | NOT NULL | Bank name |
| `account_type` | VARCHAR(50) | NOT NULL | Checking, Savings, MoneyMarket, etc. |
| `currency` | VARCHAR(3) | NOT NULL, DEFAULT 'KES' | ISO currency code |
| `opening_balance` | NUMERIC(18,2) | NOT NULL, DEFAULT 0 | Opening balance |
| `current_balance` | NUMERIC(18,2) | NOT NULL, DEFAULT 0 | Current balance |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Active, Inactive, Closed |
| `metadata` | JSONB | | Additional account metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_bank_accounts_tenant_id` ON `tenant_id`
- `idx_bank_accounts_account_number` ON `account_number`
- `idx_bank_accounts_status` ON `status`

**Relations**:
- `tenant_id` → `tenants(id)` (via auth-service sync)

### bank_transactions

**Purpose**: Bank transaction records from statements and API imports.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Transaction identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `bank_account_id` | UUID | NOT NULL, FK → bank_accounts(id) | Bank account identifier |
| `transaction_date` | DATE | NOT NULL | Transaction date |
| `amount` | NUMERIC(18,2) | NOT NULL | Transaction amount (positive for credit, negative for debit) |
| `currency` | VARCHAR(3) | NOT NULL, DEFAULT 'KES' | ISO currency code |
| `transaction_type` | VARCHAR(50) | NOT NULL | Debit, Credit, Transfer, Fee, Interest |
| `reference_number` | VARCHAR(100) | | Bank reference number |
| `description` | TEXT | | Transaction description |
| `reconciliation_status` | VARCHAR(20) | NOT NULL, DEFAULT 'Unreconciled', CHECK | Unreconciled, Matched, Reconciled |
| `reconciliation_id` | UUID | FK → reconciliations(id) | Reconciliation identifier |
| `metadata` | JSONB | | Additional transaction metadata |
| `embedding` | vector(1536) | | Vector embedding for semantic search |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |

**Indexes**:
- `idx_bank_transactions_tenant_id` ON `tenant_id`
- `idx_bank_transactions_bank_account_id` ON `bank_account_id`
- `idx_bank_transactions_transaction_date` ON `transaction_date`
- `idx_bank_transactions_reconciliation_status` ON `reconciliation_status`
- `idx_bank_transactions_reconciliation_id` ON `reconciliation_id`
- `idx_bank_transactions_reference_number` ON `reference_number`
- `idx_bank_transactions_created_at` ON `created_at` (TimescaleDB hypertable)
- `idx_bank_transactions_embedding` ON `embedding` USING ivfflat (vector_cosine_ops)

**Relations**:
- `bank_account_id` → `bank_accounts(id)`
- `reconciliation_id` → `reconciliations(id)`
- `tenant_id` → `tenants(id)` (via auth-service sync)

### reconciliations

**Purpose**: Bank reconciliation records.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Reconciliation identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `bank_account_id` | UUID | NOT NULL, FK → bank_accounts(id) | Bank account identifier |
| `reconciliation_date` | DATE | NOT NULL | Reconciliation date |
| `opening_balance` | NUMERIC(18,2) | NOT NULL | Opening balance |
| `closing_balance` | NUMERIC(18,2) | NOT NULL | Closing balance |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Draft, InProgress, Completed, Reversed |
| `reconciled_by` | UUID | FK → users | User who performed reconciliation |
| `reconciled_at` | TIMESTAMPTZ | | Reconciliation timestamp |
| `metadata` | JSONB | | Additional reconciliation metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_reconciliations_tenant_id` ON `tenant_id`
- `idx_reconciliations_bank_account_id` ON `bank_account_id`
- `idx_reconciliations_reconciliation_date` ON `reconciliation_date`
- `idx_reconciliations_status` ON `status`

**Relations**:
- `bank_account_id` → `bank_accounts(id)`
- `reconciled_by` → `users(id)` (via auth-service sync)
- `tenant_id` → `tenants(id)` (via auth-service sync)

### reconciliation_matches

**Purpose**: Reconciliation matching records (bank transactions to ledger transactions).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Match identifier |
| `reconciliation_id` | UUID | NOT NULL, FK → reconciliations(id) ON DELETE CASCADE | Reconciliation identifier |
| `bank_transaction_id` | UUID | NOT NULL, FK → bank_transactions(id) | Bank transaction identifier |
| `ledger_transaction_id` | UUID | FK → ledger_transactions(id) | Ledger transaction identifier |
| `match_type` | VARCHAR(20) | NOT NULL, CHECK | Automatic, Manual, Fuzzy |
| `match_confidence` | NUMERIC(5,2) | DEFAULT 100.00 | Match confidence score (0-100) |
| `matched_at` | TIMESTAMPTZ | NOT NULL, DEFAULT NOW() | Match timestamp |
| `metadata` | JSONB | | Additional match metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |

**Indexes**:
- `idx_reconciliation_matches_reconciliation_id` ON `reconciliation_id`
- `idx_reconciliation_matches_bank_transaction_id` ON `bank_transaction_id`
- `idx_reconciliation_matches_ledger_transaction_id` ON `ledger_transaction_id`
- `idx_reconciliation_matches_match_type` ON `match_type`

**Relations**:
- `reconciliation_id` → `reconciliations(id)` ON DELETE CASCADE
- `bank_transaction_id` → `bank_transactions(id)`
- `ledger_transaction_id` → `ledger_transactions(id)`

---

## Payments Processing

### payment_intents

**Purpose**: Payment intent records (pre-payment requests).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Payment intent identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `intent_reference` | VARCHAR(100) | NOT NULL, UNIQUE(tenant_id, intent_reference) | Unique intent reference |
| `amount` | NUMERIC(18,2) | NOT NULL | Payment amount |
| `currency` | VARCHAR(3) | NOT NULL, DEFAULT 'KES' | ISO currency code |
| `payment_method` | VARCHAR(50) | NOT NULL | Cash, Card, MobileMoney, BankTransfer, etc. |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Pending, Processing, Succeeded, Failed, Cancelled, Refunded |
| `provider` | VARCHAR(50) | | Payment provider (M-Pesa, Stripe, PayPal, Blockchain) |
| `provider_reference` | VARCHAR(255) | | Provider transaction reference |
| `customer_id` | UUID | FK → customers(id) | Customer identifier |
| `metadata` | JSONB | | Additional intent metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_payment_intents_tenant_id` ON `tenant_id`
- `idx_payment_intents_intent_reference` ON `intent_reference`
- `idx_payment_intents_status` ON `status`
- `idx_payment_intents_provider` ON `provider`
- `idx_payment_intents_customer_id` ON `customer_id`
- `idx_payment_intents_created_at` ON `created_at` (TimescaleDB hypertable)

**Relations**:
- `customer_id` → `customers(id)`
- `tenant_id` → `tenants(id)` (via auth-service sync)

### payment_transactions

**Purpose**: Payment transaction records (actual payment executions).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Payment transaction identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `payment_intent_id` | UUID | NOT NULL, FK → payment_intents(id) | Payment intent identifier |
| `transaction_type` | VARCHAR(50) | NOT NULL | Payment, Refund, Chargeback, Adjustment |
| `amount` | NUMERIC(18,2) | NOT NULL | Transaction amount |
| `currency` | VARCHAR(3) | NOT NULL, DEFAULT 'KES' | ISO currency code |
| `provider` | VARCHAR(50) | NOT NULL | Payment provider |
| `provider_reference` | VARCHAR(255) | NOT NULL | Provider transaction reference |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Pending, Processing, Succeeded, Failed, Cancelled |
| `processed_at` | TIMESTAMPTZ | | Processing timestamp |
| `metadata` | JSONB | | Additional transaction metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_payment_transactions_tenant_id` ON `tenant_id`
- `idx_payment_transactions_payment_intent_id` ON `payment_intent_id`
- `idx_payment_transactions_provider_reference` ON `provider_reference`
- `idx_payment_transactions_status` ON `status`
- `idx_payment_transactions_processed_at` ON `processed_at` (TimescaleDB hypertable)

**Relations**:
- `payment_intent_id` → `payment_intents(id)`
- `tenant_id` → `tenants(id)` (via auth-service sync)

### payment_methods

**Purpose**: Payment method records (encrypted tokens for saved payment methods).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Payment method identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `customer_id` | UUID | NOT NULL, FK → customers(id) | Customer identifier |
| `method_type` | VARCHAR(50) | NOT NULL | Card, MobileMoney, BankAccount, etc. |
| `provider` | VARCHAR(50) | NOT NULL | Payment provider |
| `token` | TEXT | NOT NULL | Encrypted payment token |
| `is_default` | BOOLEAN | DEFAULT false | Default payment method flag |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Active, Inactive, Expired |
| `expires_at` | TIMESTAMPTZ | | Expiration timestamp |
| `metadata` | JSONB | | Additional method metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_payment_methods_tenant_id` ON `tenant_id`
- `idx_payment_methods_customer_id` ON `customer_id`
- `idx_payment_methods_method_type` ON `method_type`
- `idx_payment_methods_status` ON `status`

**Relations**:
- `customer_id` → `customers(id)`
- `tenant_id` → `tenants(id)` (via auth-service sync)

### refunds

**Purpose**: Refund records.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Refund identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `payment_transaction_id` | UUID | NOT NULL, FK → payment_transactions(id) | Payment transaction identifier |
| `refund_amount` | NUMERIC(18,2) | NOT NULL | Refund amount |
| `currency` | VARCHAR(3) | NOT NULL, DEFAULT 'KES' | ISO currency code |
| `reason` | TEXT | | Refund reason |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Pending, Processing, Completed, Failed |
| `processed_at` | TIMESTAMPTZ | | Processing timestamp |
| `metadata` | JSONB | | Additional refund metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_refunds_tenant_id` ON `tenant_id`
- `idx_refunds_payment_transaction_id` ON `payment_transaction_id`
- `idx_refunds_status` ON `status`

**Relations**:
- `payment_transaction_id` → `payment_transactions(id)`
- `tenant_id` → `tenants(id)` (via auth-service sync)

---

## Expense Management

### expenses

**Purpose**: Expense records.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Expense identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `expense_number` | VARCHAR(50) | NOT NULL, UNIQUE(tenant_id, expense_number) | Sequential expense number |
| `expense_date` | DATE | NOT NULL | Expense date |
| `category_id` | UUID | NOT NULL, FK → expense_categories(id) | Expense category identifier |
| `amount` | NUMERIC(18,2) | NOT NULL | Expense amount |
| `currency` | VARCHAR(3) | NOT NULL, DEFAULT 'KES' | ISO currency code |
| `tax_code_id` | UUID | FK → tax_codes(id) | Tax code identifier |
| `project_id` | UUID | | Project identifier (from projects-service) |
| `cost_center_id` | UUID | | Cost center identifier |
| `description` | TEXT | | Expense description |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Draft, Submitted, Approved, Rejected, Paid |
| `approved_by` | UUID | FK → users | Approver user ID |
| `approved_at` | TIMESTAMPTZ | | Approval timestamp |
| `metadata` | JSONB | | Additional expense metadata |
| `embedding` | vector(1536) | | Vector embedding for semantic search |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_expenses_tenant_id` ON `tenant_id`
- `idx_expenses_expense_number` ON `expense_number`
- `idx_expenses_category_id` ON `category_id`
- `idx_expenses_expense_date` ON `expense_date`
- `idx_expenses_status` ON `status`
- `idx_expenses_project_id` ON `project_id`
- `idx_expenses_embedding` ON `embedding` USING ivfflat (vector_cosine_ops)

**Relations**:
- `category_id` → `expense_categories(id)`
- `tax_code_id` → `tax_codes(id)`
- `approved_by` → `users(id)` (via auth-service sync)
- `tenant_id` → `tenants(id)` (via auth-service sync)

### expense_categories

**Purpose**: Expense category definitions.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Category identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `category_code` | VARCHAR(50) | NOT NULL, UNIQUE(tenant_id, category_code) | Category code |
| `category_name` | VARCHAR(255) | NOT NULL | Category name |
| `parent_id` | UUID | FK → expense_categories(id) | Parent category for hierarchy |
| `gl_account_id` | UUID | FK → chart_of_accounts(id) | GL account mapping |
| `is_active` | BOOLEAN | DEFAULT true | Active status |
| `metadata` | JSONB | | Additional category metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_expense_categories_tenant_id` ON `tenant_id`
- `idx_expense_categories_category_code` ON `category_code`
- `idx_expense_categories_parent_id` ON `parent_id`
- `idx_expense_categories_gl_account_id` ON `gl_account_id`

**Relations**:
- `parent_id` → `expense_categories(id)` (self-referential)
- `gl_account_id` → `chart_of_accounts(id)`
- `tenant_id` → `tenants(id)` (via auth-service sync)

### expense_approvals

**Purpose**: Expense approval workflow records.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Approval identifier |
| `expense_id` | UUID | NOT NULL, FK → expenses(id) ON DELETE CASCADE | Expense identifier |
| `approver_id` | UUID | NOT NULL, FK → users | Approver user ID |
| `approval_status` | VARCHAR(20) | NOT NULL, CHECK | Pending, Approved, Rejected |
| `comments` | TEXT | | Approval comments |
| `approved_at` | TIMESTAMPTZ | | Approval timestamp |
| `metadata` | JSONB | | Additional approval metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |

**Indexes**:
- `idx_expense_approvals_expense_id` ON `expense_id`
- `idx_expense_approvals_approver_id` ON `approver_id`
- `idx_expense_approvals_approval_status` ON `approval_status`

**Relations**:
- `expense_id` → `expenses(id)` ON DELETE CASCADE
- `approver_id` → `users(id)` (via auth-service sync)

### expense_receipts

**Purpose**: Expense receipt attachments.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Receipt identifier |
| `expense_id` | UUID | NOT NULL, FK → expenses(id) ON DELETE CASCADE | Expense identifier |
| `receipt_url` | TEXT | NOT NULL | S3-compatible storage URL |
| `receipt_type` | VARCHAR(50) | NOT NULL | Image, PDF, etc. |
| `uploaded_at` | TIMESTAMPTZ | NOT NULL, DEFAULT NOW() | Upload timestamp |
| `metadata` | JSONB | | Additional receipt metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |

**Indexes**:
- `idx_expense_receipts_expense_id` ON `expense_id`
- `idx_expense_receipts_receipt_type` ON `receipt_type`

**Relations**:
- `expense_id` → `expenses(id)` ON DELETE CASCADE

---

## Tax Compliance

### tax_codes

**Purpose**: Tax code definitions.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Tax code identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `tax_code` | VARCHAR(50) | NOT NULL, UNIQUE(tenant_id, tax_code) | Tax code (e.g., "VAT-16", "WHT-5") |
| `tax_name` | VARCHAR(255) | NOT NULL | Tax name |
| `tax_rate` | NUMERIC(5,2) | NOT NULL | Tax rate percentage |
| `tax_type` | VARCHAR(50) | NOT NULL | VAT, WHT, Excise, ServiceTax, etc. |
| `is_active` | BOOLEAN | DEFAULT true | Active status |
| `metadata` | JSONB | | Additional tax code metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_tax_codes_tenant_id` ON `tenant_id`
- `idx_tax_codes_tax_code` ON `tax_code`
- `idx_tax_codes_tax_type` ON `tax_type`

**Relations**:
- `tenant_id` → `tenants(id)` (via auth-service sync)

### tax_returns

**Purpose**: Tax return records.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Tax return identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `return_period` | VARCHAR(20) | NOT NULL | Return period (e.g., "2024-01") |
| `return_type` | VARCHAR(50) | NOT NULL | VAT, IncomeTax, WHT, etc. |
| `filing_date` | DATE | NOT NULL | Filing date |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Draft, Submitted, Accepted, Rejected, Amended |
| `total_tax` | NUMERIC(18,2) | NOT NULL | Total tax amount |
| `kra_reference` | VARCHAR(100) | | KRA reference number |
| `metadata` | JSONB | | Additional return metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_tax_returns_tenant_id` ON `tenant_id`
- `idx_tax_returns_return_period` ON `return_period`
- `idx_tax_returns_return_type` ON `return_type`
- `idx_tax_returns_status` ON `status`
- `idx_tax_returns_kra_reference` ON `kra_reference`

**Relations**:
- `tenant_id` → `tenants(id)` (via auth-service sync)

### tax_filings

**Purpose**: Tax filing records (KRA iTax integration).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Tax filing identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `tax_return_id` | UUID | NOT NULL, FK → tax_returns(id) | Tax return identifier |
| `filing_date` | DATE | NOT NULL | Filing date |
| `filing_status` | VARCHAR(20) | NOT NULL, CHECK | Pending, Submitted, Accepted, Rejected |
| `kra_response` | JSONB | | KRA API response |
| `submitted_at` | TIMESTAMPTZ | | Submission timestamp |
| `metadata` | JSONB | | Additional filing metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_tax_filings_tenant_id` ON `tenant_id`
- `idx_tax_filings_tax_return_id` ON `tax_return_id`
- `idx_tax_filings_filing_status` ON `filing_status`
- `idx_tax_filings_filing_date` ON `filing_date`

**Relations**:
- `tax_return_id` → `tax_returns(id)`
- `tenant_id` → `tenants(id)` (via auth-service sync)

---

## Budgeting

### budgets

**Purpose**: Budget records.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Budget identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `budget_name` | VARCHAR(255) | NOT NULL | Budget name |
| `budget_period_start` | DATE | NOT NULL | Budget period start |
| `budget_period_end` | DATE | NOT NULL | Budget period end |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Draft, Active, Closed |
| `metadata` | JSONB | | Additional budget metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_budgets_tenant_id` ON `tenant_id`
- `idx_budgets_budget_period` ON `(budget_period_start, budget_period_end)`
- `idx_budgets_status` ON `status`

**Relations**:
- `tenant_id` → `tenants(id)` (via auth-service sync)

### budget_lines

**Purpose**: Budget line items.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Budget line identifier |
| `budget_id` | UUID | NOT NULL, FK → budgets(id) ON DELETE CASCADE | Budget identifier |
| `account_id` | UUID | FK → chart_of_accounts(id) | Account identifier |
| `project_id` | UUID | | Project identifier (from projects-service) |
| `cost_center_id` | UUID | | Cost center identifier |
| `budgeted_amount` | NUMERIC(18,2) | NOT NULL | Budgeted amount |
| `actual_amount` | NUMERIC(18,2) | DEFAULT 0 | Actual amount (calculated) |
| `variance` | NUMERIC(18,2) | DEFAULT 0 | Variance (actual - budgeted) |
| `metadata` | JSONB | | Additional line metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_budget_lines_budget_id` ON `budget_id`
- `idx_budget_lines_account_id` ON `account_id`
- `idx_budget_lines_project_id` ON `project_id`

**Relations**:
- `budget_id` → `budgets(id)` ON DELETE CASCADE
- `account_id` → `chart_of_accounts(id)`

### budget_versions

**Purpose**: Budget version tracking.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Budget version identifier |
| `budget_id` | UUID | NOT NULL, FK → budgets(id) ON DELETE CASCADE | Budget identifier |
| `version_number` | INTEGER | NOT NULL | Version number |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Draft, Approved, Active |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `created_by` | UUID | FK → users | Creator user ID |
| `metadata` | JSONB | | Additional version metadata |

**Indexes**:
- `idx_budget_versions_budget_id` ON `budget_id`
- `idx_budget_versions_version_number` ON `version_number`
- `idx_budget_versions_status` ON `status`

**Relations**:
- `budget_id` → `budgets(id)` ON DELETE CASCADE
- `created_by` → `users(id)` (via auth-service sync)

---

## Integrations

### integration_configs

**Purpose**: Integration configuration (two-tier: system/tenant).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Config identifier |
| `tenant_id` | UUID | FK → tenants | Tenant isolation (NULL for system-level) |
| `integration_type` | VARCHAR(50) | NOT NULL | M-Pesa, Stripe, PayPal, KRA, BankAPI, Blockchain |
| `config_tier` | VARCHAR(20) | NOT NULL, CHECK | System, Tenant |
| `config_key` | VARCHAR(100) | NOT NULL | Configuration key |
| `config_value` | TEXT | NOT NULL | Configuration value (encrypted if `is_encrypted` = true) |
| `is_encrypted` | BOOLEAN | DEFAULT false | Encryption flag |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Active, Inactive |
| `metadata` | JSONB | | Additional config metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_integration_configs_tenant_id` ON `tenant_id`
- `idx_integration_configs_integration_type` ON `integration_type`
- `idx_integration_configs_config_tier` ON `config_tier`
- `idx_integration_configs_config_key` ON `config_key`
- UNIQUE(`tenant_id`, `integration_type`, `config_key`) WHERE `tenant_id IS NOT NULL`
- UNIQUE(`integration_type`, `config_key`) WHERE `tenant_id IS NULL`

**Relations**:
- `tenant_id` → `tenants(id)` (via auth-service sync, nullable for system-level)

### integration_logs

**Purpose**: Integration activity logs.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Log identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `integration_type` | VARCHAR(50) | NOT NULL | Integration type |
| `request_type` | VARCHAR(50) | NOT NULL | Request type (API call, webhook, etc.) |
| `request_payload` | JSONB | | Request payload |
| `response_payload` | JSONB | | Response payload |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Success, Failed, Pending |
| `error_message` | TEXT | | Error message (if failed) |
| `occurred_at` | TIMESTAMPTZ | NOT NULL, DEFAULT NOW() | Occurrence timestamp |
| `metadata` | JSONB | | Additional log metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |

**Indexes**:
- `idx_integration_logs_tenant_id` ON `tenant_id`
- `idx_integration_logs_integration_type` ON `integration_type`
- `idx_integration_logs_status` ON `status`
- `idx_integration_logs_occurred_at` ON `occurred_at` (TimescaleDB hypertable)

**Relations**:
- `tenant_id` → `tenants(id)` (via auth-service sync)

### webhook_subscriptions

**Purpose**: Outbound webhook subscriptions.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PRIMARY KEY | Subscription identifier |
| `tenant_id` | UUID | NOT NULL, FK → tenants | Tenant isolation |
| `event_key` | VARCHAR(100) | NOT NULL | Event key (e.g., "treasury.payment.success") |
| `target_url` | TEXT | NOT NULL | Webhook target URL |
| `secret` | TEXT | NOT NULL | HMAC signing secret (encrypted) |
| `status` | VARCHAR(20) | NOT NULL, CHECK | Active, Inactive, Suspended |
| `last_delivery_status` | VARCHAR(20) | | Last delivery status |
| `retry_count` | INTEGER | DEFAULT 0 | Retry count |
| `metadata` | JSONB | | Additional subscription metadata |
| `created_at` | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- `idx_webhook_subscriptions_tenant_id` ON `tenant_id`
- `idx_webhook_subscriptions_event_key` ON `event_key`
- `idx_webhook_subscriptions_status` ON `status`

**Relations**:
- `tenant_id` → `tenants(id)` (via auth-service sync)

---

## Database Views

### v_ar_aging_summary

**Purpose**: AR aging summary view.

```sql
CREATE VIEW v_ar_aging_summary AS
SELECT
    tenant_id,
    customer_id,
    SUM(CASE WHEN age_bucket = 'Current' THEN amount ELSE 0 END) AS current_amount,
    SUM(CASE WHEN age_bucket = '30Days' THEN amount ELSE 0 END) AS days_30_amount,
    SUM(CASE WHEN age_bucket = '60Days' THEN amount ELSE 0 END) AS days_60_amount,
    SUM(CASE WHEN age_bucket = '90Days' THEN amount ELSE 0 END) AS days_90_amount,
    SUM(CASE WHEN age_bucket = '120Plus' THEN amount ELSE 0 END) AS days_120_plus_amount,
    SUM(amount) AS total_outstanding
FROM ar_aging
WHERE as_of_date = CURRENT_DATE
GROUP BY tenant_id, customer_id;
```

### v_ap_aging_summary

**Purpose**: AP aging summary view.

```sql
CREATE VIEW v_ap_aging_summary AS
SELECT
    tenant_id,
    vendor_id,
    SUM(CASE WHEN age_bucket = 'Current' THEN amount ELSE 0 END) AS current_amount,
    SUM(CASE WHEN age_bucket = '30Days' THEN amount ELSE 0 END) AS days_30_amount,
    SUM(CASE WHEN age_bucket = '60Days' THEN amount ELSE 0 END) AS days_60_amount,
    SUM(CASE WHEN age_bucket = '90Days' THEN amount ELSE 0 END) AS days_90_amount,
    SUM(CASE WHEN age_bucket = '120Plus' THEN amount ELSE 0 END) AS days_120_plus_amount,
    SUM(amount) AS total_outstanding
FROM ap_aging
WHERE as_of_date = CURRENT_DATE
GROUP BY tenant_id, vendor_id;
```

### v_trial_balance

**Purpose**: Trial balance view.

```sql
CREATE VIEW v_trial_balance AS
SELECT
    lt.tenant_id,
    lt.account_id,
    coa.account_code,
    coa.account_name,
    coa.account_type,
    SUM(lt.debit_amount) AS total_debits,
    SUM(lt.credit_amount) AS total_credits,
    SUM(lt.debit_amount - lt.credit_amount) AS balance
FROM ledger_transactions lt
JOIN chart_of_accounts coa ON lt.account_id = coa.id
WHERE lt.transaction_date BETWEEN :period_start AND :period_end
GROUP BY lt.tenant_id, lt.account_id, coa.account_code, coa.account_name, coa.account_type;
```

### v_payment_summary

**Purpose**: Payment summary view by provider and status.

```sql
CREATE VIEW v_payment_summary AS
SELECT
    tenant_id,
    provider,
    status,
    COUNT(*) AS transaction_count,
    SUM(amount) AS total_amount,
    AVG(amount) AS average_amount
FROM payment_transactions
WHERE processed_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY tenant_id, provider, status;
```

---

## Database Functions

### fn_calculate_ar_aging(invoice_id UUID, as_of_date DATE)

**Purpose**: Calculate AR aging for a specific invoice.

```sql
CREATE OR REPLACE FUNCTION fn_calculate_ar_aging(
    p_invoice_id UUID,
    p_as_of_date DATE DEFAULT CURRENT_DATE
) RETURNS TABLE (
    age_bucket VARCHAR(20),
    amount NUMERIC(18,2)
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        CASE
            WHEN p_as_of_date - i.due_date <= 0 THEN 'Current'
            WHEN p_as_of_date - i.due_date <= 30 THEN '30Days'
            WHEN p_as_of_date - i.due_date <= 60 THEN '60Days'
            WHEN p_as_of_date - i.due_date <= 90 THEN '90Days'
            ELSE '120Plus'
        END AS age_bucket,
        (i.total_amount - COALESCE(SUM(ip.amount_applied), 0)) AS amount
    FROM invoices i
    LEFT JOIN invoice_payments ip ON i.id = ip.invoice_id
    WHERE i.id = p_invoice_id
    GROUP BY i.id, i.due_date, i.total_amount;
END;
$$ LANGUAGE plpgsql;
```

### fn_post_ledger_entry(p_tenant_id UUID, p_account_id UUID, p_debit NUMERIC, p_credit NUMERIC, p_reference_type VARCHAR, p_reference_id UUID)

**Purpose**: Post a ledger entry with double-entry validation.

```sql
CREATE OR REPLACE FUNCTION fn_post_ledger_entry(
    p_tenant_id UUID,
    p_account_id UUID,
    p_debit NUMERIC(18,2),
    p_credit NUMERIC(18,2),
    p_reference_type VARCHAR(50),
    p_reference_id UUID,
    p_description TEXT DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    v_transaction_id UUID;
BEGIN
    -- Validate double-entry
    IF (p_debit = 0 AND p_credit = 0) OR (p_debit > 0 AND p_credit > 0) THEN
        RAISE EXCEPTION 'Invalid double-entry: must have either debit or credit, not both';
    END IF;

    -- Insert ledger transaction
    INSERT INTO ledger_transactions (
        tenant_id, account_id, debit_amount, credit_amount,
        reference_type, reference_id, description, transaction_date
    ) VALUES (
        p_tenant_id, p_account_id, p_debit, p_credit,
        p_reference_type, p_reference_id, p_description, CURRENT_DATE
    ) RETURNING id INTO v_transaction_id;

    RETURN v_transaction_id;
END;
$$ LANGUAGE plpgsql;
```

### fn_reconcile_bank_transaction(p_bank_transaction_id UUID, p_ledger_transaction_id UUID, p_match_type VARCHAR)

**Purpose**: Match a bank transaction to a ledger transaction.

```sql
CREATE OR REPLACE FUNCTION fn_reconcile_bank_transaction(
    p_bank_transaction_id UUID,
    p_ledger_transaction_id UUID,
    p_match_type VARCHAR(20) DEFAULT 'Manual'
) RETURNS UUID AS $$
DECLARE
    v_reconciliation_id UUID;
    v_match_id UUID;
BEGIN
    -- Get or create reconciliation
    SELECT id INTO v_reconciliation_id
    FROM reconciliations
    WHERE bank_account_id = (
        SELECT bank_account_id FROM bank_transactions WHERE id = p_bank_transaction_id
    )
    AND status = 'InProgress'
    ORDER BY reconciliation_date DESC
    LIMIT 1;

    IF v_reconciliation_id IS NULL THEN
        INSERT INTO reconciliations (
            tenant_id, bank_account_id, reconciliation_date, status
        ) VALUES (
            (SELECT tenant_id FROM bank_transactions WHERE id = p_bank_transaction_id),
            (SELECT bank_account_id FROM bank_transactions WHERE id = p_bank_transaction_id),
            CURRENT_DATE,
            'InProgress'
        ) RETURNING id INTO v_reconciliation_id;
    END IF;

    -- Create match
    INSERT INTO reconciliation_matches (
        reconciliation_id, bank_transaction_id, ledger_transaction_id, match_type
    ) VALUES (
        v_reconciliation_id, p_bank_transaction_id, p_ledger_transaction_id, p_match_type
    ) RETURNING id INTO v_match_id;

    -- Update bank transaction status
    UPDATE bank_transactions
    SET reconciliation_status = 'Matched', reconciliation_id = v_reconciliation_id
    WHERE id = p_bank_transaction_id;

    RETURN v_match_id;
END;
$$ LANGUAGE plpgsql;
```

---

## Integration Points

### Internal Service References

**Auth Service**:
- `tenant_id` → References `tenants(id)` via tenant sync events
- `user_id` → References `users(id)` for approvers, creators, etc.

**Cafe Backend**:
- Creates invoices via API → `invoices` table
- Payment processing → `payment_intents`, `payment_transactions` tables
- References: `invoice_id`, `payment_intent_id`

**POS Service**:
- Payment processing → `payment_intents`, `payment_transactions` tables
- References: `payment_intent_id`

**Logistics Service**:
- Expense export → `expenses` table
- References: `expense_id`

**Inventory Service**:
- PO matching → `purchase_orders`, `vendor_bills` tables
- References: `purchase_order_id`, `vendor_bill_id`

**Projects Service**:
- Project expense allocation → `expenses.project_id`
- Budget tracking → `budgets`, `budget_lines.project_id`
- References: `project_id` (UUID from projects-service)

### External API Integrations

**M-Pesa Daraja API**:
- Configuration stored in `integration_configs` (encrypted)
- Payment processing → `payment_transactions` with `provider = 'M-Pesa'`
- Webhook callbacks → `integration_logs`

**Stripe**:
- Configuration stored in `integration_configs` (encrypted)
- Payment processing → `payment_transactions` with `provider = 'Stripe'`
- Webhook callbacks → `integration_logs`

**PayPal**:
- Configuration stored in `integration_configs` (encrypted)
- Payment processing → `payment_transactions` with `provider = 'PayPal'`
- Webhook callbacks → `integration_logs`

**KRA iTax API**:
- Configuration stored in `integration_configs` (encrypted)
- Tax filing → `tax_filings` table
- API responses stored in `tax_filings.kra_response` (JSONB)

**Bank APIs**:
- Configuration stored in `integration_configs` (encrypted)
- Transaction import → `bank_transactions` table
- Auto-reconciliation via matching engine

**Blockchain (Ethereum, Polygon)**:
- Configuration stored in `integration_configs` (encrypted)
- Payment processing → `payment_transactions` with `provider = 'Blockchain'`
- Settlement proofs stored in `payment_transactions.metadata` (JSONB)

---

## Cross-Service Entity Alignment

This service owns all financial entities. Other services reference treasury entities via IDs:
- **Cafe Backend**: Creates invoices via API, references `invoice_id`
- **POS Service**: Processes payments via API, references `payment_intent_id`
- **Logistics Service**: Exports expenses, references `expense_id`
- **Inventory Service**: Matches supplier invoices, references `vendor_bill_id`
- **Projects Service**: Allocates expenses to projects, references `project_id` (from projects-service)

---

## Maintenance Notes

- Maintain this document alongside schema updates.
- After changing Ent schema definitions, run `go generate ./internal/ent` and refresh the ERD.
- Vector embeddings are generated using OpenAI embeddings API or similar (1536 dimensions).
- TimescaleDB hypertables are created for time-series data: `ledger_transactions`, `bank_transactions`, `customer_ledger`, `payment_transactions`, `integration_logs`.
- All encrypted fields use AES-256-GCM encryption with keys stored in Vault/K8s secrets.
- Indexes are maintained automatically via Ent migrations.
- Views and functions are versioned and managed via migration scripts.