# Treasury Service - Apache Superset Integration

## Overview

The Treasury service integrates with the centralized Apache Superset instance for BI dashboards, analytics, and reporting. Superset is deployed as a centralized service accessible to all BengoBox services.

---

## Architecture

### Service Configuration

**Environment Variables**:
- `SUPERSET_BASE_URL` - Superset service URL
- `SUPERSET_ADMIN_USERNAME` - Admin username (K8s secret)
- `SUPERSET_ADMIN_PASSWORD` - Admin password (K8s secret)
- `SUPERSET_API_VERSION` - API version (default: v1)

**Authentication**:
- Admin credentials used for backend-to-Superset communication
- User authentication via JWT tokens passed to Superset for SSO
- Guest tokens generated for embedded dashboards

---

## Integration Methods

### 1. REST API Client

Backend uses Go HTTP client configured for Superset REST API calls.

**Base Configuration**:
- Base URL: `SUPERSET_BASE_URL/api/v1`
- Default headers: `Content-Type: application/json`
- Authentication: Bearer token from Superset login endpoint
- Retry policy: Exponential backoff (3 retries)
- Circuit breaker: Opens after 5 consecutive failures

**Key API Endpoints**:

**Authentication**:
- `POST /api/v1/security/login` - Login with admin credentials
- `POST /api/v1/security/refresh` - Refresh access token
- `POST /api/v1/security/guest_token/` - Generate guest token for embedding

**Data Sources**:
- `GET /api/v1/database/` - List all data sources
- `POST /api/v1/database/` - Create new data source
- `PUT /api/v1/database/{id}` - Update data source

**Dashboards**:
- `GET /api/v1/dashboard/` - List all dashboards
- `POST /api/v1/dashboard/` - Create new dashboard
- `GET /api/v1/dashboard/{id}` - Get dashboard details

### 2. Database Direct Connection

Superset connects directly to PostgreSQL database via read-only user for data access.

**Connection Configuration**:
- Database type: PostgreSQL with TimescaleDB extension
- Connection string: Provided to Superset via data source API
- Read-only user: `superset_readonly` (created in PostgreSQL)
- Permissions: SELECT only on all tables, no write access
- SSL: Required for production connections

**Read-Only User Setup**:
- Create `superset_readonly` role in PostgreSQL
- Grant CONNECT on database
- Grant USAGE on schema
- Grant SELECT on all tables
- Set default privileges for future tables

**Connection String** (for Superset):
```
postgresql://superset_readonly:password@postgresql.infra.svc.cluster.local:5432/treasury_db?sslmode=require
```

---

## Pre-Built Dashboards

### 1. Financial Overview Dashboard

**Charts**:
- Revenue by period (line chart)
- Profit & Loss summary (table)
- Cash position (metric)
- Outstanding receivables (metric)
- Outstanding payables (metric)

**Filters**:
- Date range
- Branch selection
- Currency

**Data Source**: `ledger_transactions`, `invoices`, `vendor_bills` tables

### 2. Payment Analytics Dashboard

**Charts**:
- Payment volume by gateway (pie chart)
- Payment success rate (line chart)
- Average transaction value (metric)
- Payment method breakdown (bar chart)
- Refund rate (metric)

**Filters**:
- Date range
- Payment gateway
- Payment status

**Data Source**: `payment_transactions`, `payment_intents` tables

### 3. AR/AP Aging Dashboard

**Charts**:
- AR aging buckets (bar chart)
- AP aging buckets (bar chart)
- Aging trends (line chart)
- Collection efficiency (metric)
- Payment efficiency (metric)

**Filters**:
- Date range
- Customer/Vendor selection
- Aging bucket

**Data Source**: `ar_aging`, `ap_aging`, `customer_ledger` tables

### 4. Bank Reconciliation Dashboard

**Charts**:
- Reconciliation status (pie chart)
- Unreconciled items (table)
- Reconciliation rate (metric)
- Bank balance trends (line chart)
- Variance analysis (bar chart)

**Filters**:
- Date range
- Bank account selection
- Reconciliation status

**Data Source**: `bank_accounts`, `bank_transactions`, `reconciliations` tables

### 5. Tax Compliance Dashboard

**Charts**:
- Tax liability by type (bar chart)
- Tax filing status (pie chart)
- Tax payment trends (line chart)
- Compliance score (metric)
- Pending filings (table)

**Filters**:
- Date range
- Tax type
- Filing status

**Data Source**: `tax_returns`, `tax_filings`, `tax_codes` tables

### 6. Expense Analytics Dashboard

**Charts**:
- Expense by category (pie chart)
- Expense trends (line chart)
- Budget vs actual (bar chart)
- Top expense categories (table)
- Expense approval rate (metric)

**Filters**:
- Date range
- Expense category
- Approval status

**Data Source**: `expenses`, `expense_categories`, `budgets` tables

---

## Implementation Details

### Initialization Process

1. Authenticate with Superset using admin credentials
2. Create/update data source pointing to PostgreSQL with TimescaleDB
3. Create/update dashboards for each module:
   - Financial Overview Dashboard
   - Payment Analytics Dashboard
   - AR/AP Aging Dashboard
   - Bank Reconciliation Dashboard
   - Tax Compliance Dashboard
   - Expense Analytics Dashboard
4. Log warnings for dashboard creation failures (non-blocking)

### Dashboard Bootstrap

**Backend Endpoint**: `GET /api/v1/dashboards/{module}/embed`

**Process**:
1. Extract tenant ID from context
2. Get dashboard ID for module from Superset
3. Generate guest token with Row-Level Security (RLS) clause filtering by tenant_id
4. Construct embed URL with dashboard ID and guest token
5. Return embed URL with expiration time (5 minutes)

### Row-Level Security (RLS)

**Implementation**:
- Guest tokens include RLS clauses
- RLS filters data by `tenant_id`
- Each tenant sees only their data

---

## Error Handling

### Retry Logic

**Retry Policy**:
- Maximum 3 retry attempts
- Exponential backoff (1s, 2s, 4s delays)
- Retry on 5xx errors or network failures
- Return response on success or after max retries

### Circuit Breaker

**Implementation**:
- Opens after 5 consecutive failures
- Half-open after 60 seconds
- Closes on successful request

### Fallback Strategies

**Superset Unavailable**:
- Return cached dashboard URLs (if available)
- Show static dashboard images
- Log error for monitoring
- Alert operations team

---

## Monitoring

### Metrics

**Integration-Specific Metrics**:
- Superset API call latency (p50, p95, p99)
- Dashboard creation/update success rates
- Guest token generation latency
- Data source connection health

**Prometheus Metrics**:
- `superset_api_call_duration_seconds` - Histogram of API call durations (labeled by endpoint, status)
- `superset_dashboard_views_total` - Counter of dashboard views (labeled by dashboard, tenant)

### Alerts

**Alert Conditions**:
- Superset service unavailability
- High API call failure rate (>5%)
- Dashboard creation failures
- Data source connection failures

---

## Security Considerations

### Authentication & Authorization

- Admin credentials stored in K8s secrets
- Guest tokens expire after 5 minutes
- RLS ensures tenant data isolation
- JWT tokens validated for SSO

### Data Privacy

- Read-only database user
- RLS filters enforce tenant isolation
- Sensitive financial data masked in logs
- PII data excluded from dashboards (if applicable)

---

## References

- [Apache Superset REST API Documentation](https://superset.apache.org/docs/api)
- [Superset Deployment Guide](../../devops-k8s/docs/superset-deployment.md)
- [Cafe Superset Integration](../Cafe/cafe-backend/docs/superset-integration.md)

