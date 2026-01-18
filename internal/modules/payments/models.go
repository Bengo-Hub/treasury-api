package payments

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// PaymentIntent represents a payment intent entity.
type PaymentIntent struct {
	ID            uuid.UUID
	TenantID      uuid.UUID
	ReferenceID   string
	ReferenceType string // order, subscription, invoice
	PaymentMethod string // mpesa, stripe, cash, bank_transfer
	Currency      string
	Amount        decimal.Decimal
	Status        string // pending, processing, succeeded, failed, cancelled
	CustomerID    *uuid.UUID
	Description   *string
	ExpiresAt     *time.Time
	Metadata      map[string]any
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

