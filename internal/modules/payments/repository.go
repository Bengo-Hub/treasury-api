package payments

import (
	"context"

	"github.com/google/uuid"
)

// Repository abstracts persistence for payment intents.
type Repository interface {
	CreatePaymentIntent(ctx context.Context, tenantID uuid.UUID, intent *PaymentIntent) error
	GetPaymentIntent(ctx context.Context, tenantID uuid.UUID, intentID uuid.UUID) (*PaymentIntent, error)
	GetPaymentIntentByReference(ctx context.Context, tenantID uuid.UUID, referenceID string) (*PaymentIntent, error)
	UpdatePaymentIntentStatus(ctx context.Context, tenantID uuid.UUID, intentID uuid.UUID, status string) error
	ListPaymentIntents(ctx context.Context, tenantID uuid.UUID, filters PaymentIntentFilters) ([]*PaymentIntent, error)
}

// PaymentIntentFilters for listing payment intents.
type PaymentIntentFilters struct {
	Status        *string
	PaymentMethod *string
	ReferenceType *string
	CustomerID    *uuid.UUID
}

