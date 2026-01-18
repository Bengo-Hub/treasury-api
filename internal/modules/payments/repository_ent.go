package payments

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/bengobox/treasury-api/internal/ent"
	"github.com/bengobox/treasury-api/internal/ent/paymentintent"
)

// EntRepository implements the Repository interface using Ent ORM.
type EntRepository struct {
	client *ent.Client
}

// NewEntRepository creates a new Ent-backed repository.
func NewEntRepository(client *ent.Client) *EntRepository {
	return &EntRepository{client: client}
}

// CreatePaymentIntent creates a new payment intent.
func (r *EntRepository) CreatePaymentIntent(ctx context.Context, tenantID uuid.UUID, intent *PaymentIntent) error {
	if intent == nil {
		return errors.New("payment intent cannot be nil")
	}

	builder := r.client.PaymentIntent.Create().
		SetID(intent.ID).
		SetTenantID(tenantID).
		SetReferenceID(intent.ReferenceID).
		SetReferenceType(intent.ReferenceType).
		SetPaymentMethod(intent.PaymentMethod).
		SetCurrency(intent.Currency).
		SetAmount(intent.Amount).
		SetStatus(intent.Status).
		SetMetadata(intent.Metadata)

	if intent.CustomerID != nil {
		builder.SetCustomerID(*intent.CustomerID)
	}
	if intent.Description != nil {
		builder.SetDescription(*intent.Description)
	}
	if intent.ExpiresAt != nil {
		builder.SetExpiresAt(*intent.ExpiresAt)
	}

	_, err := builder.Save(ctx)
	if err != nil {
		return fmt.Errorf("create payment intent: %w", err)
	}

	return nil
}

// GetPaymentIntent retrieves a payment intent by ID.
func (r *EntRepository) GetPaymentIntent(ctx context.Context, tenantID uuid.UUID, intentID uuid.UUID) (*PaymentIntent, error) {
	entIntent, err := r.client.PaymentIntent.Query().
		Where(
			paymentintent.ID(intentID),
			paymentintent.TenantID(tenantID),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("payment intent not found: %w", err)
		}
		return nil, fmt.Errorf("get payment intent: %w", err)
	}

	return mapEntPaymentIntent(entIntent), nil
}

// GetPaymentIntentByReference retrieves a payment intent by reference ID.
func (r *EntRepository) GetPaymentIntentByReference(ctx context.Context, tenantID uuid.UUID, referenceID string) (*PaymentIntent, error) {
	entIntent, err := r.client.PaymentIntent.Query().
		Where(
			paymentintent.TenantID(tenantID),
			paymentintent.ReferenceID(referenceID),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("payment intent not found: %w", err)
		}
		return nil, fmt.Errorf("get payment intent by reference: %w", err)
	}

	return mapEntPaymentIntent(entIntent), nil
}

// UpdatePaymentIntentStatus updates the status of a payment intent.
func (r *EntRepository) UpdatePaymentIntentStatus(ctx context.Context, tenantID uuid.UUID, intentID uuid.UUID, status string) error {
	_, err := r.client.PaymentIntent.Update().
		Where(
			paymentintent.ID(intentID),
			paymentintent.TenantID(tenantID),
		).
		SetStatus(status).
		SetUpdatedAt(time.Now()).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("update payment intent status: %w", err)
	}

	return nil
}

// ListPaymentIntents lists payment intents with filters.
func (r *EntRepository) ListPaymentIntents(ctx context.Context, tenantID uuid.UUID, filters PaymentIntentFilters) ([]*PaymentIntent, error) {
	query := r.client.PaymentIntent.Query().
		Where(paymentintent.TenantID(tenantID))

	if filters.Status != nil {
		query = query.Where(paymentintent.Status(*filters.Status))
	}
	if filters.PaymentMethod != nil {
		query = query.Where(paymentintent.PaymentMethod(*filters.PaymentMethod))
	}
	if filters.ReferenceType != nil {
		query = query.Where(paymentintent.ReferenceType(*filters.ReferenceType))
	}
	if filters.CustomerID != nil {
		query = query.Where(paymentintent.CustomerID(*filters.CustomerID))
	}

	entIntents, err := query.Order(ent.Desc(paymentintent.FieldCreatedAt)).All(ctx)
	if err != nil {
		return nil, fmt.Errorf("list payment intents: %w", err)
	}

	intents := make([]*PaymentIntent, len(entIntents))
	for i, entIntent := range entIntents {
		intents[i] = mapEntPaymentIntent(entIntent)
	}

	return intents, nil
}

// mapEntPaymentIntent converts an Ent PaymentIntent to domain model.
func mapEntPaymentIntent(entIntent *ent.PaymentIntent) *PaymentIntent {
	intent := &PaymentIntent{
		ID:            entIntent.ID,
		TenantID:      entIntent.TenantID,
		ReferenceID:   entIntent.ReferenceID,
		ReferenceType: entIntent.ReferenceType,
		PaymentMethod: entIntent.PaymentMethod,
		Currency:      entIntent.Currency,
		Amount:        entIntent.Amount,
		Status:        entIntent.Status,
		Metadata:      entIntent.Metadata,
		CreatedAt:     entIntent.CreatedAt,
		UpdatedAt:     entIntent.UpdatedAt,
	}

	// Optional fields - check for zero values
	if entIntent.CustomerID != uuid.Nil {
		intent.CustomerID = &entIntent.CustomerID
	}
	if entIntent.Description != "" {
		intent.Description = &entIntent.Description
	}
	if !entIntent.ExpiresAt.IsZero() {
		intent.ExpiresAt = &entIntent.ExpiresAt
	}

	return intent
}

