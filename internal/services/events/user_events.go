package events

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"go.uber.org/zap"

	"github.com/bengobox/treasury-app/internal/modules/rbac"
)

// UserEventConsumer handles auth-service user events.
type UserEventConsumer struct {
	rbacService *rbac.Service
	logger      *zap.Logger
}

// NewUserEventConsumer creates a new user event consumer.
func NewUserEventConsumer(rbacService *rbac.Service, logger *zap.Logger) *UserEventConsumer {
	return &UserEventConsumer{
		rbacService: rbacService,
		logger:      logger,
	}
}

// UserCreatedEvent represents auth.user.created event.
type UserCreatedEvent struct {
	UserID    string                 `json:"user_id"`
	TenantID  string                 `json:"tenant_id"`
	Email     string                 `json:"email"`
	CreatedAt string                 `json:"created_at"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// UserUpdatedEvent represents auth.user.updated event.
type UserUpdatedEvent struct {
	UserID   string                 `json:"user_id"`
	TenantID string                 `json:"tenant_id"`
	Email    string                 `json:"email"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ConsumeUserEvents subscribes to auth-service user events.
func (c *UserEventConsumer) ConsumeUserEvents(ctx context.Context, js nats.JetStreamContext) error {
	// Subscribe to auth.user.created
	subCreated, err := js.Subscribe("auth.user.created", func(msg *nats.Msg) {
		var event UserCreatedEvent
		if err := json.Unmarshal(msg.Data, &event); err != nil {
			c.logger.Error("failed to unmarshal user.created event", zap.Error(err))
			msg.Nak()
			return
		}

		userID, err := uuid.Parse(event.UserID)
		if err != nil {
			c.logger.Error("invalid user_id in event", zap.Error(err))
			msg.Nak()
			return
		}

		tenantID, err := uuid.Parse(event.TenantID)
		if err != nil {
			c.logger.Error("invalid tenant_id in event", zap.Error(err))
			msg.Nak()
			return
		}

		// Sync user in treasury service
		if _, err := c.rbacService.SyncUser(ctx, tenantID, userID, event.Email); err != nil {
			c.logger.Error("failed to sync user from event", zap.Error(err))
			msg.Nak()
			return
		}

		c.logger.Info("user synced from auth.user.created event",
			zap.String("user_id", userID.String()),
			zap.String("tenant_id", tenantID.String()),
		)

		msg.Ack()
	}, nats.Durable("treasury-user-created"))
	if err != nil {
		return fmt.Errorf("subscribe to auth.user.created: %w", err)
	}
	defer subCreated.Unsubscribe()

	// Subscribe to auth.user.updated
	subUpdated, err := js.Subscribe("auth.user.updated", func(msg *nats.Msg) {
		var event UserUpdatedEvent
		if err := json.Unmarshal(msg.Data, &event); err != nil {
			c.logger.Error("failed to unmarshal user.updated event", zap.Error(err))
			msg.Nak()
			return
		}

		// Sync user in treasury service
		if _, err := c.rbacService.SyncUser(ctx, event.TenantID, event.UserID, event.Email); err != nil {
			c.logger.Error("failed to sync user from updated event", zap.Error(err))
			msg.Nak()
			return
		}

		c.logger.Info("user synced from auth.user.updated event",
			zap.String("user_id", userID.String()),
			zap.String("tenant_id", tenantID.String()),
		)

		msg.Ack()
	}, nats.Durable("treasury-user-updated"))
	if err != nil {
		return fmt.Errorf("subscribe to auth.user.updated: %w", err)
	}
	defer subUpdated.Unsubscribe()

	// Wait for context cancellation
	<-ctx.Done()
	return nil
}
