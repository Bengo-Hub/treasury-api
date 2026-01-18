package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/treasury-api/internal/modules/rbac"
	"github.com/bengobox/treasury-api/internal/services/usersync"
)

// UserHandler handles user management operations.
type UserHandler struct {
	logger      *zap.Logger
	rbacService *rbac.Service
	syncService *usersync.Service
	rbacRepo    rbac.Repository
}

// NewUserHandler creates a new user handler.
func NewUserHandler(logger *zap.Logger, rbacService *rbac.Service, syncService *usersync.Service, rbacRepo rbac.Repository) *UserHandler {
	return &UserHandler{
		logger:      logger,
		rbacService: rbacService,
		syncService: syncService,
		rbacRepo:    rbacRepo,
	}
}

// CreateUserRequest represents a request to create a user.
type CreateUserRequest struct {
	Email      string `json:"email"`
	TenantSlug string `json:"tenant_slug"`
}

// CreateUser creates a new user and syncs with auth-service.
func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := chi.URLParam(r, "tenantID")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid tenant ID")
		return
	}

	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Sync user with auth-service
	syncReq := usersync.SyncUserRequest{
		Email:      req.Email,
		TenantSlug: req.TenantSlug,
		Service:    "treasury-service",
	}

	syncResp, err := h.syncService.SyncUser(r.Context(), syncReq)
	if err != nil {
		h.logger.Error("failed to sync user with auth-service", zap.Error(err))
		respondError(w, http.StatusInternalServerError, "failed to sync user")
		return
	}

	// Sync user in treasury service
	user, err := h.rbacService.SyncUser(r.Context(), tenantID, syncResp.UserID, syncResp.Email)
	if err != nil {
		h.logger.Error("failed to sync user in treasury", zap.Error(err))
		respondError(w, http.StatusInternalServerError, "failed to sync user")
		return
	}

	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"user_id":   user.ID,
		"email":     user.Email,
		"tenant_id": user.TenantID,
		"created":   true,
	})
}

// GetUser retrieves a user by ID.
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := chi.URLParam(r, "tenantID")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid tenant ID")
		return
	}

	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	user, err := h.rbacRepo.GetUser(r.Context(), tenantID, userID)
	if err != nil {
		h.logger.Error("failed to get user", zap.Error(err))
		respondError(w, http.StatusNotFound, "user not found")
		return
	}

	respondJSON(w, http.StatusOK, user)
}

// ListUsers lists all users for a tenant.
func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	// This would require adding a ListUsers method to the repository
	// For now, return not implemented
	respondError(w, http.StatusNotImplemented, "list users not yet implemented")
}

// GetUserRoles retrieves roles for a user.
func (h *UserHandler) GetUserRoles(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := chi.URLParam(r, "tenantID")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid tenant ID")
		return
	}

	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	roles, err := h.rbacService.GetUserRoles(r.Context(), tenantID, userID)
	if err != nil {
		h.logger.Error("failed to get user roles", zap.Error(err))
		respondError(w, http.StatusInternalServerError, "failed to get user roles")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{"roles": roles})
}

// RegisterRoutes registers user management routes.
func (h *UserHandler) RegisterRoutes(r chi.Router) {
	r.Post("/users", h.CreateUser)
	r.Get("/users/{id}", h.GetUser)
	r.Get("/users", h.ListUsers)
	r.Get("/users/{id}/roles", h.GetUserRoles)
}
