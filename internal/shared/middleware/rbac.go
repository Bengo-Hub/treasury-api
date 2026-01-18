package middleware

import (
	"net/http"

	authclient "github.com/Bengo-Hub/shared-auth-client"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/treasury-app/internal/modules/rbac"
)

// RequirePermission returns a middleware that checks if the user has the required permission.
func RequirePermission(rbacService *rbac.Service, logger *zap.Logger, permissionCode string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := authclient.ClaimsFromContext(r.Context())
			if !ok {
				logger.Warn("no claims in context")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			userID, err := claims.UserID()
			if err != nil || userID == uuid.Nil {
				logger.Warn("invalid user ID in claims")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			tenantID, err := claims.TenantUUID()
			if err != nil || tenantID == nil {
				logger.Warn("invalid tenant ID in claims")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			// Check if user is superuser (bypass permission check)
			if claims.HasScope("superuser") {
				next.ServeHTTP(w, r)
				return
			}

			hasPermission, err := rbacService.HasPermission(r.Context(), *tenantID, userID, permissionCode)
			if err != nil {
				logger.Error("permission check failed", zap.Error(err))
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}

			if !hasPermission {
				logger.Warn("permission denied",
					zap.String("user_id", userID.String()),
					zap.String("permission", permissionCode),
				)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole returns a middleware that checks if the user has the required role.
func RequireRole(rbacService *rbac.Service, logger *zap.Logger, roleCode string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := authclient.ClaimsFromContext(r.Context())
			if !ok {
				logger.Warn("no claims in context")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			userID, err := claims.UserID()
			if err != nil || userID == uuid.Nil {
				logger.Warn("invalid user ID in claims")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			tenantID, err := claims.TenantUUID()
			if err != nil || tenantID == nil {
				logger.Warn("invalid tenant ID in claims")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			// Check if user is superuser (bypass role check)
			if claims.HasScope("superuser") {
				next.ServeHTTP(w, r)
				return
			}

			hasRole, err := rbacService.HasRole(r.Context(), *tenantID, userID, roleCode)
			if err != nil {
				logger.Error("role check failed", zap.Error(err))
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}

			if !hasRole {
				logger.Warn("role denied",
					zap.String("user_id", userID.String()),
					zap.String("role", roleCode),
				)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
