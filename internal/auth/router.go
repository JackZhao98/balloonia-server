package auth

import (
	"github.com/JackZhao98/balloonia-server/internal/auth/jwt"
	"github.com/gin-gonic/gin"
)

// RegisterRoutes registers all auth routes
func RegisterRoutes(r *gin.Engine, h Handler, jwt jwt.Service) {
	// 公开路由
	auth := r.Group("/auth")
	{
		auth.POST("/register", h.Register)
		auth.POST("/login", h.Login)
		auth.POST("/refresh", h.RefreshToken)
		auth.POST("/login/apple", h.AppleSignIn)
		auth.POST("/password-reset/request", h.RequestPasswordReset)
		auth.POST("/password-reset/reset", h.ResetPassword)

		// 受保护的路由
		protected := auth.Group("")
		protected.Use(jwt.AuthMiddleware())
		{
			protected.DELETE("/account", h.DeleteAccount)
		}
	}
}
