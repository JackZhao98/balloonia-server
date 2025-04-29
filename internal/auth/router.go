package auth

import (
	"github.com/JackZhao98/balloonia-server/internal/auth/jwt"
	"github.com/JackZhao98/balloonia-server/internal/auth/middleware"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine, h Handler, jwtService jwt.Service) {
	// 公开路由
	auth := r.Group("/auth")
	{
		auth.POST("/register", h.Register)
		auth.POST("/login", h.Login)
		auth.POST("/refresh", h.RefreshToken)
		auth.POST("/login/apple", h.AppleSignIn)
	}

	// 需要认证的路由
	protected := r.Group("/auth")
	protected.Use(middleware.AuthMiddleware(jwtService))
	{
		protected.DELETE("/account", h.DeleteAccount)
	}

	// API 路由
	api := r.Group("/api")
	api.Use(middleware.AuthMiddleware(jwtService))
	{
		api.GET("/profile", h.GetProfile)
		api.PUT("/profile", h.UpdateProfile)
	}
}
