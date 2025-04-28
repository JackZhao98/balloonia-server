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
	}

	// 需要认证的路由
	protected := r.Group("/api")
	protected.Use(middleware.AuthMiddleware(jwtService))
	{
		// 在这里添加需要认证的路由
		// protected.GET("/profile", h.GetProfile)
		// protected.PUT("/profile", h.UpdateProfile)
	}
}
