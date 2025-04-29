// @title        Balloonia API
// @version      1.0
// @description  This is the Balloonia server API documentation
// @BasePath     /

// 定义一个名为 BearerAuth 的 apiKey 安全方案
// @securityDefinitions.apikey  BearerAuth
// @in                          header
// @name                        Authorization
// @description                 Enter your bearer token in the format: Bearer <token>

package main

import (
	"embed"
	"log"
	"net/http"
	"path/filepath"

	"github.com/JackZhao98/balloonia-server/config"
	"github.com/JackZhao98/balloonia-server/internal/auth"
	"github.com/JackZhao98/balloonia-server/internal/auth/jwt"
	"github.com/JackZhao98/balloonia-server/internal/db"
	"github.com/gin-gonic/gin"
)

type Application struct {
}

var docsFS embed.FS

func main() {
	if err := config.LoadConfig(); err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	db.ConnectDatabase()

	// 初始化 JWT 服务
	jwtService := jwt.NewService()

	// 初始化认证服务
	authRepo := auth.NewRepository(db.DB)
	authSvc := auth.NewService(authRepo, jwtService)
	authH := auth.NewHandler(authSvc)

	router := gin.Default()

	router.Static("/docs", filepath.Join(".", "docs"))
	router.GET("/docs", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/docs/index.html")
	})

	// 注册路由
	auth.RegisterRoutes(router, *authH, jwtService)
	router.Run(":" + config.Get().Port)
}
