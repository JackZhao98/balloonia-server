package main

import (
	"embed"
	"log"
	"net/http"
	"path/filepath"

	"github.com/JackZhao98/balloonia-server/config"
	"github.com/JackZhao98/balloonia-server/internal/auth"
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

	authRepo := auth.NewRepository(db.DB)
	authSvc := auth.NewService(authRepo)
	authH := auth.NewHandler(authSvc)

	router := gin.Default()

	router.Static("/docs", filepath.Join(".", "docs"))
	router.GET("/docs", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/docs/index.html")
	})

	api := router.Group("/")
	auth.RegisterRoutes(api, authH)
	router.Run(":" + config.Get().Port)
}
