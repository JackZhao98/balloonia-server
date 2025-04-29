package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// @title Balloonia API
// @version 1.0
// @description This is the Balloonia server API documentation
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

// Handler bundles auth routes
type Handler struct {
	Service Service
}

// NewHandler creates a new auth handler
func NewHandler(s Service) *Handler {
	return &Handler{Service: s}
}

// Register godoc
// @Summary Register a new user
// @Description Register a new user with email and password
// @Tags auth
// @Accept json
// @Produce json
// @Param request body RegisterRequest true "Registration data"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} error
// @Failure 500 {object} error
// @Router /auth/register [post]
func (h *Handler) Register(c *gin.Context) {
	var in RegisterRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	resp, err := h.Service.Register(c.Request.Context(), in)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, resp)
}

// Login godoc
// @Summary Login user
// @Description Login with email and password
// @Tags auth
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Login credentials"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} error
// @Failure 401 {object} error
// @Failure 500 {object} error
// @Router /auth/login [post]
func (h *Handler) Login(c *gin.Context) {
	var in LoginRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	resp, err := h.Service.Login(c.Request.Context(), in)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// RefreshToken godoc
// @Summary Refresh access token
// @Description Get a new access token using refresh token
// @Tags auth
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body RefreshTokenRequest true "Refresh token"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} error
// @Failure 401 {object} error
// @Failure 500 {object} error
// @Router /auth/refresh [post]
func (h *Handler) RefreshToken(c *gin.Context) {
	var in RefreshTokenRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	resp, err := h.Service.RefreshToken(c.Request.Context(), in.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// AppleSignIn godoc
// @Summary Sign in with Apple
// @Description Handle Apple Sign In
// @Tags auth
// @Accept json
// @Produce json
// @Param request body AppleSigninRequest true "Apple Sign In data"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} error
// @Failure 500 {object} error
// @Router /auth/apple/signin [post]
func (h *Handler) AppleSignIn(c *gin.Context) {
	var in AppleSigninRequest
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	resp, err := h.Service.AppleSignin(c.Request.Context(), in)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}
