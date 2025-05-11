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
// @Router /auth/login/apple [post]
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

// RequestPasswordReset godoc
// @Summary Request password reset
// @Description Request a password reset token to be sent to email
// @Tags auth
// @Accept json
// @Produce json
// @Param request body RequestPasswordResetRequest true "Email for password reset"
// @Success 200 {object} map[string]string
// @Failure 400 {object} error
// @Failure 500 {object} error
// @Router /auth/password-reset/request [post]
func (h *Handler) RequestPasswordReset(c *gin.Context) {
	var req RequestPasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.Service.RequestPasswordReset(c.Request.Context(), req.Email); err != nil {
		// 为了安全，不返回具体错误
		c.JSON(http.StatusOK, gin.H{"message": "如果该邮箱存在，重置密码的邮件已发送"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "如果该邮箱存在，重置密码的邮件已发送"})
}

// ResetPassword godoc
// @Summary Reset password
// @Description Reset password using the token received in email
// @Tags auth
// @Accept json
// @Produce json
// @Param request body ResetPasswordRequest true "Password reset data"
// @Success 200 {object} map[string]string
// @Failure 400 {object} error
// @Failure 500 {object} error
// @Router /auth/password-reset/reset [post]
func (h *Handler) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.Service.ResetPassword(c.Request.Context(), req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效或已过期的重置令牌"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "密码重置成功"})
}

// GetProfile godoc
// @Summary Get user profile
// @Description Get the profile of the authenticated user
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} ProfileResponse
// @Failure 401 {object} error
// @Failure 500 {object} error
// @Router /users/profile [get]
func (h *Handler) GetProfile(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	profile, err := h.Service.GetProfile(c.Request.Context(), userID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, profile)
}

// UpdateProfile godoc
// @Summary Update user profile
// @Description Update the profile of the authenticated user
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body ProfileUpdateRequest true "Profile update data"
// @Success 200 {object} ProfileResponse
// @Failure 400 {object} error
// @Failure 401 {object} error
// @Failure 500 {object} error
// @Router /users/profile [put]
func (h *Handler) UpdateProfile(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req ProfileUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	profile, err := h.Service.UpdateProfile(c.Request.Context(), userID.(string), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, profile)
}
