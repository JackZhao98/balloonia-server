package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetProfile godoc
// @Summary Get user profile
// @Description Get the profile of the authenticated user
// @Tags auth
// @Accept json
// @Produce json
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} error
// @Failure 500 {object} error
// @Router /api/profile [get]
func (h *Handler) GetProfile(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// TODO: 实现获取用户资料的逻辑
	c.JSON(http.StatusOK, gin.H{
		"user_id": userID,
		"message": "Profile endpoint - to be implemented",
	})
}

// UpdateProfile godoc
// @Summary Update user profile
// @Description Update the profile of the authenticated user
// @Tags auth
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body map[string]interface{} true "Profile update data"
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} error
// @Failure 500 {object} error
// @Router /api/profile [put]
func (h *Handler) UpdateProfile(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// TODO: 实现更新用户资料的逻辑
	c.JSON(http.StatusOK, gin.H{
		"user_id": userID,
		"message": "Profile update endpoint - to be implemented",
	})
}

// DeleteAccount godoc
// @Summary Delete user account
// @Description Soft delete the user's account and revoke all tokens
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Failure 401 {object} error
// @Failure 500 {object} error
// @Router /auth/account [delete]
func (h *Handler) DeleteAccount(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	if err := h.Service.DeleteAccount(c.Request.Context(), userID.(string)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "account deleted successfully"})
}
