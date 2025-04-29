package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

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
