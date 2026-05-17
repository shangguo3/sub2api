package admin

import (
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type AWSSSOOAuthHandler struct {
	awsSSOOAuthService *service.AWSSSOOAuthService
}

func NewAWSSSOOAuthHandler(awsSSOOAuthService *service.AWSSSOOAuthService) *AWSSSOOAuthHandler {
	return &AWSSSOOAuthHandler{awsSSOOAuthService: awsSSOOAuthService}
}

type AWSSSOStartDeviceAuthRequest struct {
	SSOStartURL string `json:"sso_start_url" binding:"required"`
	SSORegion   string `json:"sso_region" binding:"required"`
}

// StartDeviceAuth registers an OIDC client and starts device authorization
// POST /api/v1/admin/aws/sso/start-device-auth
func (h *AWSSSOOAuthHandler) StartDeviceAuth(c *gin.Context) {
	var req AWSSSOStartDeviceAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	result, err := h.awsSSOOAuthService.StartDeviceAuth(c.Request.Context(), req.SSOStartURL, req.SSORegion)
	if err != nil {
		response.InternalError(c, "Failed to start device auth: "+err.Error())
		return
	}

	response.Success(c, result)
}

type AWSSSOPollTokenRequest struct {
	SSORegion    string `json:"sso_region" binding:"required"`
	ClientID     string `json:"client_id" binding:"required"`
	ClientSecret string `json:"client_secret" binding:"required"`
	DeviceCode   string `json:"device_code" binding:"required"`
}

// PollForToken polls for the SSO access token after the user has authorized the device
// POST /api/v1/admin/aws/sso/poll-token
func (h *AWSSSOOAuthHandler) PollForToken(c *gin.Context) {
	var req AWSSSOPollTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	result, err := h.awsSSOOAuthService.PollForToken(c.Request.Context(), &service.AWSSSOPollInput{
		SSORegion:    req.SSORegion,
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		DeviceCode:   req.DeviceCode,
	})
	if err != nil {
		response.BadRequest(c, "Token poll failed: "+err.Error())
		return
	}

	response.Success(c, result)
}
