package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// ============================================================
// OAuth 2.0 Authorization Code Flow endpoints
//
// GET  /v1/oauth/authorize  - Authorization endpoint (shows login page or redirects)
// POST /v1/oauth/token      - Token endpoint (exchanges code for access token)
// GET  /v1/oauth/userinfo   - UserInfo endpoint (returns user profile)
//
// Admin endpoints:
// GET    /api/oauth2/clients     - List all OAuth clients
// POST   /api/oauth2/clients     - Create a new OAuth client
// DELETE /api/oauth2/clients/:id - Delete an OAuth client
// ============================================================

// --- Authorization Endpoint ---

// OAuth2Authorize handles GET /v1/oauth/authorize
// Standard OAuth 2.0 Authorization Code flow.
// If user is logged in (session), issues auth code and redirects.
// If not logged in, shows a login page.
func OAuth2Authorize(c *gin.Context) {
	clientId := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.DefaultQuery("scope", "read")
	state := c.Query("state")

	if responseType != "code" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_response_type",
			"error_description": "Only 'code' response_type is supported",
		})
		return
	}

	if clientId == "" || redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "client_id and redirect_uri are required",
		})
		return
	}

	// Validate client
	client, err := model.GetOAuthClientByClientId(clientId)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client",
			"error_description": "Unknown client_id",
		})
		return
	}

	// Validate redirect_uri
	if !isValidRedirectURI(client, redirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid redirect_uri",
		})
		return
	}

	// Check if user is already logged in via session
	session := sessions.Default(c)
	userId := session.Get("id")

	if userId != nil {
		// User is logged in, issue authorization code directly
		issueAuthCodeAndRedirect(c, client, userId.(int), redirectURI, scope, state)
		return
	}

	// User not logged in, redirect to frontend OAuth page
	frontendURL := fmt.Sprintf("/oauth2/authorize?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s&state=%s",
		url.QueryEscape(clientId),
		url.QueryEscape(redirectURI),
		url.QueryEscape(responseType),
		url.QueryEscape(scope),
		url.QueryEscape(state),
	)
	c.Redirect(http.StatusFound, frontendURL)
}

// OAuth2AuthorizeSubmit handles POST /v1/oauth/authorize
// Processes the login form submission from the OAuth login page.
func OAuth2AuthorizeSubmit(c *gin.Context) {
	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		ClientId    string `json:"client_id"`
		RedirectURI string `json:"redirect_uri"`
		Scope       string `json:"scope"`
		State       string `json:"state"`
	}

	if err := json.NewDecoder(c.Request.Body).Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Invalid request body"})
		return
	}

	// Validate client
	client, err := model.GetOAuthClientByClientId(req.ClientId)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	if !isValidRedirectURI(client, req.RedirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Invalid redirect_uri"})
		return
	}

	// Authenticate user
	user := model.User{Username: req.Username, Password: req.Password}
	if err := user.ValidateAndFill(); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   "access_denied",
			"message": "Invalid username or password",
		})
		return
	}

	// Issue authorization code
	authCode := &model.OAuthAuthorizationCode{
		ClientId:    req.ClientId,
		UserId:      user.Id,
		RedirectURI: req.RedirectURI,
		Scope:       req.Scope,
		State:       req.State,
	}
	if err := model.CreateAuthorizationCode(authCode); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Return the redirect URL with code
	redirectURL, _ := url.Parse(req.RedirectURI)
	q := redirectURL.Query()
	q.Set("code", authCode.Code)
	if req.State != "" {
		q.Set("state", req.State)
	}
	redirectURL.RawQuery = q.Encode()

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"redirect_uri": redirectURL.String(),
	})
}

// --- Token Endpoint ---

// OAuth2Token handles POST /v1/oauth/token
// Supports grant_type: authorization_code, refresh_token
func OAuth2Token(c *gin.Context) {
	grantType := c.PostForm("grant_type")
	if grantType == "" {
		// Try JSON body
		var body map[string]string
		if err := json.NewDecoder(c.Request.Body).Decode(&body); err == nil {
			grantType = body["grant_type"]
			// Re-set form values from JSON for uniform access
			for k, v := range body {
				c.Request.PostForm.Set(k, v)
			}
		}
	}

	switch grantType {
	case "authorization_code":
		handleAuthorizationCodeGrant(c)
	case "refresh_token":
		handleRefreshTokenGrant(c)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "Supported: authorization_code, refresh_token",
		})
	}
}

func handleAuthorizationCodeGrant(c *gin.Context) {
	code := c.PostForm("code")
	clientId := c.PostForm("client_id")
	redirectURI := c.PostForm("redirect_uri")

	if code == "" || clientId == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "code and client_id are required"})
		return
	}

	// Validate authorization code
	authCode, err := model.GetAuthorizationCode(code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "Invalid or expired authorization code"})
		return
	}

	if authCode.ClientId != clientId {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "Client mismatch"})
		return
	}

	if redirectURI != "" && authCode.RedirectURI != redirectURI {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "redirect_uri mismatch"})
		return
	}

	// Mark code as used
	model.MarkAuthorizationCodeUsed(code)

	// Create or find an API token for the user (this is the real token for /v1/messages)
	apiKey, err := getOrCreateUserApiToken(authCode.UserId, clientId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Failed to create API token"})
		return
	}

	// Also create an OAuth access token for userinfo endpoint
	accessToken := &model.OAuthAccessToken{
		ClientId:  clientId,
		UserId:    authCode.UserId,
		Scope:     authCode.Scope,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	if err := model.CreateOAuthAccessToken(accessToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Return the real API key as access_token so it can be used directly with /v1/messages
	c.JSON(http.StatusOK, gin.H{
		"access_token":  apiKey,
		"token_type":    "Bearer",
		"expires_in":    int(time.Until(accessToken.ExpiresAt).Seconds()),
		"refresh_token": accessToken.RefreshToken,
		"scope":         accessToken.Scope,
	})
}

func handleRefreshTokenGrant(c *gin.Context) {
	refreshToken := c.PostForm("refresh_token")
	if refreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	oldToken, err := model.GetOAuthAccessTokenByRefresh(refreshToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "Invalid refresh token"})
		return
	}

	// Delete old token
	model.DeleteOAuthAccessToken(oldToken.Id)

	// Issue new token
	newToken := &model.OAuthAccessToken{
		ClientId:  oldToken.ClientId,
		UserId:    oldToken.UserId,
		Scope:     oldToken.Scope,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	if err := model.CreateOAuthAccessToken(newToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  newToken.AccessToken,
		"token_type":    "Bearer",
		"expires_in":    int(time.Until(newToken.ExpiresAt).Seconds()),
		"refresh_token": newToken.RefreshToken,
		"scope":         newToken.Scope,
	})
}

// --- UserInfo Endpoint ---

// OAuth2UserInfo handles GET /v1/oauth/userinfo
// Returns user profile for the authenticated access token.
func OAuth2UserInfo(c *gin.Context) {
	// Extract Bearer token
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := model.GetOAuthAccessToken(tokenStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "Token expired or invalid"})
		return
	}

	user, err := model.GetUserById(token.UserId, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":           user.Id,
		"username":     user.Username,
		"display_name": user.DisplayName,
		"email":        user.Email,
		"role":         user.Role,
		"status":       user.Status,
		"group":        user.Group,
	})
}

// --- Admin: OAuth Client Management ---

func OAuth2ListClients(c *gin.Context) {
	clients, err := model.GetAllOAuthClients()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": clients})
}

func OAuth2CreateClient(c *gin.Context) {
	var client model.OAuthClient
	if err := c.ShouldBindJSON(&client); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid request"})
		return
	}
	if client.Name == "" || client.RedirectURIs == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "name and redirect_uris are required"})
		return
	}
	if err := model.CreateOAuthClient(&client); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"client_id":     client.ClientId,
			"client_secret": client.ClientSecret,
			"name":          client.Name,
			"redirect_uris": client.RedirectURIs,
		},
	})
}

func OAuth2DeleteClient(c *gin.Context) {
	id := c.Param("id")
	intId, err := strconv.Atoi(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid id"})
		return
	}
	if err := model.DeleteOAuthClient(intId); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// --- Helpers ---

// getOrCreateUserApiToken finds an existing API token for the user created by OAuth,
// or creates a new one. This token is the real key for /v1/messages.
func getOrCreateUserApiToken(userId int, clientId string) (string, error) {
	tokenName := fmt.Sprintf("oauth-%s", clientId)

	// Check if user already has an OAuth-created token
	tokens, err := model.GetAllUserTokens(userId, 0, 100)
	if err == nil {
		for _, t := range tokens {
			if t.Name == tokenName && t.Status == 1 {
				return t.Key, nil
			}
		}
	}

	// Create a new unlimited API token for the user
	key, err := common.GenerateKey()
	if err != nil {
		return "", err
	}

	now := common.GetTimestamp()
	token := &model.Token{
		UserId:         userId,
		Name:           tokenName,
		Key:            key,
		CreatedTime:    now,
		AccessedTime:   now,
		ExpiredTime:    -1, // never expires
		UnlimitedQuota: true,
		Status:         1,
	}
	if err := token.Insert(); err != nil {
		return "", err
	}

	return key, nil
}

func isValidRedirectURI(client *model.OAuthClient, uri string) bool {
	// Allow localhost for development (any port)
	if strings.HasPrefix(uri, "http://localhost") || strings.HasPrefix(uri, "http://127.0.0.1") {
		return true
	}
	// Allow lumio.run URLs
	if strings.HasPrefix(uri, "https://lumio.run") {
		return true
	}
	// Allow any HTTPS URL for the claude-code-haha client (manual flow uses various redirect URIs)
	if client.ClientId == "claude-code-haha" && strings.HasPrefix(uri, "https://") {
		return true
	}
	allowed := strings.Split(client.RedirectURIs, ",")
	for _, a := range allowed {
		if strings.TrimSpace(a) == uri {
			return true
		}
	}
	return false
}

func issueAuthCodeAndRedirect(c *gin.Context, client *model.OAuthClient, userId int, redirectURI, scope, state string) {
	authCode := &model.OAuthAuthorizationCode{
		ClientId:    client.ClientId,
		UserId:      userId,
		RedirectURI: redirectURI,
		Scope:       scope,
		State:       state,
	}
	if err := model.CreateAuthorizationCode(authCode); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	redirectURL, _ := url.Parse(redirectURI)
	q := redirectURL.Query()
	q.Set("code", authCode.Code)
	if state != "" {
		q.Set("state", state)
	}
	redirectURL.RawQuery = q.Encode()

	c.Redirect(http.StatusFound, redirectURL.String())
}
