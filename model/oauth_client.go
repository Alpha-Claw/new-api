package model

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"gorm.io/gorm"
)

// OAuthClient represents a registered OAuth 2.0 client application
type OAuthClient struct {
	Id           int            `json:"id" gorm:"primaryKey"`
	ClientId     string         `json:"client_id" gorm:"type:varchar(64);uniqueIndex;not null"`
	ClientSecret string         `json:"client_secret" gorm:"type:varchar(128);not null"`
	Name         string         `json:"name" gorm:"type:varchar(128);not null"`
	RedirectURIs string         `json:"redirect_uris" gorm:"type:text;not null"` // comma-separated
	Scopes       string         `json:"scopes" gorm:"type:varchar(512);default:'read'"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `json:"-" gorm:"index"`
}

// OAuthAuthorizationCode represents a temporary authorization code
type OAuthAuthorizationCode struct {
	Id          int       `json:"id" gorm:"primaryKey"`
	Code        string    `json:"code" gorm:"type:varchar(64);uniqueIndex;not null"`
	ClientId    string    `json:"client_id" gorm:"type:varchar(64);index;not null"`
	UserId      int       `json:"user_id" gorm:"index;not null"`
	RedirectURI string    `json:"redirect_uri" gorm:"type:text;not null"`
	Scope       string    `json:"scope" gorm:"type:varchar(512)"`
	State       string    `json:"state" gorm:"type:varchar(256)"`
	ExpiresAt   time.Time `json:"expires_at" gorm:"not null"`
	Used        bool      `json:"used" gorm:"default:false"`
	CreatedAt   time.Time `json:"created_at"`
}

// OAuthAccessToken represents an issued access token
type OAuthAccessToken struct {
	Id           int       `json:"id" gorm:"primaryKey"`
	AccessToken  string    `json:"access_token" gorm:"type:varchar(128);uniqueIndex;not null"`
	RefreshToken string    `json:"refresh_token" gorm:"type:varchar(128);uniqueIndex"`
	ClientId     string    `json:"client_id" gorm:"type:varchar(64);index;not null"`
	UserId       int       `json:"user_id" gorm:"index;not null"`
	Scope        string    `json:"scope" gorm:"type:varchar(512)"`
	ExpiresAt    time.Time `json:"expires_at" gorm:"not null"`
	CreatedAt    time.Time `json:"created_at"`
}

func generateRandomToken(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// --- OAuthClient CRUD ---

func CreateOAuthClient(client *OAuthClient) error {
	if client.ClientId == "" {
		client.ClientId = generateRandomToken(16)
	}
	if client.ClientSecret == "" {
		client.ClientSecret = generateRandomToken(32)
	}
	return DB.Create(client).Error
}

func GetOAuthClientByClientId(clientId string) (*OAuthClient, error) {
	var client OAuthClient
	err := DB.Where("client_id = ?", clientId).First(&client).Error
	if err != nil {
		return nil, err
	}
	return &client, nil
}

func GetAllOAuthClients() ([]*OAuthClient, error) {
	var clients []*OAuthClient
	err := DB.Find(&clients).Error
	return clients, err
}

func DeleteOAuthClient(id int) error {
	return DB.Delete(&OAuthClient{}, id).Error
}

// --- Authorization Code ---

func CreateAuthorizationCode(code *OAuthAuthorizationCode) error {
	if code.Code == "" {
		code.Code = generateRandomToken(20)
	}
	if code.ExpiresAt.IsZero() {
		code.ExpiresAt = time.Now().Add(10 * time.Minute)
	}
	return DB.Create(code).Error
}

func GetAuthorizationCode(code string) (*OAuthAuthorizationCode, error) {
	var authCode OAuthAuthorizationCode
	err := DB.Where("code = ? AND used = ? AND expires_at > ?", code, false, time.Now()).First(&authCode).Error
	if err != nil {
		return nil, err
	}
	return &authCode, nil
}

func MarkAuthorizationCodeUsed(code string) error {
	return DB.Model(&OAuthAuthorizationCode{}).Where("code = ?", code).Update("used", true).Error
}

// --- Access Token ---

func CreateOAuthAccessToken(token *OAuthAccessToken) error {
	if token.AccessToken == "" {
		token.AccessToken = "sk-lumio-" + generateRandomToken(32)
	}
	if token.RefreshToken == "" {
		token.RefreshToken = "rt-lumio-" + generateRandomToken(32)
	}
	if token.ExpiresAt.IsZero() {
		token.ExpiresAt = time.Now().Add(30 * 24 * time.Hour) // 30 days
	}
	return DB.Create(token).Error
}

func GetOAuthAccessToken(accessToken string) (*OAuthAccessToken, error) {
	var token OAuthAccessToken
	err := DB.Where("access_token = ? AND expires_at > ?", accessToken, time.Now()).First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func GetOAuthAccessTokenByRefresh(refreshToken string) (*OAuthAccessToken, error) {
	var token OAuthAccessToken
	err := DB.Where("refresh_token = ?", refreshToken).First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func DeleteOAuthAccessToken(id int) error {
	return DB.Delete(&OAuthAccessToken{}, id).Error
}

// CleanupExpiredOAuthData removes expired codes and tokens
func CleanupExpiredOAuthData() error {
	now := time.Now()
	if err := DB.Where("expires_at < ?", now).Delete(&OAuthAuthorizationCode{}).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	if err := DB.Where("expires_at < ?", now).Delete(&OAuthAccessToken{}).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return nil
}
