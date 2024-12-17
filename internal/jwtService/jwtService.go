package jwtService

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/alexey-petrov/go-webauthn/internal/storage"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

// Generate random JTI (JWT ID)
func generateJTI() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

var ACCESS_TOKEN_EXPIRATION = 1 * time.Hour

var REFRESH_TOKEN_EXPIRATION = 24 * ACCESS_TOKEN_EXPIRATION * 7
var ACCESS_TOKEN_EXPIRATION_DEVELOPMENT = REFRESH_TOKEN_EXPIRATION

func isDevelopment() bool {
	return os.Getenv("ENV") == "development"
}

// Store JTI in HTTP-only cookie
func SetRefreshCookie(c *fiber.Ctx, jti string) {
	publicUrl := os.Getenv("PUBLIC_URL")
	publicDomain := os.Getenv("PUBLIC_DOMAIN")

	sameSite := "Lax"
	secure := false
	domain := "localhost"

	if publicUrl != "" {
		secure = true
		domain = publicDomain
	}

	c.Cookie(&fiber.Cookie{
		Name:     os.Getenv("JWT_REFRESH_KEY"),             // Name of the cookie to store JTI
		Value:    jti,                                      // JTI as value
		Expires:  time.Now().Add(REFRESH_TOKEN_EXPIRATION), // Cookie expiry matches refresh token expiry
		HTTPOnly: true,                                     // HTTP-only, prevents JavaScript access
		// @TODO: Set Secure to true/Strict in production
		Secure:   secure,   // Send only over HTTPS
		SameSite: sameSite, // Prevent CSRF attacks
		Domain:   domain,
	})
}

// Store JTI in HTTP-only cookie
func SetAccessTokenCookie(c *fiber.Ctx, token string) {
	publicUrl := os.Getenv("PUBLIC_URL")
	publicDomain := os.Getenv("PUBLIC_DOMAIN")

	sameSite := "Lax"
	secure := false
	domain := "localhost"

	if publicUrl != "" {
		secure = true
		domain = publicDomain
	}

	expires := ACCESS_TOKEN_EXPIRATION

	if isDevelopment() {
		expires = ACCESS_TOKEN_EXPIRATION_DEVELOPMENT
	}

	c.Cookie(&fiber.Cookie{
		Name:     os.Getenv("ACCESS_TOKEN_COOKIE_NAME"), // Name of the cookie to store JTI
		Value:    token,                                 // JTI as value
		Expires:  time.Now().Add(expires),               // Cookie expiry matches refresh token expiry
		HTTPOnly: true,                                  // HTTP-only, prevents JavaScript access
		// @TODO: Set Secure to true/Strict in production
		Secure:   secure,   // Send only over HTTPS
		SameSite: sameSite, // Prevent CSRF attacks
		Domain:   domain,
	})
}

func GetConnectRpcAccessTokenCookie(token string) string {
	publicUrl := os.Getenv("PUBLIC_URL")
	publicDomain := os.Getenv("PUBLIC_DOMAIN")

	sameSite := "Lax"
	secure := false
	domain := "localhost"

	if publicUrl != "" {
		secure = true
		domain = publicDomain
	}

	cookieName := os.Getenv("ACCESS_TOKEN_COOKIE_NAME")
	cookieValue := token
	expires := time.Now().Add(REFRESH_TOKEN_EXPIRATION).Format(time.RFC1123) // Cookie expiry formatted to a standard HTTP date

	// Construct the cookie as a string
	cookieStr := fmt.Sprintf("%s=%s; Expires=%s; HttpOnly; SameSite=%s; Domain=%s; Path=/",
		cookieName, cookieValue, expires, sameSite, domain)

	if secure {
		cookieStr += "; Secure"
	}

	return cookieStr
}

func DeleteAccessTokenCookie(c *fiber.Ctx) {
	publicDomain := os.Getenv("PUBLIC_DOMAIN")
	publicUrl := os.Getenv("PUBLIC_URL")

	domain := "localhost"

	if publicUrl != "" {
		domain = publicDomain
	}

	c.Cookie(&fiber.Cookie{
		Name:     os.Getenv("ACCESS_TOKEN_COOKIE_NAME"),
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
		Secure:   true,
		SameSite: "Lax",
		Domain:   domain,
	})
}

type AuthClaims struct {
	ID        string `json:"id"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	Admin     bool   `json:"role"`
	jwt.RegisteredClaims
}
type RefreshJWTClaims struct {
	ID string `json:"id"`
	jwt.RegisteredClaims
}

type JwtServiceStore struct {
	logger      *slog.Logger
	userService *storage.UserService
}

func New(logger *slog.Logger, userService *storage.UserService) *JwtServiceStore {
	return &JwtServiceStore{
		logger,
		userService,
	}
}

func (jwtStore JwtServiceStore) GenerateJWTAccessToken(userId string) (string, error) {
	// Set expiration time for the token
	expirationTime := time.Now().Add(ACCESS_TOKEN_EXPIRATION)
	userData, _ := jwtStore.userService.GetUserById(userId)
	// Create the claims, which includes the user ID and standard JWT claims
	claims := &AuthClaims{
		ID:        userData.UserId,
		FirstName: userData.FirstName,
		LastName:  userData.LastName,
		Email:     userData.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    "identia-be",
		},
	}

	// Create the token with the specified signing method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	accessToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET_KEY")))
	if err != nil {
		return "", err
	}
	fmt.Println("Generated JWT:", accessToken)
	return accessToken, err
}

func GenerateJWTRefreshToken(userId string) (string, time.Time, error) {
	// Set expiration time for the token
	expirationTime := time.Now().Add(REFRESH_TOKEN_EXPIRATION)

	jti, err := generateJTI()

	if err != nil {
		return "", time.Time{}, err
	}

	refreshClaims := &RefreshJWTClaims{
		ID: userId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    "identia-be",
			ID:        jti, // Set JTI in the refresh token
		},
	}

	// Create the token with the specified signing method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)

	// Sign the token with the secret key
	refreshToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET_KEY")))
	if err != nil {
		return "", time.Time{}, err
	}
	fmt.Println("Generated REFRESH TOKEN:", refreshToken)
	return refreshToken, expirationTime, err
}

// Generate JWT with user ID
func (jwtStore JwtServiceStore) GenerateJWTPair(userId string) (string, error) {
	accessToken, err := jwtStore.GenerateJWTAccessToken(userId)
	if err != nil {
		return "", err
	}
	// Set expiration time for Refresh Token (long-lived)
	refreshToken, expirationTime, err := GenerateJWTRefreshToken(userId)

	if err != nil {
		return "", err
	}

	userData, _ := jwtStore.userService.GetUserById(userId)

	// Store the JTI in the database
	err = jwtStore.userService.StoreJTI(refreshToken, userData.UserId, expirationTime.Format(time.RFC3339), accessToken)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func (jwtStore JwtServiceStore) handleRefreshAccessTokenByUserId(userId, accessToken string) (string, error) {
	result := jwtStore.userService.GetConnection().Model(&storage.RefreshToken{}).Where("user_id = ? AND access_token = ? AND expiry > NOW() AND is_revoked=false", userId, accessToken).Limit(1)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", fmt.Errorf("refresh token is expired or invalid")
		}
		return "", result.Error
	}

	accessToken, err := jwtStore.GenerateJWTAccessToken(userId)

	return accessToken, err
}

func (jwtStore JwtServiceStore) HandleInvalidateUserSession(userId string) error {
	if userId == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "No user id found")
	}

	err := jwtStore.userService.GetConnection().Model(&storage.RefreshToken{}).Where("user_id = ?", userId).Update("is_revoked", true).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("refresh token is expired or invalid")
		}
		return err
	}

	return nil
}

func (jwtStore JwtServiceStore) RefreshAccessToken(userId string, accessToken string) (string, error) {
	// Validate the JTI against stored refresh tokens in your database (mock validation here)
	// In production, check if the JTI is valid and not revoked.
	accessToken, err := jwtStore.handleRefreshAccessTokenByUserId(userId, accessToken)

	if err != nil {
		return "", fmt.Errorf("token refresh failed")
	}

	return accessToken, nil
}

func (jwtStore JwtServiceStore) VerifyToken(token string) (*jwt.Token, error) {
	// Parse the JWT token
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {

		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method: %v", token.Header["alg"])
		}

		// Return the secret key used for signing
		return []byte(os.Getenv("JWT_SECRET_KEY")), nil
	})
	if err != nil {
		// Check if the error is due to token expiration
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("access token expired")
		}
		return nil, fmt.Errorf("invalid access token")
	}
	// Check if the token is valid
	if !parsedToken.Valid {
		return nil, errors.New("invalid JWT token")
	}

	if err := jwtStore.userService.GetConnection().Table("refresh_tokens").Where("access_token = ?", parsedToken).Error; err != nil {
		return nil, errors.New("access token is invalid")
	}

	// Return the parsed token
	return parsedToken, nil
}

func (jwtStore JwtServiceStore) RevokeJWTByUserId(userId string) error {

	err := jwtStore.userService.RevokeJWTByUserId(userId)

	if err != nil {
		return err
	}

	return nil
}

func (jwtStore JwtServiceStore) RevokeJwtByJwtToken(accessToken string) error {

	err := jwtStore.userService.RevokeJwtByJwtToken(accessToken)

	if err != nil {
		return err
	}

	return nil
}
