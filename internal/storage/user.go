package storage

import (
	"errors"
	"fmt"
	"log"
	"time"

	"connectrpc.com/connect"
	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	UserId    string     `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()" json:"userId"`
	Email     string     `gorm:"unique;default:uuid_generate_v4()" json:"email"`
	FirstName string     `json:"firstName"`
	LastName  string     `json:"lastName"`
	Password  string     `json:"-"`
	IsAdmin   bool       `gorm:"default:false" json:"isAdmin"`
	CreatedAt *time.Time `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`

	// WebAuthn-specific fields
	CredentialID        []byte `gorm:"type:bytea" json:"credentialID"`        // WebAuthn Credential ID
	PublicKey           []byte `gorm:"type:bytea" json:"publicKey"`           // Public Key used for authentication
	AuthenticatorAAGUID []byte `gorm:"type:bytea" json:"authenticatorAAGUID"` // Authenticator AAGUID
	SignCount           uint32 `json:"signCount"`                             // Sign counter to prevent replay attacks
}

type UserService struct {
	connection      *gorm.DB
	shardWriteQueue chan User
	shards          []*gorm.DB
}

func NewUserService(authStorage *AuthStorage) *UserService {
	return &UserService{
		connection:      authStorage.connection,
		shardWriteQueue: authStorage.shardWriteQueue,
		shards:          authStorage.shards,
	}
}

func (userService *UserService) CreateAdmin(email string, password string, firstName string, lastName string) (string, error) {
	user := User{
		Email:     email,
		Password:  password,
		FirstName: firstName,
		LastName:  lastName,
		IsAdmin:   true,
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 14)

	if err != nil {
		return "", errors.New("failed to hash password")
	}

	user.Password = string(hashedPassword)
	if err := userService.connection.Create(&user).Error; err != nil {
		return "", err
	}

	QueueShardWrite(user, userService.shardWriteQueue)

	return user.UserId, nil
}

func (userService *UserService) CreateWebAuthnAdmin(webAuthnUser *User) (string, error) {
	webAuthnUser.IsAdmin = true

	if err := userService.connection.Create(&webAuthnUser).Error; err != nil {
		return "", err
	}

	QueueShardWrite(*webAuthnUser, userService.shardWriteQueue)

	return webAuthnUser.UserId, nil
}

func (userService *UserService) LoginAsAdmin(email string, password string) (*User, error) {
	user := &User{}

	if err := userService.connection.Where("email = ? AND is_admin = ?", email, true).First(user).Error; err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not found"))
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {

		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("password is incorrect"))
	}

	return user, nil
}

func (userService *UserService) LoginAsWebAuthAdmin(userId string) (*User, error) {
	user := &User{}
	if err := userService.connection.Where("user_id = ? AND is_admin = ?", userId, true).First(user).Error; err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("user not found"))
	}

	return user, nil
}

func (userService *UserService) RevokeJWTByUserId(userId string) error {
	err := userService.connection.Model(&RefreshToken{}).Where("user_id = ?", userId).Update("is_revoked", true).Error

	if err != nil {
		log.Fatal(err)
		return err
	}

	fmt.Println("Revoked JWT for user ID:", userId)

	return nil
}

func (userService *UserService) RevokeJwtByJwtToken(accessToken string) error {
	err := userService.connection.Model(&RefreshToken{}).Where("access_token = ?", accessToken).Update("is_revoked", true).Error

	if err != nil {
		log.Fatal(err)
		return err
	}

	fmt.Println("Revoked JWT:", accessToken)

	return nil
}

func (userService *UserService) findRefreshTokenByUserId(userId string) (*gorm.DB, error) {
	result := userService.connection.Model(&RefreshToken{}).Where("user_id = ? AND expiry > NOW() AND is_revoked=false", userId).Limit(1)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("refresh token is expired or invalid")
		}
		return nil, result.Error
	}

	return result, nil
}

func (userService *UserService) GetUserById(id string) (User, error) {
	user, err := ReadFromShard(id, userService.shards)

	if err != nil {
		if err = userService.connection.Where("user_id = ?", id).First(&user).Error; err != nil {
			return user, err
		}
	}
	return user, err
}

type RefreshToken struct {
	ID          string `gorm:"type:uuid;default:uuid_generate_v4()" json:"id"`
	UserID      string `json:"userID"`
	JTI         string `json:"jti"`
	AccessToken string `json:"accessToken"`
	Expiry      string `json:"expiry"`
	IsRevoked   bool   `json:"isRevoked"`
}

func (userService *UserService) StoreJTI(jti string, userID string, refreshTokenExp string, accessToken string) error {
	refreshToken := RefreshToken{
		UserID:      userID,
		JTI:         jti,
		Expiry:      refreshTokenExp,
		IsRevoked:   false,
		AccessToken: accessToken,
	}

	if err := userService.connection.Table("refresh_tokens").Create(&refreshToken).Error; err != nil {
		log.Fatal(err)
		return err
	}

	return nil
}

func (userService *UserService) CheckIfRefreshTokenIsRevokedByUserId(userId string) (string, error) {
	var refreshToken RefreshToken

	err := userService.connection.Table("refresh_tokens").Where("user_id = ? AND expiry > NOW()", userId).Order("token_id DESC").Limit(1).Select("is_revoked, jti").Scan(&refreshToken).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", fmt.Errorf("refresh token is expired or invalid")
		}
		return "", err
	}

	isRevoked := refreshToken.IsRevoked

	if isRevoked {
		return "", fmt.Errorf("refresh token is revoked")
	}

	return refreshToken.JTI, nil
}

func (userService *UserService) GetConnection() *gorm.DB {
	return userService.connection
}

// Implement WebAuthn User interface for the User struct
func (u *User) WebAuthnID() []byte {
	return []byte(u.UserId) // Use UUID as the WebAuthn ID
}

func (u *User) WebAuthnName() string {
	return u.Email // Use the email address as the WebAuthn name
}

func (u *User) WebAuthnDisplayName() string {
	return u.FirstName + " " + u.LastName // Full name for display
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return []webauthn.Credential{
		{
			ID:        u.CredentialID,
			PublicKey: u.PublicKey,
		},
	}
}
