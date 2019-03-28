package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/jmoiron/sqlx"
	"github.com/json-multiplex/iam-service/internal/models"
	uuid "github.com/satori/go.uuid"
)

type DBStore struct {
	DB *sqlx.DB
}

type dbUser struct {
	ID          uuid.UUID  `db:"id"`
	AccountID   uuid.UUID  `db:"account_id"`
	Slug        string     `db:"slug"`
	DisplayName string     `db:"display_name"`
	IsRoot      bool       `db:"is_root"`
	CreateTime  time.Time  `db:"create_time"`
	UpdateTime  time.Time  `db:"update_time"`
	DeleteTime  *time.Time `db:"delete_time"`
}

type dbIdentity struct {
	PasswordHash string `db:"password_hash"`
}

func (s *DBStore) CheckPassword(ctx context.Context, req CheckPasswordRequest) (bool, error) {
	accountSegments := strings.Split(req.Account, "/")
	accountID := accountSegments[1]

	userSegments := strings.Split(req.User, "/")
	userSlug := userSegments[1]

	var identity dbIdentity
	if err := s.DB.GetContext(ctx, &identity, `
		SELECT
			identities.password_hash
		FROM
			identities, users
		WHERE
			identities.user_id = users.id AND identities.auth_method = 'password' AND
			users.account_id = $1 AND users.slug = $2
	`, accountID, userSlug); err != nil {
		return false, err
	}

	hashedPassword := []byte(identity.PasswordHash)
	attempt := []byte(req.Password)
	return bcrypt.CompareHashAndPassword(hashedPassword, attempt) == nil, nil
}

func (s *DBStore) CreateAccount(ctx context.Context, req CreateAccountRequest) (models.Account, error) {
	accountId := uuid.NewV4()
	now := time.Now()

	if _, err := s.DB.ExecContext(ctx, `
		INSERT INTO accounts
			(id, create_time, update_time, delete_time, display_name)
		VALUES
			($1, $2, $3, NULL, $4);
	`, accountId, now, now, req.Account.DisplayName); err != nil {
		return models.Account{}, err
	}

	user, err := s.CreateUser(ctx, CreateUserRequest{
		AccountID: accountId.String(),
		User:      req.Root,
	})

	if err != nil {
		return models.Account{}, err
	}

	_, err = s.CreateIdentity(ctx, CreateIdentityRequest{
		AccountID: accountId.String(),
		Parent:    user.Name,
		Identity: models.Identity{
			AuthMethod: models.AuthMethodPassword,
			Password:   req.RootPassword,
		},
	})

	if err != nil {
		return models.Account{}, err
	}

	return models.Account{
		Name:       fmt.Sprintf("accounts/%s", accountId),
		CreateTime: now,
		UpdateTime: now,
		DeleteTime: nil,
		Root:       user.Name,
	}, nil
}

func (s *DBStore) GetUser(ctx context.Context, req GetUserRequest) (models.User, error) {
	segments := strings.Split(req.Name, "/")
	slug := segments[1]

	var user dbUser
	if err := s.DB.GetContext(ctx, &user, `
		SELECT
			id, account_id, create_time, update_time, delete_time, slug, display_name, is_root
		FROM
			users
		WHERE
			account_id = $1 AND slug = $2
	`, req.AccountID, slug); err != nil {
		return models.User{}, err
	}

	return models.User{
		Name:        fmt.Sprintf("users/%s", user.Slug),
		CreateTime:  user.CreateTime,
		UpdateTime:  user.UpdateTime,
		DeleteTime:  user.DeleteTime,
		DisplayName: user.DisplayName,
		IsRoot:      user.IsRoot,
	}, nil
}

func (s *DBStore) CreateUser(ctx context.Context, req CreateUserRequest) (models.User, error) {
	id := uuid.NewV4()
	now := time.Now()

	segments := strings.Split(req.User.Name, "/")
	slug := segments[1]

	if _, err := s.DB.ExecContext(ctx, `
		INSERT INTO users
			(id, account_id, create_time, update_time, delete_time, slug, display_name, is_root)
		VALUES
			($1, $2, $3, $3, NULL, $4, $5, $6)
	`, id, req.AccountID, now, slug, req.User.DisplayName, req.User.IsRoot); err != nil {
		return models.User{}, err
	}

	return models.User{
		Name:        req.User.Name,
		IsRoot:      req.User.IsRoot,
		DisplayName: req.User.DisplayName,
		CreateTime:  req.User.CreateTime,
		UpdateTime:  req.User.UpdateTime,
		DeleteTime:  req.User.DeleteTime,
	}, nil
}

func (s *DBStore) CreateIdentity(ctx context.Context, req CreateIdentityRequest) (models.Identity, error) {
	id := uuid.NewV4()
	now := time.Now()

	segments := strings.Split(req.Parent, "/")
	slug := segments[1]

	authMethod := "password"
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Identity.Password), bcrypt.DefaultCost)
	if err != nil {
		return models.Identity{}, err
	}

	if _, err := s.DB.ExecContext(ctx, `
		INSERT INTO identities
			(id, user_id, create_time, update_time, delete_time, auth_method, password_hash)
		VALUES
			($1, (SELECT id FROM users WHERE account_id = $2 AND slug = $3), $4, $4, NULL, $5, $6);
	`, id, req.AccountID, slug, now, authMethod, passwordHash); err != nil {
		return models.Identity{}, err
	}

	return models.Identity{
		Name:       fmt.Sprintf("%s/identities/%s", req.Parent, id),
		CreateTime: now,
		UpdateTime: now,
		DeleteTime: nil,
		AuthMethod: models.AuthMethodPassword,
	}, nil
}
