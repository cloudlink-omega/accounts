package authorization

import (
	"fmt"
	"time"

	"github.com/cloudlink-omega/accounts/pkg/database"
	"github.com/cloudlink-omega/accounts/pkg/structs"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

type Context fiber.Ctx

type Auth struct {
	ServerURL  string
	SessionKey string
	DB         *database.Database
}

func New(url string, sessionkey string, db *database.Database) *Auth {
	return &Auth{
		ServerURL:  url,
		SessionKey: sessionkey,
		DB:         db,
	}
}

func (s *Auth) GetNormalClaims(c *fiber.Ctx) *structs.Claims {
	cookie := c.Cookies("clomega-authorization")
	if cookie == "" {
		return nil
	}
	return s.GetClaimsFromToken(cookie)
}

func (s *Auth) GetRecoveryClaims(c *fiber.Ctx) *structs.Claims {
	cookie := c.Cookies("clomega-recovery")
	if cookie == "" {
		return nil
	}
	return s.GetClaimsFromToken(cookie)
}

func (s *Auth) GetClaimsFromToken(token string) *structs.Claims {
	claims := &structs.Claims{}
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return []byte(s.SessionKey), nil
	})
	if err != nil {
		panic(err)
	}
	if !tkn.Valid {
		panic(fiber.ErrUnauthorized)
	}
	return claims
}

func (s *Auth) GetState(state_data string) (*structs.State, error) {
	state := &structs.State{}
	tkn, err := jwt.ParseWithClaims(state_data, state, func(token *jwt.Token) (any, error) {
		return []byte(s.SessionKey), nil
	})
	if err != nil {
		return nil, err
	}
	if !tkn.Valid {
		return nil, fmt.Errorf("invalid state jwt")
	}
	return state, nil
}

func (s *Auth) ValidFromNormal(c *fiber.Ctx) bool {
	cookie := c.Cookies("clomega-authorization")
	if cookie == "" {
		return false
	}
	return s.ValidFromToken(cookie)
}

func (s *Auth) ValidFromRecovery(c *fiber.Ctx) bool {
	cookie := c.Cookies("clomega-recovery")
	if cookie == "" {
		return false
	}
	return s.ValidFromToken(cookie)
}

func (s *Auth) ValidFromToken(token string) bool {
	tkn, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		return []byte(s.SessionKey), nil
	})
	return err == nil && tkn.Valid
}

func (s *Auth) Create(claims any, expiration time.Time) string {

	var token *jwt.Token
	switch c := claims.(type) {
	case *structs.Claims:
		c.RegisteredClaims = jwt.RegisteredClaims{
			Issuer:    s.ServerURL,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(expiration),
		}
		token = jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	case *structs.State:
		c.RegisteredClaims = jwt.RegisteredClaims{
			Issuer:    s.ServerURL,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(expiration),
		}
		token = jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	default:
		panic("missing implementation for claims type")
	}

	token_string, err := token.SignedString([]byte(s.SessionKey))

	if err != nil {
		panic(fmt.Sprintf("failed to create token: %s", err))
	}

	return token_string
}
