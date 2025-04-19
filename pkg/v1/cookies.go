package v1

import (
	"time"

	"github.com/cloudlink-omega/accounts/pkg/domain"
	"github.com/cloudlink-omega/accounts/pkg/structs"
	"github.com/cloudlink-omega/storage/pkg/types"
	"github.com/gofiber/fiber/v2"
)

func (v *API) SetCookie(user *types.User, session_id string, expiration time.Time, c *fiber.Ctx) {
	token := v.Auth.Create(&structs.Claims{
		ClaimType:        0,
		SessionID:        session_id,
		Email:            user.Email,
		Username:         user.Username,
		ULID:             user.ID,
		IdentityProvider: "local",
	}, expiration)
	c.Cookie(&fiber.Cookie{
		Name:     "clomega-authorization",
		Value:    token,
		Path:     "/",
		Expires:  expiration,
		Secure:   v.EnforceHTTPS,
		Domain:   domain.GetDomain(c.Hostname()),
		SameSite: fiber.CookieSameSiteNoneMode,
	})
}

func (v *API) ClearCookie(c *fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     "clomega-authorization",
		Path:     "/",
		Expires:  time.Now().Add(-1 * time.Hour),
		Secure:   true,
		Domain:   domain.GetDomain(c.Hostname()),
		SameSite: fiber.CookieSameSiteNoneMode,
	})
}

func (v *API) SetRecoveryCookie(user *types.User, expiration time.Time, c *fiber.Ctx) {
	token := v.Auth.Create(&structs.Claims{
		ClaimType:        1,
		Email:            user.Email,
		Username:         user.Username,
		ULID:             user.ID,
		IdentityProvider: "local",
	}, expiration)
	c.Cookie(&fiber.Cookie{
		Name:     "clomega-recovery",
		Value:    token,
		Path:     "/",
		Expires:  expiration,
		Secure:   v.EnforceHTTPS,
		Domain:   domain.GetDomain(c.Hostname()),
		SameSite: fiber.CookieSameSiteNoneMode,
	})
}

func (v *API) ClearRecoveryCookie(c *fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     "clomega-recovery",
		Path:     "/",
		Expires:  time.Now().Add(-1 * time.Hour),
		Secure:   true,
		Domain:   domain.GetDomain(c.Hostname()),
		SameSite: fiber.CookieSameSiteNoneMode,
	})
}
