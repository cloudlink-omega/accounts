package pages

import (
	"github.com/cloudlink-omega/accounts/pkg/constants"
	"github.com/cloudlink-omega/accounts/pkg/sanitizer"
	"github.com/cloudlink-omega/accounts/pkg/structs"
	"github.com/cloudlink-omega/storage/pkg/types"
	"github.com/gofiber/fiber/v2"
)

func (p *Pages) Verify(c *fiber.Ctx) error {

	// Check if the user  is already logged in. If so, tell them
	if !p.Auth.ValidFromNormal(c) {
		return p.ErrorPage(c, &fiber.Error{
			Code:    fiber.StatusUnauthorized,
			Message: "Please log in or register.",
		})
	}

	// Attempt to get claims
	var claims *structs.Claims
	var user *types.User
	if p.Auth.ValidFromNormal(c) {
		claims = p.Auth.GetNormalClaims(c)
	} else {
		return p.ErrorPage(c, &fiber.Error{
			Code:    fiber.StatusInternalServerError,
			Message: "Could not obtain session claim data.",
		})
	}

	// Check if the user is using an OAuth provider
	user, err := p.DB.GetUser(claims.ULID)
	if err != nil {
		return p.ErrorPage(c, &fiber.Error{
			Code:    fiber.StatusInternalServerError,
			Message: err.Error(),
		})
	}

	if user.State.Read(constants.USER_IS_EMAIL_REGISTERED) {
		return c.Redirect(p.RouterPath)
	}

	if user.State.Read(constants.USER_IS_OAUTH_ONLY) {
		return p.ErrorPage(c, &fiber.Error{
			Code:    fiber.StatusBadRequest,
			Message: "You are using an OAuth provider for your account. Verifying your email through Omega is not necessary.",
		})
	}

	data := map[string]any{
		"BaseURL":        p.RouterPath,
		"ServerName":     p.ServerName,
		"PrimaryWebsite": p.PrimaryWebsite,
		"Redirect":       sanitizer.Sanitized(c, c.Query("redirect")),
	}
	c.Context().SetContentType("text/html; charset=utf-8")
	return c.Render("views/verify", data, "views/layout")
}
