package pages

import (
	"github.com/cloudlink-omega/accounts/pkg/constants"
	"github.com/cloudlink-omega/accounts/pkg/sanitizer"
	"github.com/gofiber/fiber/v2"
)

func (p *Pages) Index(c *fiber.Ctx) error {
	c.Context().SetContentType("text/html; charset=utf-8")
	if p.Auth.ValidFromNormal(c) {
		claims := p.Auth.GetNormalClaims(c)
		user, _ := p.DB.GetUser(claims.ULID)
		return c.Render("views/hello", map[string]any{
			"BaseURL":        p.RouterPath,
			"ServerName":     p.ServerName,
			"PrimaryWebsite": p.PrimaryWebsite,
			"OAuthOnly":      user.State.Read(constants.USER_IS_OAUTH_ONLY),
			"Profile":        "/assets/static/img/placeholder.png",
			"User":           user.Username,
			"VerifyRequired": !user.State.Read(constants.USER_IS_EMAIL_REGISTERED),
			"Redirect":       sanitizer.Sanitized(c, c.Query("redirect")),
		}, "views/layout")

	} else {
		return c.Render("views/welcome", map[string]any{
			"BaseURL":          p.RouterPath,
			"ServerName":       p.ServerName,
			"PrimaryWebsite":   p.PrimaryWebsite,
			"ProvidersEnabled": len(p.Providers) > 0,
			"Google":           p.Providers["google"] != nil,
			"GitHub":           p.Providers["github"] != nil,
			"Discord":          p.Providers["discord"] != nil,
			"Redirect":         sanitizer.Sanitized(c, c.Query("redirect")),
		}, "views/layout")
	}
}
