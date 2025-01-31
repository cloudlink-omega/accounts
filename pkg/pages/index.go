package pages

import (
	"github.com/cloudlink-omega/accounts/pkg/sanitizer"
	"github.com/gofiber/fiber/v2"
)

func (p *Pages) Index(c *fiber.Ctx) error {
	c.Context().SetContentType("text/html; charset=utf-8")
	if p.Auth.Valid(c) {
		user := p.Auth.GetClaims(c)
		return c.Render("views/hello", map[string]interface{}{
			"BaseURL":        p.RouterPath,
			"ServerName":     p.ServerName,
			"PrimaryWebsite": p.PrimaryWebsite,
			"Profile":        "/assets/static/img/placeholder.png",
			"User":           user.Username,
			"Redirect":       sanitizer.Sanitized(c, c.Query("redirect")),
		}, "views/layout")

	} else {
		return c.Render("views/welcome", map[string]interface{}{
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
