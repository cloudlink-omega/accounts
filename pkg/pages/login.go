package pages

import (
	"github.com/cloudlink-omega/accounts/pkg/sanitizer"
	"github.com/gofiber/fiber/v2"
)

func (p *Pages) Login(c *fiber.Ctx) error {
	if !p.Auth.ValidFromNormal(c) {
		data := map[string]any{
			"BaseURL":        p.RouterPath,
			"ServerName":     p.ServerName,
			"PrimaryWebsite": p.PrimaryWebsite,
			"Redirect":       sanitizer.Sanitized(c, c.Query("redirect")),
		}
		c.Context().SetContentType("text/html; charset=utf-8")
		return c.Render("views/login", data, "views/layout")
	}
	return c.Redirect(p.RouterPath)
}
