package pages

import (
	"github.com/cloudlink-omega/accounts/pkg/sanitizer"
	"github.com/gofiber/fiber/v2"
)

func (p *Pages) RecoveryLanding(c *fiber.Ctx) error {
	data := map[string]any{
		"BaseURL":        p.RouterPath,
		"ServerName":     p.ServerName,
		"PrimaryWebsite": p.PrimaryWebsite,
		"Redirect":       sanitizer.Sanitized(c, c.Query("redirect")),
	}
	c.Context().SetContentType("text/html; charset=utf-8")
	return c.Render("views/recovery", data, "views/layout")
}
