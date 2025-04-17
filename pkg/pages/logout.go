package pages

import (
	"github.com/cloudlink-omega/accounts/pkg/sanitizer"
	"github.com/gofiber/fiber/v2"
)

func (p *Pages) Logout(c *fiber.Ctx) error {
	data := map[string]any{
		"BaseURL":        p.RouterPath,
		"ServerName":     p.ServerName,
		"PrimaryWebsite": p.PrimaryWebsite,
		"Redirect":       sanitizer.Sanitized(c, c.Query("redirect")),
		"Profile":        "/assets/static/img/placeholder.png",
	}
	c.Context().SetContentType("text/html; charset=utf-8")
	return c.Render("views/logout", data, "views/layout")
}
