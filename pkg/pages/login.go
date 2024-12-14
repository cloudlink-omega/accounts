package pages

import (
	"git.mikedev101.cc/MikeDEV/accounts/pkg/sanitizer"
	"github.com/gofiber/fiber/v2"
)

func (p *Pages) Login(c *fiber.Ctx) error {
	data := map[string]interface{}{
		"BaseURL":        p.RouterPath,
		"ServerName":     p.ServerName,
		"PrimaryWebsite": p.PrimaryWebsite,
		"Redirect":       sanitizer.Sanitized(c, c.Query("redirect")),
	}
	c.Context().SetContentType("text/html; charset=utf-8")
	return c.Render("views/login", data, "views/layout")
}
