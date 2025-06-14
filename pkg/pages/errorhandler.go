package pages

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
)

func (p *Pages) ErrorPage(c *fiber.Ctx, err error) error {
	var status_code int
	if err == nil {
		status_code = fiber.StatusInternalServerError
	} else {
		switch e := err.(type) {
		case *fiber.Error:
			status_code = e.Code
		default:
			status_code = fiber.StatusInternalServerError
		}
	}

	// Set the status code for the response
	c.Status(status_code)

	// Either render a page, or send plain text
	request_content_type := string(c.Request().Header.Peek("Content-Type"))

	var match bool
	for _, t := range []string{"html", "plain", "form"} {
		match = !match && strings.Contains(request_content_type, t)
	}

	if err != nil {
		if match {
			return c.SendString(err.Error())
		} else {
			return c.Render("views/error", &map[string]string{
				"Message":    err.Error(),
				"Status":     fmt.Sprint(status_code),
				"ServerName": p.ServerName})
		}
	} else {
		if match {
			return c.SendString("Hm... Something went wrong.")
		} else {
			return c.Render("views/error", &map[string]string{
				"Message":    "Hm... Something went wrong.",
				"Status":     fmt.Sprint(status_code),
				"ServerName": p.ServerName})
		}
	}
}
