package sanitizer

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/mrz1836/go-sanitize"
)

func Sanitized(c *fiber.Ctx, s string) string {

	// TODO: check if redirect URL is local or safe

	return sanitize.URL(strings.ReplaceAll(strings.ReplaceAll(s, "../", ""), "./", ""))
}
