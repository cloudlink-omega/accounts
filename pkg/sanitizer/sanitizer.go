package sanitizer

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/mrz1836/go-sanitize"
)

func Sanitized(c *fiber.Ctx, s string) string {
	return sanitize.URL(strings.ReplaceAll(strings.ReplaceAll(s, "../", ""), "./", ""))
}
