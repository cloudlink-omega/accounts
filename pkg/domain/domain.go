package domain

import (
	"regexp"
)

func GetDomain(origin string) string {
	return remove_port(remove_protocol(origin))
}

func remove_port(origin string) string {
	re := regexp.MustCompile(`([^:/]+)`) // Remove port (*:*)
	matches := re.FindStringSubmatch(origin)
	if len(matches) == 2 {
		return matches[1] // Extracted hostname
	}
	return origin // Return as-is if no match
}

func remove_protocol(origin string) string {
	re := regexp.MustCompile(`^[a-zA-Z]+://`) // Remove protocol (*://)
	matches := re.FindStringSubmatch(origin)
	if len(matches) == 2 {
		return matches[1] // Extracted hostname
	}
	return origin // Return as-is if no match
}
