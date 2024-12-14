package pages

import (
	"git.mikedev101.cc/MikeDEV/accounts/pkg/authorization"
	"git.mikedev101.cc/MikeDEV/accounts/pkg/database"
	"github.com/gofiber/fiber/v2"
)

type Pages struct {
	RouterPath     string
	ServerURL      string
	APIURL         string
	ServerName     string
	PrimaryWebsite string
	Routes         func(fiber.Router)
	ErrorHandler   func(c *fiber.Ctx, err error) error
	Auth           *authorization.Auth
	DB             *database.Database
}

func New(router_path string, server_url string, api_url string, server_name string, primary_website string, session_key string, db *database.Database) *Pages {

	// Create new instance
	p := &Pages{
		RouterPath:     router_path,
		ServerURL:      server_url,
		APIURL:         api_url,
		ServerName:     server_name,
		PrimaryWebsite: primary_website,
		Auth:           authorization.New(server_url, session_key, db),
		DB:             db,
	}

	// Configure routes
	p.Routes = func(router fiber.Router) {
		router.Get("/register", p.Register)
		router.Get("/login", p.Login)
		router.Get("/", p.Index)
	}

	// Return created instance
	return p
}