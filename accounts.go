package accounts

import (
	"embed"
	"net/http"

	database "github.com/cloudlink-omega/accounts/pkg/database"
	oauth "github.com/cloudlink-omega/accounts/pkg/oauth"
	pages "github.com/cloudlink-omega/accounts/pkg/pages"
	"github.com/cloudlink-omega/accounts/pkg/structs"
	v1 "github.com/cloudlink-omega/accounts/pkg/v1"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/template/html/v2"
	"gorm.io/gorm"
)

//go:embed assets/*
var embedded_assets embed.FS

//go:embed views/*
var embedded_templates embed.FS

type Accounts struct {
	APIv1 *v1.API
	Page  *pages.Pages
	OAuth *oauth.OAuth
	App   *fiber.App
}

// New creates a new Accounts instance.
//
// Accounts is a collection of API endpoints, pages, and OAuth endpoints that make up the
// Accounts service. It is meant to be mounted to a higher-level router.
//
// The main purpose of New is to provide a simple way to create a new Accounts instance that
// is pre-configured with the most commonly used endpoints and settings.
func New(

	// Router path is the path that the Accounts server will be mounted to.
	router_path string,

	// Server URL is the full hostname or URL that the server will be deployed to.
	server_url string,

	// API Domain is the domain (or subdomain) that authorized cookies are permitted on.
	api_domain string,

	// API URL is the interface that the Account server will listen to.
	api_url string,

	// Server Name is used for labeling the server. Format: [Country Code]-[Server Nickname]-[Designation].
	server_name string,

	// Primary Website is the URL of the primary website. Consider using it to point to a higher-level router.
	primary_website string,

	// Session Key is used for encrypting and decrypting JWT cookies.
	session_key string,

	// Set to "true" to enforce cookies requiring HTTPS.
	enforce_https bool,

	// Database configuration. Passed into GORM.
	db *gorm.DB,

	// Email configuration
	email_config *structs.MailConfig,

) *Accounts {

	// Truncate ending / in router_path if it exists
	if router_path[len(router_path)-1] == '/' {
		router_path = router_path[:len(router_path)-1]
	}

	// Initialize database
	accounts_db := &database.Database{DB: db}
	if err := accounts_db.RunMigrations(); err != nil {
		panic(err)
	}

	// Create new instance
	srv := &Accounts{
		Page:  pages.New(router_path, server_url, api_url, server_name, primary_website, session_key, accounts_db),
		OAuth: oauth.New(router_path, server_url, enforce_https, api_domain, session_key, accounts_db),
		APIv1: v1.New(router_path, enforce_https, api_domain, server_url, session_key, accounts_db, email_config, server_name),
	}

	// Link Pages to OAuth providers
	srv.Page.Providers = srv.OAuth.Providers

	// Initialize template engine
	engine := html.NewFileSystem(http.FS(embedded_templates), ".html")

	// Initialize app
	srv.App = fiber.New(fiber.Config{Views: engine, ErrorHandler: srv.Page.ErrorPage})

	// Configure routes
	srv.App.Route("/oauth", srv.OAuth.Routes)
	srv.App.Route("/api/v1", srv.APIv1.Routes)
	srv.App.Route("/", srv.Page.Routes)

	// Configure static
	srv.App.Use("/assets", filesystem.New(filesystem.Config{
		Root:       http.FS(embedded_assets),
		PathPrefix: "assets",
		Browse:     false,
	}))

	// Configure 404 handler
	srv.App.Use(func(c *fiber.Ctx) error {
		return srv.Page.ErrorPage(c, c.Context().Err())
	})

	// Return created instance
	return srv
}
