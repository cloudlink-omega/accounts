# CloudLink Omega / CL5 Accounts Backend

Provides account registration & authentication endpoints for CL5.

# Requirements
* Go 1.23.2 or newer
* A SQL driver and database.

# Usage
The accounts server is a standard Fiber v2 app, and can be natively mounted.
```go
package main

import (
    "database/sql"
    "github.com/gofiber/fiber/v2"
    "github.com/cloudlink-omega/accounts"
    "github.com/huandu/go-sqlbuilder"
    _ "github.com/ncruces/go-sqlite3/driver"
    _ "github.com/ncruces/go-sqlite3/embed"
)

func main() {

    // Initialize your database (SQLite as an example)
	db, err := sql.Open("sqlite3", "file:database.db")
	if err != nil {
		panic(err)
	}

    // . . .

    // Initialize a new Fiber app
    app := fiber.New()

    // . . . 

    // Initialize the Accounts service
    auth := accounts.New(
        "/",                     // router_path: The path that the server app will be mounted to. By default, leave this set to `/`.
        "http://localhost:3000", // server_url: The full hostname or URL that the server will be deployed to.
        "localhost",             // api_domain: The domain (or subdomain) that authorized cookies are permitted on.
        "localhost:3000",        // api_url: The interface that the Account server will listen to.
        "USA-OMEGA-1",           // server_name: Used for labeling the server. Recommended format: [Country Code]-[Server Nickname]-[Designation].
        "localhost:3000",        // primary_website: For use with pointing to any higher-level routers that may be mounted beyond the accounts server.
        "SERVER_SECRET",           // server_secret: Used for encrypting and decrypting JWT cookies, as well as encrypting/decrypting user secrets. For example, use `openssl rand 60 | base64`.
        false,                   // enforce_https: Set to true if you are serving over HTTPS. This sets the "HTTPSOnly" value for cookies.
        db,                      // db: Use a database/sql compatible driver and insert an instance here. In this example, I am using SQLite.
		sqlbuilder.SQLite,       // db_flavor: See huandu/go-sqlbuilder flavors for your specific DB / driver.
		&types.MailConfig{       // email_config: Required for sending emails.
			Port:     587,
			Server:   "smtp.gmail.com",
			Username: "invalid@gmail.com",
			Password: " . . . ",
		},
    )

    // You can then configure OAuth providers. The currently supported ones are Google, Discord, and GitHub.

    /* Create a new Cloud App at https://console.cloud.google.com/projectcreate 
    * then go to the "APIs & Services" section. Select the "Credentials" category
    * and select "Create Credentials" > "OAuth client ID". Select "Web application"
    * as the Application type, and specify the Redirect URL under the "Authorized
    * redirect URLs" section ({server_url}/auth/google/callback). */
    auth.OAuth.Google("GOOGLE_KEY", "GOOGLE_SECRET")

    /* https://github.com/settings/developers > New OAuth App
    * Once you've created the application, you will need to specify
    * the Redirect URL under the "Authorization callback URL" section
    * ({server_url}/auth/github/callback). */
    auth.OAuth.GitHub("GITHUB_KEY", "GITHUB_SECRET")

    /* https://discord.com/developers/applications > New Application
    * then, once you've created the application, go to the "OAuth2" section in
    * the app's settings and generate a client secret, as well as specify
    * the Redirect URL ({server_url}/auth/discord/callback). */
    auth.OAuth.Discord("DISCORD_KEY", "DISCORD_SECRET")

    // . . . 

    // Mount the application
    app.Mount("/accounts", auth.App)

    // Serve assets that the account server depends on
    app.Static("/assets", "./assets")

    // . . . 

    // Run the app
    app.Listen("localhost:3000")
}
```
