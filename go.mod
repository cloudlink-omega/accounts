module github.com/cloudlink-omega/accounts

go 1.24.1

replace github.com/cloudlink-omega/storage => ..\storage

require (
	github.com/cloudlink-omega/storage v0.0.0-00010101000000-000000000000
	github.com/elithrar/simple-scrypt v1.3.0
	github.com/goccy/go-json v0.10.5
	github.com/gofiber/fiber/v2 v2.52.6
	github.com/gofiber/template/html/v2 v2.1.3
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/mrz1836/go-sanitize v1.3.5
	github.com/oklog/ulid/v2 v2.1.0
	github.com/pquerna/otp v1.4.0
	golang.org/x/crypto v0.37.0
	golang.org/x/oauth2 v0.29.0
	gopkg.in/mail.v2 v2.3.1
	gorm.io/gorm v1.25.12
)

require (
	cloud.google.com/go/compute/metadata v0.6.0 // indirect
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/boombuler/barcode v1.0.2 // indirect
	github.com/gofiber/template v1.8.3 // indirect
	github.com/gofiber/utils v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/philhofer/fwd v1.1.3-0.20240916144458-20a13a1f6b7c // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/tinylib/msgp v1.2.5 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.60.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
)
