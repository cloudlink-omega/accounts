package v0

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"math/rand"
	"time"

	"github.com/cloudlink-omega/accounts/pkg/constants"
	"github.com/gofiber/fiber/v2"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	scrypt "github.com/elithrar/simple-scrypt"

	"github.com/goccy/go-json"
)

func (v *APIv0) EnrollTotpEndpoint(c *fiber.Ctx) error {

	// Get authorization
	claims := v.Auth.GetClaims(c)
	if claims == nil {
		c.SendStatus(fiber.StatusUnauthorized)
		return c.SendString("not logged in")
	}

	// Create a new TOTP
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      v.ServerNickname,
		AccountName: claims.Username,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA512,
		Period:      30,
	})
	if err != nil {
		panic(err)
	}

	// Store the secret
	v.DB.StoreTotpSecret(claims.ULID, key.Secret())

	// Generate the QR code
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		panic(err)
	}
	if err := png.Encode(&buf, img); err != nil {
		panic(err)
	}

	// Serve the QR code as a data URI
	dataURI := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())

	// Return the QR code and the key as JSON
	return c.JSON(fiber.Map{"qr": dataURI, "key": key.Secret()})
}

func (v *APIv0) VerifyTotpEndpoint(c *fiber.Ctx) error {

	// Get authorization
	claims := v.Auth.GetClaims(c)
	if claims == nil {
		c.SendStatus(fiber.StatusUnauthorized)
		return c.SendString("not logged in")
	}

	// Require the token
	if c.Query("code") == "" {
		c.SendStatus(fiber.ErrBadRequest.Code)
		return c.SendString("missing code parameter")
	}

	// Require token to be less than 6 characters
	if len(c.Query("code")) > 6 {
		c.SendStatus(fiber.ErrBadRequest.Code)
		return c.SendString("code too long")
	}

	// Read the secret from the database
	secret := v.DB.GetTotpSecret(claims.ULID)

	// Verify the TOTP
	success, err := totp.ValidateCustom(
		c.Query("code"),
		secret,
		time.Now().UTC(),
		totp.ValidateOpts{
			Digits:    otp.DigitsSix,
			Period:    30,
			Skew:      1,
			Algorithm: otp.AlgorithmSHA512,
		})
	if err != nil {
		panic(err)
	}
	if !success {
		c.SendStatus(fiber.StatusBadRequest)
		return c.SendString("invalid code")
	}

	// Read the user's state
	user := v.DB.GetUser(claims.ULID)
	if user == nil {
		panic("no user found")
	}

	// Set the user flags necessary to enable TOTP
	user.State.Set(constants.USER_IS_TOTP_ENABLED)
	if err := v.DB.UpdateUserState(claims.ULID, user.State); err != nil {
		panic(err)
	}

	// Generate ten randomly generated 10-digit codes used for recovery. TODO: make this generate random words instead
	var recovery_codes []string
	for i := 0; i < 10; i++ {
		recovery_codes = append(recovery_codes, fmt.Sprintf("%10d", rand.Intn(10000000000)))
	}

	// Hash the recovery codes with scrypt
	var hashed_codes []string
	for _, i := range recovery_codes {
		hash, err := scrypt.GenerateFromPassword([]byte(i), scrypt.DefaultParams)
		if err != nil {
			panic(err)
		}
		hashed_codes = append(hashed_codes, string(hash))
	}

	// Store the hashed recovery codes in the database
	if err := v.DB.StoreRecoveryCodes(claims.ULID, hashed_codes); err != nil {
		panic(err)
	}

	// Return the recovery codes
	output, err := json.Marshal(struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}{
		RecoveryCodes: recovery_codes,
	})
	if err != nil {
		panic(err)
	}
	return c.SendString(string(output))
}
