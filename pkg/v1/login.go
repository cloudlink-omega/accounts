package v1

import (
	"fmt"
	"strconv"
	"time"

	"github.com/cloudlink-omega/accounts/pkg/constants"
	scrypt "github.com/elithrar/simple-scrypt"
	"github.com/gofiber/fiber/v2"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func (v *API) LoginEndpoint(c *fiber.Ctx) error {

	// Check if the user  is already logged in. If so, tell them
	if v.Auth.ValidFromNormal(c) {
		return APIResult(c, fiber.StatusBadRequest, "Already logged in!", nil)
	}

	// Try to read the contents, accept JSON or form data
	var creds Credentials
	creds.Email = c.FormValue("email")
	creds.Password = c.FormValue("password")
	creds.TOTP = c.FormValue("totp")
	creds.BackupCode = c.FormValue("backup_code")

	// Require email field
	if creds.Email == "" {
		return APIResult(c, fiber.StatusBadRequest, "Missing email.", nil)
	}

	// Check if the account exists.
	user, err := v.DB.GetUserByEmail(creds.Email)
	if err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	if user == nil {
		return APIResult(c, fiber.StatusUnauthorized, "Account not found.", nil)
	}

	// Read account flags to see if the user only has OAuth
	if user.State.Read(constants.USER_IS_OAUTH_ONLY) {
		return APIResult(c, fiber.StatusBadRequest, "Please use OAuth to log in.", nil)
	}

	// Require password field
	if creds.Password == "" {
		return APIResult(c, fiber.StatusBadRequest, "Missing password.", nil)
	}

	// Check if the password has six numbers at the end (legacy client compatibility). If so, read it as TOTP and trim it from the password.
	if totp, err := strconv.Atoi(creds.Password[len(creds.Password)-6:]); err == nil {
		creds.TOTP = fmt.Sprintf("%06d", totp)
		creds.Password = creds.Password[:len(creds.Password)-6]
	}

	// Verify password
	if scrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)) != nil {
		return APIResult(c, fiber.StatusUnauthorized, "Invalid password.", nil)
	}

	// Check if TOTP is required
	if user.State.Read(constants.USER_IS_TOTP_ENABLED) {
		if creds.TOTP == "" && creds.BackupCode == "" {
			return APIResult(c, fiber.StatusBadRequest, "TOTP required!", nil)

		} else if creds.TOTP != "" {

			// Get secret
			secret := v.DB.GetTotpSecret(user.ID)

			// Verify the TOTP
			success, err := totp.ValidateCustom(
				creds.TOTP,
				secret,
				time.Now().UTC(),
				totp.ValidateOpts{
					Digits:    otp.DigitsSix,
					Period:    30,
					Skew:      1,
					Algorithm: otp.AlgorithmSHA512,
				})
			if err != nil {
				return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
			}

			if !success {
				return APIResult(c, fiber.StatusUnauthorized, "Invalid TOTP!", nil)
			}

		} else {

			// Verify the backup code

			// Get backup codes
			backupCodes, err := v.DB.GetRecoveryCodes(user.ID)
			if err != nil {
				return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
			}

			// Check if there is a match in the backup codes
			var match bool
			match = false
			for i, code := range backupCodes {
				if code == creds.BackupCode {
					match = true
					backupCodes[i] = backupCodes[len(backupCodes)-1]
					break
				}
			}

			if !match {
				return APIResult(c, fiber.StatusUnauthorized, "Invalid backup code!", nil)
			}

			// Update the backup codes
			if err := v.DB.StoreRecoveryCodes(user.ID, backupCodes); err != nil {
				return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
			}
		}
	}

	// Create a new JWT for this user. Session expires in 24 hours.
	v.SetCookie(user, time.Now().Add(24*time.Hour), c)
	return APIResult(c, fiber.StatusOK, "OK", nil)
}
