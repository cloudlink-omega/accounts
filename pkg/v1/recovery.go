package v1

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/cloudlink-omega/accounts/pkg/constants"
	"github.com/cloudlink-omega/accounts/pkg/email"
	"github.com/cloudlink-omega/accounts/pkg/structs"
	"github.com/gofiber/fiber/v2"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func (v *API) SendRecoveryEmail(c *fiber.Ctx) error {

	// If email is enabled, send a verification email. Otherwise, automatically assign the user as verified.
	if v.MailConfig.Enabled {
		user, err := v.DB.GetUserByEmail(c.FormValue("email"))
		if err != nil {
			return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
		}

		if user == nil {
			// User not found, but for security reasons we never leak that an account exists or not
			return APIResult(c, fiber.StatusOK, "OK", nil)
		}

		if user.State.Read(constants.USER_IS_OAUTH_ONLY) {
			return APIResult(c, fiber.StatusBadRequest, "Please use your OAuth provider to recover your account.", nil)
		}

		// Generate a random 6-digit verification code
		code := fmt.Sprintf("%06d", rand.Intn(1000000))

		// Store the verification code in the database, with a 15 minute expiration
		if err := v.DB.AddVerificationCode(user.ID, code, time.Now().Add(15*time.Minute)); err != nil {
			return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
		}

		// Send the verification code to the user's email
		email.SendPlainEmail(v.MailConfig, &structs.EmailArgs{
			Subject:  "Recover your account",
			To:       user.Email,
			Nickname: v.ServerNickname,
		}, fmt.Sprintf(`Hello %s, You are receiving this email because you recently requested to recover your CloudLink Omega account on server %s.

			To recover your account, please use the following verification code: %s.

			This code will expire in 15 minutes.

			If you did not create this account, you can safely ignore this email.

			Regards,
			- %s.`, user.Username, v.ServerNickname, code, v.ServerNickname))

		return APIResult(c, fiber.StatusOK, "OK", nil)
	}

	return APIResult(c, fiber.StatusServiceUnavailable, "Recovery services unavailable because email is not enabled.", nil)
}

func (v *API) ConfirmRecoveryEmail(c *fiber.Ctx) error {

	// Read the user ID from the request
	if c.FormValue("code") == "" {
		return APIResult(c, fiber.StatusBadRequest, "Missing verification code.", nil)
	}

	// Ask the database if the verification code is valid
	var err error
	var verified bool

	user, err := v.DB.GetUserByEmail(c.FormValue("email"))
	if err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	verified, err = v.DB.VerifyCode(user.ID, c.FormValue("code"))
	if err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	if !verified {
		return APIResult(c, fiber.StatusBadRequest, "Invalid verification code!", nil)
	}

	// Check if TOTP is required
	if user.State.Read(constants.USER_IS_TOTP_ENABLED) {
		if c.FormValue("totp") == "" && c.FormValue("backup_code") == "" {
			return APIResult(c, fiber.StatusBadRequest, "TOTP required!", nil)

		} else if c.FormValue("totp") != "" {

			// Get secret
			secret := v.DB.GetTotpSecret(user.ID)

			// Verify the TOTP
			success, err := totp.ValidateCustom(
				c.FormValue("totp"),
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
				return APIResult(c, fiber.StatusBadRequest, "Invalid TOTP!", nil)
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
				if code == c.FormValue("backup_code") {
					match = true
					backupCodes[i] = backupCodes[len(backupCodes)-1]
					break
				}
			}

			if !match {
				return APIResult(c, fiber.StatusBadRequest, "Invalid backup code!", nil)
			}

			// Update the backup codes
			if err := v.DB.StoreRecoveryCodes(user.ID, backupCodes); err != nil {
				return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
			}
		}
	}

	// Remove verification codes from the database
	if err := v.DB.DeleteVerificationCodes(user.ID); err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	// Create a new JWT for this user. Recovery-only session expires in 1 hour.
	v.SetRecoveryCookie(user, time.Now().Add(time.Hour), c)

	return APIResult(c, fiber.StatusOK, "OK", nil)
}
