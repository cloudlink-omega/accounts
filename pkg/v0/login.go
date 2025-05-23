package v0

import (
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/cloudlink-omega/accounts/pkg/constants"
	"github.com/cloudlink-omega/storage/pkg/common"
	"github.com/cloudlink-omega/storage/pkg/types"
	scrypt "github.com/elithrar/simple-scrypt"
	"github.com/gofiber/fiber/v2"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func (v *API) LoginEndpoint(c *fiber.Ctx) error {

	// Try to read the contents, accept JSON or form data
	var creds Credentials
	if err := c.BodyParser(&creds); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}

	// Check if the user  is already logged in. If so, tell them
	if v.Auth.ValidFromToken(creds.Token) {
		return c.Status(fiber.StatusCreated).SendString("Already logged in!")
	}

	// Require email field
	if creds.Email == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Missing email.")
	}

	// Check if the account exists.
	user, err := v.DB.GetUserByEmail(creds.Email)
	if err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.SystemEvent{
			EventID:    "get_user_error",
			Details:    err.Error(),
			Successful: false,
		})

		return c.Status(fiber.StatusInternalServerError).SendString(err.Error() + "\nevent_id: " + event_id)
	}

	if user == nil {
		return c.Status(fiber.StatusUnauthorized).SendString("Account not found.")
	}

	// Read account flags to see if the user only has OAuth
	if user.State.Read(constants.USER_IS_OAUTH_ONLY) {
		return c.Status(fiber.StatusBadRequest).SendString("Please use OAuth to log in.")
	}

	// Require password field
	if creds.Password == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Missing password.")
	}

	// Check if the password has six numbers at the end (legacy client compatibility). If so, read it as TOTP and trim it from the password.
	if totp, err := strconv.Atoi(creds.Password[len(creds.Password)-6:]); err == nil {
		creds.TOTP = fmt.Sprintf("%06d", totp)
		creds.Password = creds.Password[:len(creds.Password)-6]
	}

	// Verify password
	if scrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)) != nil {
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid password.")
	}

	// Check if TOTP is required
	if user.State.Read(constants.USER_IS_TOTP_ENABLED) {
		if creds.TOTP == "" && creds.BackupCode == "" {
			return c.Status(fiber.StatusBadRequest).SendString("TOTP required!")

		} else if creds.TOTP != "" {

			// Get secret
			secret := v.DB.GetTotpSecret(user)

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

				// Log the event
				event_id := common.LogEvent(v.DB.DB, &types.SystemEvent{
					EventID:    "totp_error",
					Details:    err.Error(),
					Successful: false,
				})

				return c.Status(fiber.StatusInternalServerError).SendString(err.Error() + "\nevent_id: " + event_id)
			}

			if !success {
				return c.Status(fiber.StatusUnauthorized).SendString("Invalid TOTP!")
			}

		} else {
			// Verify the backup code

			// Get backup codes
			backupCodes, err := v.DB.GetRecoveryCodes(user)
			if err != nil {

				// Log the event
				event_id := common.LogEvent(v.DB.DB, &types.UserEvent{
					UserID:     user.ID,
					EventID:    "recovery_code_retrieval_error",
					Details:    err.Error(),
					Successful: false,
				})

				return c.Status(fiber.StatusInternalServerError).SendString(err.Error() + "\nevent_id: " + event_id)
			}

			// Check if there is a match in the backup codes
			match := slices.Contains(backupCodes, creds.BackupCode)
			if !match {
				return c.Status(fiber.StatusUnauthorized).SendString("Invalid backup code!")
			}

			// Delete the backup code
			backupCodes = slices.Delete(backupCodes, slices.Index(backupCodes, creds.BackupCode), 1)

			// Update the backup codes
			if err := v.DB.StoreRecoveryCodes(user, backupCodes); err != nil {

				// Log the event
				event_id := common.LogEvent(v.DB.DB, &types.UserEvent{
					UserID:     user.ID,
					EventID:    "recovery_code_store_error",
					Details:    err.Error(),
					Successful: false,
				})

				return c.Status(fiber.StatusInternalServerError).SendString(err.Error() + "\nevent_id: " + event_id)
			}
		}
	}

	// Create a new session
	if token, err := v.CreateSessionToken(c, user, time.Now().Add(24*time.Hour)); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	} else {

		// Log the event
		common.LogEvent(v.DB.DB, &types.UserEvent{
			UserID:     user.ID,
			EventID:    "user_login",
			Details:    "Logged in using local provider (legacy API)",
			Successful: true,
		})

		return c.Status(fiber.StatusOK).SendString(token)
	}
}
