package v1

import (
	"fmt"
	"math/rand"
	"slices"
	"time"

	"github.com/cloudlink-omega/accounts/pkg/constants"
	"github.com/cloudlink-omega/accounts/pkg/email"
	"github.com/cloudlink-omega/accounts/pkg/structs"
	"github.com/cloudlink-omega/storage/pkg/common"
	"github.com/cloudlink-omega/storage/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type SendArgs struct {
	Email string `json:"email" form:"email"`
}

func (v *API) SendRecoveryEmail(c *fiber.Ctx) error {
	var args SendArgs
	if err := c.BodyParser(&args); err != nil {
		return APIResult(c, fiber.StatusBadRequest, err.Error(), nil)
	}

	// If email is enabled, send a verification email. Otherwise, automatically assign the user as verified.
	if v.MailConfig.Enabled {
		user, err := v.DB.GetUserByEmail(args.Email)
		if err != nil {

			// Log the event
			event_id := common.LogEvent(v.DB.DB, &types.SystemEvent{
				EventID:    "get_user_error",
				Details:    err.Error(),
				Successful: false,
			})

			return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil, event_id)
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

			// Log the event
			event_id := common.LogEvent(v.DB.DB, &types.UserEvent{
				UserID:     user.ID,
				EventID:    "user_password_reset_failure",
				Details:    err.Error(),
				Successful: false,
			})

			return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil, event_id)
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

		// Log the event
		common.LogEvent(v.DB.DB, &types.UserEvent{
			UserID:     user.ID,
			EventID:    "user_password_reset_sent",
			Details:    "",
			Successful: true,
		})

		return APIResult(c, fiber.StatusOK, "OK", nil)
	}

	return APIResult(c, fiber.StatusServiceUnavailable, "Recovery services unavailable because email is not enabled.", nil)
}

type ConfirmArgs struct {
	Email  string `json:"email" form:"email"`
	TOTP   string `json:"totp" form:"totp"`
	Code   string `json:"code" form:"code"`
	Backup string `json:"backup_code" form:"backup_code"`
}

func (v *API) ConfirmRecoveryEmail(c *fiber.Ctx) error {
	var args ConfirmArgs
	if err := c.BodyParser(&args); err != nil {
		return APIResult(c, fiber.StatusBadRequest, err.Error(), nil)
	}

	// Read the user ID from the request
	if args.Code == "" {
		return APIResult(c, fiber.StatusBadRequest, "Missing verification code.", nil)
	}

	// Ask the database if the verification code is valid
	var err error
	var verified bool

	user, err := v.DB.GetUserByEmail(args.Email)
	if err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.SystemEvent{
			EventID:    "get_user_error",
			Details:    err.Error(),
			Successful: false,
		})

		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil, event_id)
	}

	verified, err = v.DB.VerifyCode(user.ID, args.Code)
	if err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.UserEvent{
			UserID:     user.ID,
			EventID:    "user_verify_failure",
			Details:    err.Error(),
			Successful: false,
		})

		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil, event_id)
	}

	if !verified {
		return APIResult(c, fiber.StatusBadRequest, "Invalid verification code!", nil)
	}

	// Check if TOTP is required
	if user.State.Read(constants.USER_IS_TOTP_ENABLED) {
		if args.TOTP == "" && args.Backup == "" {
			return APIResult(c, fiber.StatusBadRequest, "TOTP required!", nil)

		} else if args.TOTP != "" {

			// Get secret
			secret := v.DB.GetTotpSecret(user)

			// Verify the TOTP
			success, err := totp.ValidateCustom(
				args.TOTP,
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

				return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil, event_id)
			}

			if !success {
				return APIResult(c, fiber.StatusBadRequest, "Invalid TOTP!", nil)
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

				return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil, event_id)
			}

			// Check if there is a match in the backup codes
			match := slices.Contains(backupCodes, args.Backup)
			if !match {
				return APIResult(c, fiber.StatusUnauthorized, "Invalid backup code!", nil)
			}

			// Delete the backup code
			backupCodes = slices.Delete(backupCodes, slices.Index(backupCodes, args.Backup), 1)

			// Update the backup codes
			if err := v.DB.StoreRecoveryCodes(user, backupCodes); err != nil {

				// Log the event
				event_id := common.LogEvent(v.DB.DB, &types.UserEvent{
					UserID:     user.ID,
					EventID:    "recovery_code_store_error",
					Details:    err.Error(),
					Successful: false,
				})

				return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil, event_id)
			}
		}
	}

	// Remove verification codes from the database
	if err := v.DB.DeleteVerificationCodes(user.ID); err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	// Create a new JWT for this user. Recovery-only session expires in 1 hour.
	v.SetRecoveryCookie(user, time.Now().Add(time.Hour), c)

	// Log the event
	common.LogEvent(v.DB.DB, &types.UserEvent{
		UserID:     user.ID,
		EventID:    "user_password_reset_verified",
		Details:    "",
		Successful: true,
	})

	return APIResult(c, fiber.StatusOK, "OK", nil)
}
