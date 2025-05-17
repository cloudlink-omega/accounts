package v1

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"math/rand"
	"time"

	"github.com/cloudlink-omega/accounts/pkg/constants"
	"github.com/cloudlink-omega/storage/pkg/common"
	"github.com/cloudlink-omega/storage/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type EnrollResponse struct {
	QR  string `json:"qr"`
	Key string `json:"key"`
}

type VerifyResponse struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

func (v *API) EnrollTotpEndpoint(c *fiber.Ctx) error {

	// Get authorization
	claims := v.Auth.GetNormalClaims(c)
	if claims == nil {
		return APIResult(c, fiber.StatusUnauthorized, "Not logged in!", nil)
	}

	// Read the user's data
	user, err := v.DB.GetUser(claims.ULID)
	if err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.SystemEvent{
			EventID:    "get_user_error",
			Details:    err.Error(),
			Successful: false,
		})

		return APIResult(c, fiber.StatusInternalServerError, "Failed to get user.", nil, event_id)
	} else if user == nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.SystemEvent{
			EventID:    "get_user_error",
			Details:    "No match found (anomaly?)",
			Successful: false,
		})

		return APIResult(c, fiber.StatusInternalServerError, "Failed to get user.", nil, event_id)
	}

	// Create a new TOTP
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      v.ServerNickname,
		AccountName: user.Username,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA512,
		Period:      30,
	})
	if err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	// Store the secret. It will be encrypted by the function.
	v.DB.StoreTotpSecret(user, key.Secret())

	// Generate the QR code
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.UserEvent{
			UserID:     user.ID,
			EventID:    "user_totp_enroll_failure",
			Details:    err.Error(),
			Successful: false,
		})

		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil, event_id)
	}
	if err := png.Encode(&buf, img); err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.UserEvent{
			UserID:     user.ID,
			EventID:    "user_totp_enroll_failure",
			Details:    err.Error(),
			Successful: false,
		})

		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil, event_id)
	}

	// Log the event
	common.LogEvent(v.DB.DB, &types.UserEvent{
		UserID:     user.ID,
		EventID:    "user_totp_enroll_started",
		Details:    "",
		Successful: true,
	})

	// Return the QR code and the key as JSON
	return APIResult(c, fiber.StatusOK, "OK", &EnrollResponse{
		QR:  "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()),
		Key: fmt.Sprintf("otpauth://totp/%s:%s?algorithm=SHA512&digits=6&issuer=%s&secret=%s", v.ServerNickname, claims.Username, v.ServerNickname, key.Secret()),
	})
}

func (v *API) VerifyTotpEndpoint(c *fiber.Ctx) error {

	// Get authorization
	claims := v.Auth.GetNormalClaims(c)
	if claims == nil {
		return APIResult(c, fiber.StatusUnauthorized, "Not logged in!", nil)
	}

	// Require the token
	if c.Query("code") == "" {
		return APIResult(c, fiber.StatusBadRequest, "Missing code parameter.", nil)
	}

	// Require token to be less than 6 characters
	if len(c.Query("code")) > 6 {
		return APIResult(c, fiber.StatusBadRequest, "Code too long.", nil)
	}

	// Read the user's data
	user, err := v.DB.GetUser(claims.ULID)
	if err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.SystemEvent{
			EventID:    "get_user_error",
			Details:    err.Error(),
			Successful: false,
		})

		return APIResult(c, fiber.StatusInternalServerError, "Failed to get user.", nil, event_id)

	} else if user == nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.SystemEvent{
			EventID:    "get_user_error",
			Details:    "No match found (anomaly?)",
			Successful: false,
		})

		return APIResult(c, fiber.StatusInternalServerError, "Failed to get user.", nil, event_id)
	}

	// Read the secret from the database. It will be decrypted by the function.
	secret := v.DB.GetTotpSecret(user)

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

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.UserEvent{
			UserID:     user.ID,
			EventID:    "user_totp_enroll_failure",
			Details:    err.Error(),
			Successful: false,
		})

		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil, event_id)
	}
	if !success {
		return APIResult(c, fiber.StatusBadRequest, "Invalid code.", nil)
	}

	// Set the user flags necessary to enable TOTP
	user.State.Set(constants.USER_IS_TOTP_ENABLED)
	if err := v.DB.UpdateUserState(claims.ULID, user.State); err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.UserEvent{
			UserID:     user.ID,
			EventID:    "user_recovery_set_failure",
			Details:    err.Error(),
			Successful: false,
		})

		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil, event_id)
	}

	// Log the event
	common.LogEvent(v.DB.DB, &types.UserEvent{
		UserID:     user.ID,
		EventID:    "user_totp_enroll_success",
		Details:    "",
		Successful: true,
	})

	// Generate ten randomly generated 10-digit codes used for recovery.
	var recovery_codes []string
	for range [10]int{} {
		recovery_codes = append(recovery_codes, fmt.Sprintf("%10d", rand.Intn(10000000000)))
	}

	// Store the recovery codes in the database. They will be encrypted by the function.
	if err := v.DB.StoreRecoveryCodes(user, recovery_codes); err != nil {
		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil)
	}

	// Log the event
	common.LogEvent(v.DB.DB, &types.UserEvent{
		UserID:     user.ID,
		EventID:    "user_recovery_set",
		Details:    "",
		Successful: true,
	})

	// Return the recovery codes
	return APIResult(c, fiber.StatusOK, "OK", &VerifyResponse{
		RecoveryCodes: recovery_codes,
	})
}
