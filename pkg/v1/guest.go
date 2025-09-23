package v1

import (
	"time"

	"github.com/cloudlink-omega/storage/pkg/common"
	"github.com/cloudlink-omega/storage/pkg/types"
	"github.com/gofiber/fiber/v2"
)

func (v *API) GuestLoginEndpoint(c *fiber.Ctx) error {

	// Try to read the contents, accept JSON or form data
	var args GuestArgs
	if err := c.BodyParser(&args); err != nil {
		return APIResult(c, fiber.StatusBadRequest, err.Error(), nil)
	}

	// Check if the user is already logged in. If so, tell them
	if v.Auth.ValidFromNormal(c) {
		return APIResult(c, fiber.StatusBadRequest, "Already logged in!", nil)
	}

	// Create the guest
	guest, err := v.DB.CreateGuestAccount(args.Username)
	if err != nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.SystemEvent{
			EventID:    "guest_create_error",
			Details:    err.Error(),
			Successful: false,
		})

		return APIResult(c, fiber.StatusInternalServerError, err.Error(), nil, event_id)
	}

	if guest == nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.SystemEvent{
			EventID:    "guest_create_error",
			Details:    "(*database.Database).CreateGuestAccount returned nil",
			Successful: false,
		})

		return APIResult(c, fiber.StatusInternalServerError, "Failed to generate a guest token.", nil, event_id)
	}

	// Create a new session
	if err := v.CreateGuestSession(c, guest, time.Now().Add(time.Hour)); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}

	// Log the event
	common.LogEvent(v.DB.DB, &types.SystemEvent{
		EventID:    "guest_created",
		Details:    "Guest session " + guest.ID + " created (legacy API)",
		Successful: true,
	})

	return APIResult(c, fiber.StatusOK, "OK", nil)
}
