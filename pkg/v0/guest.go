package v0

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
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}

	// Check if the user is already logged in. If so, tell them
	if v.Auth.ValidFromToken(args.Token) {
		return c.Status(fiber.StatusCreated).SendString("Already logged in!")
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

		return c.Status(fiber.StatusInternalServerError).SendString(err.Error() + "\nevent_id: " + event_id)
	}

	if guest == nil {

		// Log the event
		event_id := common.LogEvent(v.DB.DB, &types.SystemEvent{
			EventID:    "guest_create_error",
			Details:    "(*database.Database).CreateGuestAccount returned nil",
			Successful: false,
		})

		return c.Status(fiber.StatusInternalServerError).SendString("Failed to generate a guest token. \nevent_id: " + event_id)
	}

	// Create a new session
	if token, err := v.CreateGuestToken(c, guest, time.Now().Add(time.Hour)); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	} else {

		// Log the event
		common.LogEvent(v.DB.DB, &types.SystemEvent{
			EventID:    "guest_created",
			Details:    "Guest session " + guest.ID + " created (legacy API)",
			Successful: true,
		})

		return c.Status(fiber.StatusOK).SendString(token)
	}
}
