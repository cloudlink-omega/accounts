package email

import (
	"crypto/tls"

	"github.com/cloudlink-omega/accounts/pkg/structs"

	gomail "gopkg.in/mail.v2"
)

func SendPlainEmail(config *structs.MailConfig, args *structs.EmailArgs, data string) error {

	// Create new message
	m := gomail.NewMessage()

	// Format headers
	m.SetHeader("From", m.FormatAddress(config.Username, "CloudLink Omega"))
	m.SetHeader("To", args.To)
	m.SetHeader("Subject", args.Subject)

	// Use plaintext
	m.SetBody("text/plain", data)

	// Prepare message for SMTP transmission
	d := gomail.NewDialer(
		config.Server,
		config.Port,
		config.Username,
		config.Password,
	)

	// This is only needed when SSL/TLS certificate is not valid on server.
	// In production this should be set to false.
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	// Send E-Mail
	if err := d.DialAndSend(m); err != nil {
		return err
	}

	return nil
}
