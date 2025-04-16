package database

func (d *Database) AddVerificationCode(user string, code string) error {
	// TODO
	return nil
}

func (d *Database) VerifyCode(user string, code string) (bool, error) {
	// TODO
	return false, nil
}

func (d *Database) DeleteVerificationCode(user string, code string) error {
	// TODO
	return nil
}
