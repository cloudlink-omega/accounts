package database

import "github.com/huandu/go-sqlbuilder"

func (d *Database) StoreTotpSecret(user string, secret string) error {
	builder := sqlbuilder.NewInsertBuilder().InsertInto("users_totp").Values(user, secret)
	_, err := d.run_insert(builder)
	if err != nil {
		return err
	}
	return nil
}

func (d *Database) GetTotpSecret(user string) (string, error) {
	builder := sqlbuilder.NewSelectBuilder().Select("secret").From("users_totp")
	builder.Where(builder.Equal("user_id", user))
	res, err := d.run_select(builder)
	if err != nil {
		return "", err
	}
	defer res.Close()
	if res.Next() {
		var secret string
		if err := res.Scan(&secret); err != nil {
			return "", err
		}
		return secret, nil
	}
	return "", nil
}
