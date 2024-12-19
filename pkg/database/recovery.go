package database

import "github.com/huandu/go-sqlbuilder"

func (d *Database) StoreRecoveryCodes(user string, codes []string) error {
	builder := sqlbuilder.NewInsertBuilder().InsertInto("recovery_codes").Cols("user_id", "code")
	for _, code := range codes {
		builder.Values(user, code)
	}
	_, err := d.run_insert(builder)
	if err != nil {
		return err
	}
	return nil
}
