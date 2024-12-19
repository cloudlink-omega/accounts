package database

import "github.com/huandu/go-sqlbuilder"

func (d *Database) AddVerificationCode(user string, code string) error {
	builder := sqlbuilder.NewInsertBuilder().InsertInto("verification_codes").Values(user, code)
	_, err := d.run_insert(builder)
	if err != nil {
		return err
	}
	return nil
}

func (d *Database) VerifyCode(user string, code string) (bool, error) {
	builder := sqlbuilder.NewSelectBuilder().Select("1").From("verification_codes")
	builder.Where(builder.Equal("user_id", user), builder.Equal("code", code))
	res, err := d.run_select(builder)
	if err != nil {
		return false, err
	}
	defer res.Close()
	return res.Next(), nil
}

func (d *Database) DeleteVerificationCode(user string, code string) error {
	builder := sqlbuilder.NewDeleteBuilder().DeleteFrom("verification_codes")
	builder.Where(builder.Equal("user_id", user), builder.Equal("code", code))
	_, err := d.run_delete(builder)
	if err != nil {
		return err
	}
	return nil
}
