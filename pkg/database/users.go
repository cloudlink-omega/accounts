package database

import (
	"fmt"
	"log"

	"github.com/cloudlink-omega/accounts/pkg/types"
	"github.com/huandu/go-sqlbuilder"
)

func (d *Database) GetUsers() []*types.User {
	builder := sqlbuilder.NewSelectBuilder().Select("id", "username", "password", "email", "state").From("users")
	res, err := d.run_select(builder)
	if err != nil {
		panic(err)
	}

	var out []*types.User

	defer res.Close()
	for res.Next() {
		user := &types.User{}
		if err := res.Scan(&user.ID, &user.Username, &user.Password, &user.Email, &user.State); err != nil {
			panic(err)
		}
		out = append(out, user)
	}

	for _, user := range out {
		log.Print(user.String())
	}

	return out
}

func (d *Database) GetUser(id string) *types.User {
	builder := sqlbuilder.NewSelectBuilder().Select("id", "username", "password", "email", "state").From("users").Where("id = ?", id)
	res, err := d.run_select(builder)
	if err != nil {
		panic(err)
	}
	if !res.Next() {
		return nil
	}
	user := &types.User{}
	defer res.Close()
	if err := res.Scan(&user.ID, &user.Username, &user.Password, &user.Email, &user.State); err != nil {
		panic(err)
	}
	log.Print(user.String())
	return user
}

func (d *Database) GetUserFromProvider(id string, provider string) (*types.User, error) {
	providerTable := fmt.Sprintf("users_%s", provider)
	builder := sqlbuilder.NewSelectBuilder().
		Select("u.id", "u.username", "u.password", "u.email", "u.state").
		From("users AS u", fmt.Sprintf("%s AS p", providerTable))
	builder.Join(providerTable, builder.Equal("u.id", "p.user_id"))
	builder.Where(builder.Equal("p.id", id))
	res, err := d.run_select(builder)
	if err != nil {
		return nil, err
	} else if !res.Next() {
		return nil, fmt.Errorf("user not found")
	} else {
		user := &types.User{}
		defer res.Close()
		if err := res.Scan(&user.ID, &user.Username, &user.Password, &user.Email, &user.State); err != nil {
			panic(err)
		}
		log.Print(user.String())
		return user, nil
	}
}

func (d *Database) CreateUser(user *types.User) error {
	builder := sqlbuilder.NewInsertBuilder().InsertInto("users").Values(user.ID, user.Username, user.Password, user.Email, user.State)
	_, err := d.run_insert(builder)
	if err != nil {
		return err
	}
	return nil
}

func (d *Database) LinkUserToProvider(user string, provider_user string, provider string) error {
	builder := sqlbuilder.NewInsertBuilder().InsertInto(fmt.Sprintf("users_%s", provider)).Values(provider_user, user)
	_, err := d.run_insert(builder)
	if err != nil {
		return err
	}
	return nil
}

func (d *Database) GetUserByEmail(email string) (*types.User, error) {
	builder := sqlbuilder.NewSelectBuilder().Select("id", "username", "password", "email", "state").From("users").Where("email = ?", email)
	res, err := d.run_select(builder)
	if err != nil {
		return nil, err
	} else if !res.Next() {
		return nil, fmt.Errorf("user not found")
	} else {
		user := &types.User{}
		defer res.Close()
		if err := res.Scan(&user.ID, &user.Username, &user.Password, &user.Email, &user.State); err != nil {
			panic(err)
		}
		log.Print(user.String())
		return user, nil
	}
}
