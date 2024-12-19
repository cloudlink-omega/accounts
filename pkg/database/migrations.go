package database

import (
	"github.com/huandu/go-sqlbuilder"
)

func (d *Database) run_migrations() {
	d.run_build(sqlbuilder.NewCreateTableBuilder().
		CreateTable("users").
		IfNotExists().
		Define(
			"id", "CHAR(26) UNIQUE NOT NULL",
		).
		Define(
			"username", "VARCHAR(30)",
		).
		Define(
			"password", "VARCHAR(255)",
		).
		Define(
			"email", "VARCHAR(255)",
		).
		Define(
			"state", "TINYINT NOT NULL DEFAULT 0",
		).
		Define(
			"PRIMARY KEY(id)",
		))

	d.run_build(sqlbuilder.NewCreateTableBuilder().
		CreateTable("users_google").
		IfNotExists().
		Define(
			"user_id", "CHAR(26) UNIQUE NOT NULL",
		).
		Define(
			"id", "VARCHAR(255) UNIQUE NOT NULL",
		).
		Define(
			"FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE",
		).
		Define(
			"PRIMARY KEY(id)",
		))

	d.run_build(sqlbuilder.NewCreateTableBuilder().
		CreateTable("users_discord").
		IfNotExists().
		Define(
			"user_id", "CHAR(26) UNIQUE NOT NULL",
		).
		Define(
			"id", "VARCHAR(255) UNIQUE NOT NULL",
		).
		Define(
			"FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE",
		).
		Define(
			"PRIMARY KEY(id)",
		))

	d.run_build(sqlbuilder.NewCreateTableBuilder().
		CreateTable("users_github").
		IfNotExists().
		Define(
			"user_id", "CHAR(26) UNIQUE NOT NULL",
		).
		Define(
			"id", "VARCHAR(255) UNIQUE NOT NULL",
		).
		Define(
			"FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE",
		).
		Define(
			"PRIMARY KEY(id)",
		))

	d.run_build(sqlbuilder.NewCreateTableBuilder().
		CreateTable("users_totp").
		IfNotExists().
		Define(
			"user_id", "CHAR(26) UNIQUE NOT NULL",
		).
		Define(
			"secret", "VARCHAR(255) NOT NULL",
		).
		Define(
			"FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE",
		))

	d.run_build(sqlbuilder.NewCreateTableBuilder().
		CreateTable("verification_codes").
		IfNotExists().
		Define(
			"user_id", "CHAR(26) UNIQUE NOT NULL",
		).
		Define(
			"code", "CHAR(6) NOT NULL",
		).
		Define(
			"FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE",
		))
}
