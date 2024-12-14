package database

import (
	"database/sql"
	"log"

	"git.mikedev101.cc/MikeDEV/accounts/pkg/types"
	"github.com/huandu/go-sqlbuilder"
)

type Database types.Database

func Initialize(db *sql.DB, flavor sqlbuilder.Flavor) (*Database, error) {
	if err := db.Ping(); err != nil {
		return nil, err
	}
	mydb := &Database{DB: db, Flavor: flavor}
	mydb.run_migrations()
	return mydb, nil
}

func (d *Database) run_build(builder *sqlbuilder.CreateTableBuilder) sql.Result {
	builder.BuildWithFlavor(d.Flavor)
	sql, args := builder.Build()
	log.Printf(sql, args...)
	if res, err := d.DB.Exec(sql, args...); err != nil {
		panic(err)
	} else {
		return res
	}
}

func (d *Database) run_select(builder *sqlbuilder.SelectBuilder) (*sql.Rows, error) {
	builder.BuildWithFlavor(d.Flavor)
	sql, args := builder.Build()
	log.Printf(sql, args...)
	return d.DB.Query(sql, args...)
}

func (d *Database) run_insert(builder *sqlbuilder.InsertBuilder) (sql.Result, error) {
	builder.BuildWithFlavor(d.Flavor)
	sql, args := builder.Build()
	log.Printf(sql, args...)
	return d.DB.Exec(sql, args...)
}
