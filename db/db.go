package db

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

func InitDB() error {
	var err error
	DB, err = sql.Open("mysql", "root:root@tcp(localhost:3306)/blogdb")
	if err != nil {
		return err
	}
	return DB.Ping()
}
