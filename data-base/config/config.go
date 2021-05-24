package config

import (
	"fmt"
	"os"
)

func GetDBType() string {
	dbType := os.Getenv("DBType")
	return dbType
}

func GetPostgresConnectionString() string {
	dataBase := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=disable",
		os.Getenv("DBHost"),
		os.Getenv("DBPort"),
		os.Getenv("DBUser"),
		os.Getenv("DBName"),
		os.Getenv("DBPassword"),
	)
	return dataBase
}
