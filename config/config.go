package config

import (
	"errors"

	"github.com/spf13/viper"
)

// POSTGRES_HOST=146.235.232.120
// PORT=5432
// POSTGRES_USER=postgres
// POSTGRES_PASSWORD=postgres@balloonia.app
// JWT_SECRET=JDzpylXX5knaUuHa4z3y1s9AnNF56jXL/50zGTUyCLI=

type Config struct {
	PostgresDSN string
	JwtSecret   string
	Port        string
}

var Cfg *Config

func LoadConfig() error {
	viper.SetConfigFile(".env")

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return errors.New("Error reading .env file: " + err.Error())
	}

	config := &Config{
		PostgresDSN: viper.GetString("POSTGRES_DSN"),
		JwtSecret:   viper.GetString("JWT_SECRET"),
		Port:        viper.GetString("PORT"),
	}

	if config.PostgresDSN == "" {
		return errors.New("POSTGRES_DSN is not set")
	}

	if config.JwtSecret == "" {
		return errors.New("JWT_SECRET is not set")
	}

	if config.Port == "" {
		return errors.New("PORT is not set")
	}

	Cfg = config
	return nil
}

func Get() *Config {
	return Cfg
}
