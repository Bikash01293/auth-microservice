package config

import (
	"github.com/spf13/viper"
)

type Config struct {
	Port         string `mapstructure:"PORT"`
	DbUrl        string `mapstructure:"DB_URL"`
	JwtSecretKey string `mapstructure:"JWT_SECRET_KEY"`
}

func LoadConfig() (config Config, err error) {
	viper.AddConfigPath("./pkg/config/env")
	viper.SetConfigName("dev")
	viper.SetConfigType("env")

	viper.AutomaticEnv()

	if err = viper.ReadInConfig(); err != nil {
		return
	}

	err = viper.Unmarshal(&config)

	return

}
