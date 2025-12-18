package config

import (
	"fmt"
	"os"
	"strconv"

	_ "github.com/joho/godotenv/autoload"
)

type Config struct {
	Port                int
	AppEnv              string
	AWSRegion           string
	CognitoUserPoolID   string
	CognitoClientID     string
	CognitoClientSecret string
	CookieDomain        string
	CookieSecure        bool
	FrontendURL         string
}

func Load() (*Config, error) {
	port, err := strconv.Atoi(getEnvOrDefault("PORT", "8080"))
	if err != nil {
		return nil, fmt.Errorf("invalid PORT: %w", err)
	}

	cookieSecure, _ := strconv.ParseBool(getEnvOrDefault("COOKIE_SECURE", "true"))

	cfg := &Config{
		Port:                port,
		AppEnv:              getEnvOrDefault("APP_ENV", "local"),
		AWSRegion:           os.Getenv("AWS_REGION"),
		CognitoUserPoolID:   os.Getenv("COGNITO_USER_POOL_ID"),
		CognitoClientID:     os.Getenv("COGNITO_CLIENT_ID"),
		CognitoClientSecret: os.Getenv("COGNITO_CLIENT_SECRET"),
		CookieDomain:        getEnvOrDefault("COOKIE_DOMAIN", ""),
		CookieSecure:        cookieSecure,
		FrontendURL:         getEnvOrDefault("FRONTEND_URL", "http://localhost:3000"),
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.AWSRegion == "" {
		return fmt.Errorf("AWS_REGION is required")
	}
	if c.CognitoUserPoolID == "" {
		return fmt.Errorf("COGNITO_USER_POOL_ID is required")
	}
	if c.CognitoClientID == "" {
		return fmt.Errorf("COGNITO_CLIENT_ID is required")
	}
	if c.CognitoClientSecret == "" {
		return fmt.Errorf("COGNITO_CLIENT_SECRET is required")
	}
	return nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
