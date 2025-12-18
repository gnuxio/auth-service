package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"auth-microservice/internal/cognito"
	"auth-microservice/internal/config"
	"auth-microservice/internal/handlers"

	_ "github.com/joho/godotenv/autoload"
)

type Server struct {
	config      *config.Config
	authHandler *handlers.AuthHandler
}

func NewServer() *http.Server {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	cognitoClient, err := cognito.NewClient(
		context.Background(),
		cfg.AWSRegion,
		cfg.CognitoClientID,
		cfg.CognitoClientSecret,
		cfg.CognitoUserPoolID,
	)
	if err != nil {
		log.Fatalf("Failed to create Cognito client: %v", err)
	}

	authHandler := handlers.NewAuthHandler(cognitoClient, cfg)

	newServer := &Server{
		config:      cfg,
		authHandler: authHandler,
	}

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      newServer.RegisterRoutes(),
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return server
}
