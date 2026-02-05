// Package config provides configuration for the gateway server.
package config

import (
	"os"
	"strconv"
)

// Config holds the gateway server configuration.
type Config struct {
	// Server settings
	ListenAddr string

	// Valkey settings
	ValkeyAddr     string
	ValkeyPassword string
	ValkeyDB       int

	// Logging
	LogLevel string
}

// FromEnv loads configuration from environment variables.
func FromEnv() *Config {
	return &Config{
		ListenAddr:     getEnv("GATEWAY_LISTEN_ADDR", ":8080"),
		ValkeyAddr:     getEnv("VALKEY_ADDR", "localhost:6379"),
		ValkeyPassword: getEnv("VALKEY_PASSWORD", ""),
		ValkeyDB:       getEnvInt("VALKEY_DB", 0),
		LogLevel:       getEnv("LOG_LEVEL", "info"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}
