package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Port               string
	GinMode            string
	DBHost             string
	DBPort             string
	DBUser             string
	DBPassword         string
	DBName             string
	DBSSLMode          string
	DBTimezone         string
	JWTAccessSecret    string
	JWTRefreshSecret   string
	JWTAccessExpiry    time.Duration
	JWTRefreshExpiry   time.Duration
	CORSAllowedOrigins []string
}

func LoadConfig() *Config {
	if err := godotenv.Load(); err != nil {
		log.Println("Info: .env file not found, using system environment variables")
	}

	accessMinutes := getEnvAsInt("JWT_ACCESS_EXPIRY_MINUTES", 15)
	refreshDays := getEnvAsInt("JWT_REFRESH_EXPIRY_DAYS", 7)

	originsRaw := getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173")
	var origins []string
	for _, o := range strings.Split(originsRaw, ",") {
		trimmed := strings.TrimSpace(o)
		if trimmed != "" {
			origins = append(origins, trimmed)
		}
	}

	return &Config{
		Port:               getEnv("PORT", "8080"),
		GinMode:            getEnv("GIN_MODE", "debug"),
		DBHost:             getEnv("DB_HOST", "localhost"),
		DBPort:             getEnv("DB_PORT", "5432"),
		DBUser:             getEnv("DB_USER", "postgres"),
		DBPassword:         getEnv("DB_PASSWORD", "postgres"),
		DBName:             getEnv("DB_NAME", "gin_auth_db"),
		DBSSLMode:          getEnv("DB_SSLMODE", "disable"),
		DBTimezone:         getEnv("DB_TIMEZONE", "Asia/Jakarta"),
		JWTAccessSecret:    getEnv("JWT_ACCESS_SECRET", "super-secret-access-key-change-in-production"),
		JWTRefreshSecret:   getEnv("JWT_REFRESH_SECRET", "super-secret-refresh-key-change-in-production"),
		JWTAccessExpiry:    time.Duration(accessMinutes) * time.Minute,
		JWTRefreshExpiry:   time.Duration(refreshDays) * 24 * time.Hour,
		CORSAllowedOrigins: origins,
	}
}

func (c *Config) GetDSN() string {
	return fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=%s",
		c.DBHost, c.DBUser, c.DBPassword, c.DBName, c.DBPort, c.DBSSLMode, c.DBTimezone,
	)
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists && value != "" {
		return value
	}
	return fallback
}

func getEnvAsInt(key string, fallback int) int {
	valStr := getEnv(key, "")
	if val, err := strconv.Atoi(valStr); err == nil {
		return val
	}
	return fallback
}
