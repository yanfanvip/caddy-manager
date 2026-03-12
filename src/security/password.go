package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"sync"
)

const (
	DefaultSecureSecret = "123456"
	secureHashPrefix    = "secure-sha256$"
)

var (
	currentSecureSecret = DefaultSecureSecret
	secureSecretMu      sync.RWMutex
)

func NormalizeSecureSecret(secret string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return DefaultSecureSecret
	}
	return secret
}

func SetSecureSecret(secret string) string {
	normalized := NormalizeSecureSecret(secret)
	secureSecretMu.Lock()
	currentSecureSecret = normalized
	secureSecretMu.Unlock()
	return normalized
}

func GetSecureSecret() string {
	secureSecretMu.RLock()
	defer secureSecretMu.RUnlock()
	return currentSecureSecret
}

func HashPassword(password string) string {
	return HashPasswordWithSecret(password, GetSecureSecret())
}

func HashPasswordWithSecret(password, secret string) string {
	mac := hmac.New(sha256.New, []byte(NormalizeSecureSecret(secret)))
	mac.Write([]byte(password))
	return secureHashPrefix + hex.EncodeToString(mac.Sum(nil))
}

func ComparePassword(storedPassword, plainPassword string) bool {
	return ComparePasswordWithSecret(storedPassword, plainPassword, GetSecureSecret())
}

func IsSecurePasswordHash(storedPassword string) bool {
	return strings.HasPrefix(storedPassword, secureHashPrefix)
}

func ComparePasswordWithSecret(storedPassword, plainPassword, secret string) bool {
	if storedPassword == "" {
		return false
	}

	expected := HashPasswordWithSecret(plainPassword, secret)
	return IsSecurePasswordHash(storedPassword) &&
		subtle.ConstantTimeCompare([]byte(storedPassword), []byte(expected)) == 1
}
