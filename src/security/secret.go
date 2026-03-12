package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const secureSecretPrefix = "secure-aesgcm$"

func EncryptSecretValue(value string) (string, error) {
	if value == "" {
		return "", nil
	}

	key := sha256.Sum256([]byte(GetSecureSecret()))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", fmt.Errorf("创建加密器失败: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("创建加密模式失败: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("生成随机数失败: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(value), nil)
	payload := append(nonce, ciphertext...)
	return secureSecretPrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

func DecryptSecretValue(value string) (string, error) {
	if value == "" {
		return "", nil
	}

	// 兼容历史明文 SSH 密码，避免已有连接立即失效。
	if !strings.HasPrefix(value, secureSecretPrefix) {
		return value, nil
	}

	raw := strings.TrimPrefix(value, secureSecretPrefix)
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("解码加密内容失败: %w", err)
	}

	key := sha256.Sum256([]byte(GetSecureSecret()))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", fmt.Errorf("创建解密器失败: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("创建解密模式失败: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(payload) < nonceSize {
		return "", fmt.Errorf("加密内容长度无效")
	}

	nonce := payload[:nonceSize]
	ciphertext := payload[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("解密 SSH 密码失败: %w", err)
	}
	return string(plain), nil
}
