// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// At-rest encryption for short-lived capability secrets (ACME challenge /
// authorization tokens). A deployment that leaks its database must not also
// leak live proof-of-control tokens, so these are encrypted with an
// operator-supplied key that lives outside the database (env / KMS), never in
// a table next to the ciphertext.
//
// Storage format: "enc:v1:<base64(nonce||ciphertext)>". Values without the
// prefix are legacy plaintext (still readable for backward compatibility until
// the row is rewritten; see the caller wiring in acme.go).

// atRestEncPrefix marks an at-rest-encrypted value.
const atRestEncPrefix = "enc:v1:"

// encryptAtRest seals plaintext with AES-256-GCM. The random 12-byte nonce is
// prepended to the ciphertext and both are base64-encoded.
func encryptAtRest(key []byte, plaintext string) (string, error) {
	if len(key) == 0 {
		// No operator key configured: keep on-disk behaviour unchanged rather
		// than inventing a key out of thin air.
		return plaintext, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("at-rest nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return atRestEncPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// decryptAtRest opens a value produced by encryptAtRest. Legacy plaintext
// values (no prefix) are returned unchanged so existing rows keep working.
func decryptAtRest(key []byte, stored string) (string, error) {
	if !strings.HasPrefix(stored, atRestEncPrefix) {
		return stored, nil
	}
	if len(key) == 0 {
		return "", fmt.Errorf("at-rest value present but no decryption key configured")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, atRestEncPrefix))
	if err != nil {
		return "", fmt.Errorf("decode at-rest value: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return "", fmt.Errorf("at-rest value too short")
	}
	open, err := gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt at-rest value: %w", err)
	}
	return string(open), nil
}
