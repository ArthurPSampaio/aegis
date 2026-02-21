package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// Secret = segredo armazenado com envelope encryption
type Secret struct {
	EncryptedDEK []byte

	// contem IV + ciphertext + tag concatenados
	Ciphertext []byte
}

const DEKSize = 32

func generateDEK() ([]byte, error) {
	dek := make([]byte, DEKSize)

	_, err := rand.Read(dek)
	if err != nil {
		return nil, fmt.Errorf("falha ao gerar DEK: %w", err)
	}

	return dek, nil
}

// cifra usando AES-256-GCM
// retorna IV + ciphertext + tag concatenados
func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar GCM: %w", err)
	}

	iv := make([]byte, gcm.NonceSize())
	_, err = rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("falha ao gerar IV: %w", err)
	}

	ciphertext := gcm.Seal(iv, iv, plaintext, nil)

	return ciphertext, nil
}

// espera IV + ciphertext + tag concatenados como parametros
func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cypher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext muito curto")
	}

	iv, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("falha ao decifrar: %w", err)
	}

	return plaintext, nil
}

// cifra item usando a envelope encryption
func Store(plaintext []byte, kek []byte) (*Secret, error) {
	dek, err := generateDEK()
	if err != nil {
		return nil, fmt.Errorf("falha ao gerar DEK: %w", err)
	}

	ciphertext, err := encrypt(plaintext, dek)
	if err != nil {
		return nil, fmt.Errorf("falha ao cifrar dado: %w", err)
	}

	encryptedDEK, err := encrypt(dek, kek)
	if err != nil {
		return nil, fmt.Errorf("falha ao cifrar DEK: %w", err)
	}

	return &Secret{
		EncryptedDEK: encryptedDEK,
		Ciphertext:   ciphertext,
	}, nil
}

func Open(secret *Secret, kek []byte) ([]byte, error) {
	dek, err := decrypt(secret.EncryptedDEK, kek)
	if err != nil {
		return nil, fmt.Errorf("falha ao decifrar DEK: %w", err)
	}

	plaintext, err := decrypt(secret.Ciphertext, dek)
	if err != nil {
		return nil, fmt.Errorf("falha ao decifrar dado: %w", err)
	}

	return plaintext, nil
}
