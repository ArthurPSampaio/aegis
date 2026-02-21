package secrets

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestStoreAndOpen(t *testing.T) {
	kek := make([]byte,DEKSize)
	_, err := rand.Read(kek)
	if err != nil {
		t.Fatalf("falha ao gerar KEK: %v", err)
	}

	plaintext := []byte("token-secreto-do-parceiro-123")

	secret, err := Store(plaintext, kek)
	if err != nil {
		t.Fatalf("Store falhou: %v", err)
	}

	recovered, err := Open(secret, kek)
	if err != nil {
		t.Fatalf("Open falhou: %v", err)
	}

	if !bytes.Equal(plaintext, recovered) {
		t.Errorf("dado recuperado diferente do original\ngot:  %s\nwant: %s", recovered, plaintext)
	}
}

func TestOpenComKEKErrada(t *testing.T) {
	kek := make([]byte, DEKSize)
	_, err := rand.Read(kek)
	if err != nil {
		t.Fatalf("falha ao gerar KEK: %v", err)
	}

	plaintext := []byte("dado-sensivel")

	secret, err := Store(plaintext, kek)
	if err != nil {
		t.Fatalf("Store falhou: %v", err)
	}

	kekErrada := make([]byte, DEKSize)
	_, err = rand.Read(kekErrada)
	if err != nil {
		t.Fatalf("falha ao gerar KEK errada: %v", err)
	}

	_, err = Open(secret, kekErrada)
	if err == nil {
		t.Fatal("Open deveria ter falhado com KEK errada, mas não falhou")
	}
}