package tokens

import (
	"testing"
	"time"
)

func TestIssueAndValidate(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("falha ao gerar keypair: %v", err)
	}

	tokenString, err := Issue("user-123", "admin", time.Hour, keyPair)
	if err != nil {
		t.Fatalf("Issue falhou: %v", err)
	}

	claims, err := Validate(tokenString, keyPair)
	if err != nil {
		t.Fatalf("Validate falhou: %v", err)
	}

	if claims.Subject != "user-123" {
		t.Errorf("subject incorreto: got %s, want user-123", claims.Subject)
	}

	if claims.Role != "admin" {
		t.Errorf("role incorreta: got %s, want admin", claims.Role)
	}
}

func TestTokenExpirado(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("falha ao gerar keypair: %v", err)
	}

	tokenString, err := Issue("user-123", "admin", -time.Hour, keyPair)
	if err != nil {
		t.Fatalf("Issue falhou: %v", err)
	}

	_, err = Validate(tokenString, keyPair)
	if err == nil {
		t.Fatal("Validate deveria ter falhado com token expirado, mas não falhou")
	}
}

func TestTokenComChaveErrada(t *testing.T) {
	keyPair1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("falha ao gerar keypair 1: %v", err)
	}

	keyPair2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("falha ao gerar keypair 2: %v", err)
	}

	tokenString, err := Issue("user-123", "admin", time.Hour, keyPair1)
	if err != nil {
		t.Fatalf("Issue falhou: %v", err)
	}

	_, err = Validate(tokenString, keyPair2)
	if err == nil {
		t.Fatal("Validate deveria ter falhado com chave errada, mas não falhou")
	}
}