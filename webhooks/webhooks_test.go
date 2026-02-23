package webhooks

import (
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	secret := []byte("chave-secreta-do-parceiro")
	payload := []byte(`{"event":"secret.rotated","id":"123"}`)

	signature, timestamp := Sign(payload, secret)

	if err := Verify(payload, secret, signature, timestamp); err != nil {
		t.Fatalf("webhook válido falhou na verificação: %v", err)
	}
}

func TestVerifyAssinaturaInvalida(t *testing.T) {
	secret := []byte("chave-secreta-do-parceiro")
	payload := []byte(`{"event":"secret.rotated","id":"123"}`)

	_, timestamp := Sign(payload, secret)

	if err := Verify(payload, secret, "assinatura-falsa", timestamp); err == nil {
		t.Fatal("Verify deveria ter rejeitado assinatura inválida, mas não rejeitou")
	}
}

func TestVerifyPayloadAlterado(t *testing.T) {
	secret := []byte("chave-secreta-do-parceiro")
	payload := []byte(`{"event":"secret.rotated","id":"123"}`)

	signature, timestamp := Sign(payload, secret)

	payloadAlterado := []byte(`{"event":"secret.rotated","id":"456"}`)

	if err := Verify(payloadAlterado, secret, signature, timestamp); err == nil {
		t.Fatal("Verify deveria ter rejeitado payload alterado, mas não rejeitou")
	}
}

func TestVerifyReplayAttack(t *testing.T) {
	secret := []byte("chave-secreta-do-parceiro")
	payload := []byte(`{"event":"secret.rotated","id":"123"}`)

	timestampAntigo := time.Now().Add(-10 * time.Minute).Unix()
	signature := computeSignature(payload, secret, timestampAntigo)

	if err := Verify(payload, secret, signature, timestampAntigo); err == nil {
		t.Fatal("Verify deveria ter rejeitado replay attack, mas não rejeitou")
	}
}