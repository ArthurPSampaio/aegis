package audit

import (
	"testing"
)

func TestAddAndVerify(t *testing.T) {
	log := New()

	log.Add("secret.stored", "user-123")
	log.Add("token.issued", "user-123")
	log.Add("secret.accessed", "service-payments")

	if err := log.Verify(); err != nil {
		t.Fatalf("log válido falhou na verificação: %v", err)
	}
}

func TestVerifyDetectaTampering(t *testing.T) {
	log := New()

	log.Add("secret.stored", "user-123")
	log.Add("token.issued", "user-123")
	log.Add("secret.accessed", "service-payments")

	// Adultera o evento da segunda entrada diretamente
	log.entries[1].Event = "secret.deleted"

	if err := log.Verify(); err == nil {
		t.Fatal("Verify deveria ter detectado adulteração, mas não detectou")
	}
}

func TestVerifyDetectaEntradaInserida(t *testing.T) {
	log := New()

	log.Add("secret.stored", "user-123")
	log.Add("secret.accessed", "service-payments")

	// Insere uma entrada falsa no meio sem recalcular a chain
	entrada := Entry{
		ID:       99,
		Event:    "token.issued",
		Actor:    "atacante",
		PrevHash: log.entries[0].Hash,
	}
	entrada.Hash = computeHash(entrada)

	novasEntradas := []Entry{log.entries[0], entrada, log.entries[1]}
	log.entries = novasEntradas

	if err := log.Verify(); err == nil {
		t.Fatal("Verify deveria ter detectado entrada inserida, mas não detectou")
	}
}