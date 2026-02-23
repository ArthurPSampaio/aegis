package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// janela de tempo aceitavel para um webhook - previne Replay Attack
const Tolerance = 5 * time.Minute

// assina um payload com HMAC-SHA256
func Sign(payload []byte, secret []byte) (signature string, timestamp int64) {
	timestamp = time.Now().Unix()
	signature = computeSignature(payload, secret, timestamp)
	return
}

// calcula HMAC-SHA256 sobre timestamp + payload
func computeSignature(payload []byte, secret []byte, timestamp int64) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("."))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// verifica a assinatura de um webhook recebido
func Verify(payload []byte, secret []byte, signature string, timestamp int64) error {
	receivedAt := time.Now().Unix()
	age := time.Duration(receivedAt-timestamp) * time.Second

	if age > Tolerance || age < -Tolerance {
		return fmt.Errorf("webhook expirado: idade %v excede tolerância de %v", age, Tolerance)
	}

	expected := computeSignature(payload, secret, timestamp)

	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return fmt.Errorf("assinatura inválida")
	}

	return nil
}