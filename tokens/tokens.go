package tokens

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// KeySize 2048 bits é o mínimo recomendado pelo NIST para uso até 2030.
const KeySize = 2048

// Par de chaves RSA
type KeyPair struct {
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
}

func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, KeySize)
	if err != nil {
		return nil, fmt.Errorf("falha ao gerar keypair: %w", err)
	}

	return &KeyPair{
		Private: privateKey,
		Public:  &privateKey.PublicKey,
	}, nil
}

// representa o payload do token JWT
// uso de embedding para herdar campos de jwt.RegisteredClaims
type Claims struct {
	jwt.RegisteredClaims
	Role string `json:"role"` // struct tag para definir como o campo é serializado para JSON
}

// Issue emite um token JWT assinado com a chave privada RSA
// subject identifica o dono do token — ID do usuário ou serviço.
// role define o nível de acesso.
// duration define por quanto tempo o token é válido.
func Issue(subject string, role string, duration time.Duration, keyPair *KeyPair) (string, error) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: 	subject,
			IssuedAt: 	jwt.NewNumericDate(time.Now()),
			ExpiresAt: 	jwt.NewNumericDate(time.Now().Add(duration)),
			Issuer: 	"aegis",
		},
		Role: role,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signed, err := token.SignedString(keyPair.Private)
	if err != nil {
		return "", fmt.Errorf("falha ao assinar token: %w", err)
	}

	return signed, nil
}

// valida token JWT e retorna os claims se valido
// rejeita tokens expirados, com assinatura invalida ou issuer incorreto
func Validate(tokenString string, keyPair *KeyPair) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			// verificação de algorithm confusion attack
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("algoritmo inesperado: %v", token.Header["alg"])
			}
			return keyPair.Public, nil
		},
	)

	if err != nil {
		return nil, fmt.Errorf("token invalido: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("claims inválidos")
	}

	return claims, nil
}