# Aegis

Toolkit de segurança para sistemas financeiros escrito em Go. Implementa os mecanismos de gerenciamento de segredos, tokens, auditoria e assinatura de eventos, com planejamento de adição de controle de acesso.

## Módulos Feitos

### ✅ Secrets Manager
Armazenamento seguro de segredos com envelope encryption. Cada segredo tem sua própria chave de dados (DEK) cifrada com AES-256-GCM. A DEK é cifrada com a chave mestra (KEK), garantindo que comprometer um segredo não compromete os demais.

### ✅ Token Engine
Emissão e validação de JWTs assinados com RS256. A separação entre chave privada (emissão) e chave pública (validação) garante que serviços downstream possam validar tokens sem conseguir criá-los.

### ✅ Audit Log
Registro imutável de operações com hash chain verificável. Cada entrada inclui o hash da anterior — qualquer adulteração, inserção ou remoção quebra a cadeia e é detectada na verificação.

### ✅ Webhook Signatures
Assinatura de eventos com HMAC-SHA256 e proteção contra replay attacks. O timestamp incluído na assinatura garante que requisições capturadas não podem ser reusadas fora da janela de tolerância.

## Módulos Pendentes

### 🔲 Access Control
Controle de acesso por role com princípio de least privilege.

## Stack

Go 1.22+, AES-256-GCM, RSA-2048, PostgreSQL.

---

*Projeto educacional.*