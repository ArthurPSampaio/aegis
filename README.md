# Aegis

Toolkit de segurança para sistemas financeiros escrito em Go. Implementa os mecanismos de gerenciamento de segredos e tokens, com planejamento de adição de auditoria e controle de acesso.

## Módulos Feitos 

### ✅ Secrets Manager
Armazenamento seguro de segredos com envelope encryption. Cada segredo tem sua própria chave de dados (DEK) cifrada com AES-256-GCM. A DEK é cifrada com a chave mestra (KEK), garantindo que comprometer um segredo não compromete os demais.

### ✅ Token Engine
Emissão e validação de JWTs assinados com RS256. A separação entre chave privada (emissão) e chave pública (validação) garante que serviços downstream possam validar tokens sem conseguir criá-los.

## Módulos Pendentes

### 🔲 Audit Log
Registro imutável de operações com hash chain verificável.

### 🔲 Webhook Signatures
Assinatura de eventos com HMAC-SHA256 e proteção contra replay attacks.

### 🔲 Access Control
Controle de acesso por role com princípio de least privilege.

## Stack

Go 1.22+, AES-256-GCM, RSA-2048, PostgreSQL.

---

*Projeto educacional.*