# Aegis

Toolkit de segurança para sistemas financeiros escrito em Go. Implementa gerenciamento de segredos, tokens, auditoria, assinatura de eventos e controle de acesso.

## Módulos

### ✅ Secrets Manager
Armazenamento seguro de segredos com envelope encryption. Cada segredo tem sua própria chave de dados (DEK) cifrada com AES-256-GCM. A DEK é cifrada com a chave mestra (KEK), garantindo que comprometer um segredo não compromete os demais.

### ✅ Token Engine
Emissão e validação de JWTs assinados com RS256. A separação entre chave privada (emissão) e chave pública (validação) garante que serviços downstream possam validar tokens sem conseguir criá-los.

### ✅ Audit Log
Registro imutável de operações com hash chain verificável. Cada entrada inclui o hash da anterior — qualquer adulteração, inserção ou remoção quebra a cadeia e é detectada na verificação.

### ✅ Webhook Signatures
Assinatura de eventos com HMAC-SHA256 e proteção contra replay attacks. O timestamp incluído na assinatura garante que requisições capturadas não podem ser reusadas fora da janela de tolerância.

### ✅ Access Control
Controle de acesso por role com princípio de least privilege. Cada serviço tem acesso apenas às operações necessárias para sua função — requisito explícito de segregação de funções do Banco Central.

## Stack

Go 1.22+, AES-256-GCM, RSA-2048, PostgreSQL.

---

*Projeto educacional.*