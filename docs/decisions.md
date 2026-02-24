# Decisões técnicas

Anotações sobre as principais escolhas de segurança do projeto.

---

## AES-GCM em vez de AES-CBC

CBC não autentica o ciphertext — ele só cifra. Se alguém modificar os bytes cifrados, você só descobre depois de decifrar, e às vezes nem descobre. Isso abre espaço para padding oracle attacks, onde um atacante faz requisições com ciphertexts levemente modificados e usa as mensagens de erro para deduzir o plaintext.

GCM gera uma tag de autenticação junto com o ciphertext. Qualquer modificação invalida a tag e a decifração falha imediatamente, antes de retornar qualquer dado.

## RS256 em vez de HS256

HS256 usa a mesma chave para assinar e validar tokens. Em sistemas com vários serviços, todos precisam conhecer a chave — e qualquer serviço comprometido consegue emitir tokens, não só validá-los.

RS256 usa um par de chaves assimétricas. Só o Aegis tem a chave privada e pode emitir tokens. Os outros serviços validam com a chave pública, que pode ser distribuída livremente sem risco.

## Constant-time comparison no HMAC

Comparar strings com `==` para no primeiro caractere diferente. Um atacante que mede o tempo de resposta de muitas requisições com assinaturas diferentes consegue deduzir a assinatura correta byte por byte — isso é um timing attack.

`hmac.Equal` sempre percorre os dois valores inteiros independente de onde está a diferença. O tempo de execução é constante, então não vaza informação sobre onde a assinatura diverge.

## Envelope encryption no Secrets Manager

Cifrar todos os segredos com a mesma chave significa que comprometer essa chave compromete tudo. Com envelope encryption, cada segredo tem sua própria chave de dados (DEK). A DEK é cifrada com a chave mestra (KEK).

Se um segredo específico for comprometido, os outros não são afetados. Se precisar rotacionar a chave mestra, só as DEKs precisam ser re-cifradas — não os dados.

## Hash chain no Audit Log

Guardar logs num banco de dados não garante imutabilidade — um administrador com acesso direto pode alterar ou deletar registros. A hash chain faz cada entrada depender do hash da anterior.

Qualquer modificação numa entrada muda seu hash, o que invalida o hash de todas as entradas seguintes. A integridade do log inteiro pode ser verificada criptograficamente a qualquer momento.