package access

import "testing"

func TestCan(t *testing.T) {
	policy := NewPolicy()

	policy.AddRole("admin", SecretsStore, SecretsOpen, TokensIssue)
	policy.AddRole("auditor", AuditRead)
	policy.AddRole("service", TokensValidate, WebhooksVerify)

	if err := policy.Can("admin", SecretsStore); err != nil {
		t.Fatalf("admin deveria ter permissão secrets.store: %v", err)
	}

	if err := policy.Can("auditor", AuditRead); err != nil {
		t.Fatalf("auditor deveria ter permissão audit.read: %v", err)
	}
}

func TestCanSemPermissao(t *testing.T) {
	policy := NewPolicy()

	policy.AddRole("service", TokensValidate, WebhooksVerify)

	if err := policy.Can("service", SecretsOpen); err == nil {
		t.Fatal("service não deveria ter permissão secrets.open, mas teve")
	}
}

func TestCanRoleInexistente(t *testing.T) {
	policy := NewPolicy()

	if err := policy.Can("inexistente", SecretsStore); err == nil {
		t.Fatal("role inexistente deveria ser rejeitada, mas não foi")
	}
}

func TestSegregacaoDeFuncoes(t *testing.T) {
	policy := NewPolicy()

	policy.AddRole("service-pagamentos", TokensValidate, WebhooksVerify)
	policy.AddRole("service-notificacoes", WebhooksSign)

	// service-pagamentos não pode assinar webhooks
	if err := policy.Can("service-pagamentos", WebhooksSign); err == nil {
		t.Fatal("service-pagamentos não deveria assinar webhooks, mas conseguiu")
	}

	// service-notificacoes não pode validar tokens
	if err := policy.Can("service-notificacoes", TokensValidate); err == nil {
		t.Fatal("service-notificacoes não deveria validar tokens, mas conseguiu")
	}
}