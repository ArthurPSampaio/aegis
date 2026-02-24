package access

import "fmt"

type Permission string

const (
	SecretsStore   Permission = "secrets.store"
	SecretsOpen    Permission = "secrets.open"
	TokensIssue    Permission = "tokens.issue"
	TokensValidate Permission = "tokens.validate"
	AuditRead      Permission = "audit.read"
	WebhooksSign   Permission = "webhooks.sign"
	WebhooksVerify Permission = "webhooks.verify"
)

type Role struct {
	Name        string
	Permissions map[Permission]bool
}

// define roles disponíveis no sistema
type Policy struct {
	roles map[string]Role
}

func NewPolicy() *Policy {
	return &Policy{
		roles: map[string]Role{},
	}
}

// adiciona uma role com suas permissões à política
func (p *Policy) AddRole(name string, permissions ...Permission) {
	perms := map[Permission]bool{}
	for _, perm := range permissions {
		perms[perm] = true
	}

	p.roles[name] = Role{
		Name:        name,
		Permissions: perms,
	}
}

// verifica permissões
func (p *Policy) Can(role string, permission Permission) error {
	r, exists := p.roles[role]
	if !exists {
		return fmt.Errorf("role '%s' não encontrada", role)
	}

	if !r.Permissions[permission] {
		return fmt.Errorf("role '%s' não tem permissão '%s'", role, permission)
	}

	return nil
}