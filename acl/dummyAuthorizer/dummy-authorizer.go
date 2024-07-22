package dummyAuthorizer

import (
	"github.com/seill/api/acl"
)

type DummyAuthorizer struct {
	acl.BaseAuthorizer
	Roles    []string
	Username string
}

func New(identity acl.Identity) *DummyAuthorizer {
	return &DummyAuthorizer{
		BaseAuthorizer: acl.BaseAuthorizer{
			Identity: identity,
		},
		Roles:    identity.Dummy.Roles,
		Username: identity.Dummy.Username,
	}
}

func (a *DummyAuthorizer) Authorize(authorization *acl.Authorization) (roles []string, action acl.Action, err error) {
	roles = a.Roles
	action, err = a.BaseAuthorizer.Authorize(authorization, roles)

	return
}

func (a *DummyAuthorizer) GetRoles() (roles []string) {
	return a.Roles
}
