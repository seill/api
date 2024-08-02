package acl

import (
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

const IdentityTypeDummy = "Dummy"
const IdentityTypeCognito = "Cognito"

var Acls map[string]Acl

const (
	View   = "view"
	Create = "create"
	Edit   = "edit"
	Remove = "remove"
)

type Identity struct {
	MemberId *string          `json:"memberId"`
	Type     string           `json:"type"`
	Dummy    *IdentityDummy   `json:"dummy"`
	Cognito  *IdentityCognito `json:"cognito"`
}

type IdentityDummy struct {
	Roles    []string `json:"roles"`
	Username string   `json:"username"`
}

type IdentityCognito struct {
	CognitoIdp *cognitoidentityprovider.Client `json:"-"`
	UserPoolId string                          `json:"userPoolId"`
	Username   string                          `json:"username"`
}

type Action struct {
	View   []string `json:"view,omitempty"`
	Create []string `json:"create,omitempty"`
	Edit   []string `json:"edit,omitempty"`
	Remove []string `json:"remove,omitempty"`
}

func (a *Action) GetResources() (resources []string) {
	resources = []string{}

	if nil != a.View {
		resources = append(resources, a.View...)
	}
	if nil != a.Create {
		resources = append(resources, a.Create...)
	}
	if nil != a.Edit {
		resources = append(resources, a.Edit...)
	}
	if nil != a.Remove {
		resources = append(resources, a.Remove...)
	}

	return
}

type Acl struct {
	Action
	Parent *string `json:"parent,omitempty"`
}

type Authorization struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

func getActionByRoles(roles []string) (action Action) {
	parentRoles := getParentRoles(roles)
	if nil != parentRoles {
		roles = append(roles, parentRoles...)
	}

	action = Action{
		View:   []string{},
		Create: []string{},
		Edit:   []string{},
		Remove: []string{},
	}

	if nil == Acls {
		return
	}

	for _, role := range roles {
		if acl, ok := Acls[role]; ok {
			action.View = append(action.View, acl.View...)
			action.View = append(action.View, acl.Create...)
			action.View = append(action.View, acl.Edit...)
			action.View = append(action.View, acl.Remove...)

			action.Create = append(action.Create, acl.Create...)
			action.Create = append(action.Create, acl.Edit...)
			action.Create = append(action.Create, acl.Remove...)

			action.Edit = append(action.Edit, acl.Edit...)
			action.Edit = append(action.Edit, acl.Remove...)

			action.Remove = append(action.Remove, acl.Remove...)
		}
	}

	return
}

func getParentRoles(roles []string) (parentRoles []string) {
	for _, role := range roles {
		if acl, ok := Acls[role]; ok {
			if nil != acl.Parent {
				if nil == parentRoles {
					parentRoles = []string{}
				}

				parentRoles = append(parentRoles, *acl.Parent)
				grandParentRoles := getParentRoles([]string{*acl.Parent})

				if nil != grandParentRoles {
					parentRoles = append(parentRoles, grandParentRoles...)
				}
			}
		}
	}

	return
}

func foundResourceInResources(resource string, resources []string) (found bool) {
	for _, resourceInResource := range resources {
		if 0 == strings.Compare(resourceInResource, "*") {
			found = true
			return
		}

		if 0 == strings.Compare(resource, resourceInResource) {
			found = true
			return
		}
	}

	return
}

type IAuthorizer interface {
	Authorize(authorization *Authorization) (roles []string, action Action, err error)
	GetRoles() (roles []string)
}

type BaseAuthorizer struct {
	IAuthorizer
	Identity Identity
}

func (a *BaseAuthorizer) Authorize(authorization *Authorization, roles []string) (action Action, err error) {
	var authorized bool

	action = getActionByRoles(roles)

	if nil == authorization {
		return
	}

	switch authorization.Action {
	case View:
		authorized = foundResourceInResources(authorization.Resource, action.View)
	case Create:
		authorized = foundResourceInResources(authorization.Resource, action.Create)
	case Edit:
		authorized = foundResourceInResources(authorization.Resource, action.Edit)
	case Remove:
		authorized = foundResourceInResources(authorization.Resource, action.Remove)
	}

	if !authorized {
		err = errors.New("resource not found")
	}

	return
}
