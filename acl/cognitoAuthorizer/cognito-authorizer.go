package cognitoAuthorizer

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/seill/api/acl"
)

type CognitoAuthorizer struct {
	acl.BaseAuthorizer
	cognitoIdp *cognitoidentityprovider.Client
	userPoolId *string
	username   *string
	user       *cognitoidentityprovider.AdminGetUserOutput
}

func New(identity acl.Identity) *CognitoAuthorizer {
	return &CognitoAuthorizer{
		BaseAuthorizer: acl.BaseAuthorizer{
			Identity: identity,
		},
		cognitoIdp: identity.Cognito.CognitoIdp,
		userPoolId: &identity.Cognito.UserPoolId,
		username:   &identity.Cognito.Username,
	}
}

func (a *CognitoAuthorizer) Authorize(authorization *acl.Authorization) (roles []string, action acl.Action, err error) {
	err = a.getUser()
	if nil != err {
		return
	}

	roles = a.GetRoles()
	action, err = a.BaseAuthorizer.Authorize(authorization, roles)

	return
}

func (a *CognitoAuthorizer) GetRoles() (roles []string) {
	var _err = a.getUser()
	if nil != _err {
		goto guest
	}

	for _, attributeType := range a.user.UserAttributes {
		if 0 == strings.Compare(*attributeType.Name, "custom:roles") {
			roles = strings.Split(*attributeType.Value, " ")
			return
		}
	}

guest:
	roles = []string{"guest"}
	return
}

func (a *CognitoAuthorizer) getUser() (err error) {
	if nil == a.user {
		a.user, err = a.cognitoIdp.AdminGetUser(context.TODO(), &cognitoidentityprovider.AdminGetUserInput{
			UserPoolId: a.userPoolId,
			Username:   a.username,
		})
	}

	return
}
