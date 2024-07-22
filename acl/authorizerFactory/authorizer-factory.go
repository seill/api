package authorizerFactory

import (
	"github.com/seill/api/acl"
	"github.com/seill/api/acl/cognitoAuthorizer"
	"github.com/seill/api/acl/dummyAuthorizer"
)

func GetAuthorizer(identity *acl.Identity) (authorizer acl.IAuthorizer) {
	switch identity.Type {
	case acl.IdentityTypeDummy:
		authorizer = dummyAuthorizer.New(*identity)
	case acl.IdentityTypeCognito:
		authorizer = cognitoAuthorizer.New(*identity)
	}

	return
}
