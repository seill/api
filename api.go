package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/seill/api/acl"
	"github.com/seill/api/acl/authorizerFactory"
	"github.com/seill/api/menu"

	"github.com/seill/ddb"
)

var Handlers map[string]map[string]Handler
var ErrorCodes map[string]ErrorCode

type IService interface {
	OnRegisterHandlers() (handlers map[string]map[string]Handler)
	OnRegisterErrorCodes() (errorCodes []ErrorCode)
	OnRegisterAcls() (acls map[string]acl.Acl)
	OnRegisterMenuItems() (items []menu.Item)
}

type Handler struct {
	Function      func(*Request) (*Response, *Error) `json:"-"`
	Authorization *acl.Authorization                 `json:"authorization"`
}

type Request struct {
	Stage     string        `json:"stage"`
	RequestId string        `json:"requestId"`
	Payload   interface{}   `json:"payload,omitempty"`
	Identity  *acl.Identity `json:"identity,omitempty"`
	Roles     []string      `json:"roles,omitempty"`
	Action    *acl.Action   `json:"action,omitempty"`
}

func Init() (awsConfig *aws.Config, _ddb *ddb.Ddb, isLocal bool) {
	if _value, _err := strconv.ParseBool(os.Getenv("AWS_SAM_LOCAL")); nil == _err {
		isLocal = _value
	}

	if _value, _err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(os.Getenv("AWS_REGION"))); nil == _err {
		awsConfig = &_value

		if isLocal {
			ddbClient := dynamodb.NewFromConfig(*awsConfig, func(o *dynamodb.Options) {
				o.BaseEndpoint = aws.String(os.Getenv("DYNAMODB_ENDPOINT"))
			})

			_ddb = ddb.New(ddbClient, os.Getenv("TABLE_NAME"))
		}
	}

	return
}

func RegisterHandlers(handlers map[string]map[string]Handler) {
	Handlers = handlers
}

func RegisterErrorCodes(errorCodes map[string]ErrorCode) {
	ErrorCodes = errorCodes
}

func RegisterAcls(acls map[string]acl.Acl) {
	acl.Acls = acls
}

func RegisterMenuItems(items []menu.Item) {
	menu.Items = items
}

func Execute(tag *string, awsConfig *aws.Config, request *events.APIGatewayProxyRequest, isLocal bool) (response events.APIGatewayProxyResponse) {
	var _apiError *Error
	var apiRequest Request
	var apiResponse *Response

	apiRequest = Request{
		Stage:     request.RequestContext.Stage,
		RequestId: request.RequestContext.RequestID,
		Payload:   _mustBuildPayload(request),
	}

	if isLocal {
		apiRequest.Identity = &acl.Identity{
			MemberId: aws.String("000000000000000_LOCAL_TEST"),
			Type:     acl.IdentityTypeDummy,
			Dummy: &acl.IdentityDummy{
				Roles:    []string{"system/admin"},
				Username: "local user",
			},
		}
	} else {
		var userPoolId, username, memberId string

		if value, ok := request.RequestContext.Authorizer["claims"].(map[string]interface{}); ok {
			iss := value["iss"].(string)
			issArray := strings.Split(iss, "/")
			userPoolId = issArray[len(issArray)-1]
			username = value["cognito:username"].(string)
			memberId = value["custom:memberId"].(string)
		}

		apiRequest.Identity = &acl.Identity{
			MemberId: aws.String(memberId),
			Type:     acl.IdentityTypeCognito,
			Cognito: &acl.IdentityCognito{
				CognitoIdp: cognitoidentityprovider.NewFromConfig(*awsConfig),
				UserPoolId: userPoolId,
				Username:   username,
			},
		}
	}

	apiResponse, _apiError = apiRequest._execute(request.HTTPMethod, request.Resource)
	if nil != _apiError {
		goto final
	}

final:
	response = apiResponse._mustBuildProxyResponse(_apiError)

	return
}

func (r *Request) _execute(httpMethod string, resource string) (apiResponse *Response, apiError *Error) {
	var _err error

	if nil == Handlers {
		apiError = &Error{
			ErrorCode: "99",
			Err:       errors.New("handlers not registered"),
		}
		return
	}

	if handler, ok := Handlers[resource][httpMethod]; ok {
		if nil != handler.Authorization {
			// access control
			var roles []string
			var action acl.Action

			roles, action, _err = authorizerFactory.GetAuthorizer(r.Identity).Authorize(handler.Authorization)
			if nil != _err {
				apiError = &Error{
					ErrorCode: "99",
					Err:       _err,
				}
				return
			}

			r.Roles = roles
			r.Action = &action
		}

		// call method by function
		if nil != handler.Function {
			apiResponse, apiError = handler.Function(r)
			return
		} else {
			apiError = &Error{
				ErrorCode: "99",
				Err:       errors.New("handler.Function is nil"),
			}
			return
		}
	}

	apiError = &Error{
		ErrorCode: "99",
		Err:       errors.New("method and resource not matched"),
	}

	return
}

type Response struct {
	Error            string            `json:"error"`
	Message          string            `json:"message,omitempty"`
	Data             interface{}       `json:"data"`
	Count            *uint64           `json:"count,omitempty"`
	Start            *uint64           `json:"start,omitempty"`
	Total            *uint64           `json:"total,omitempty"`
	LastEvaluatedKey interface{}       `json:"lastEvaluatedKey,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	IsBaredBody      *bool             `json:"isBaredBody,omitempty"`
}

func (r *Response) _mustBuildProxyResponse(apiError *Error) (response events.APIGatewayProxyResponse) {
	var locationInHeader *string

	response = events.APIGatewayProxyResponse{
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "*",
			"Access-Control-Allow-Headers": "*",
		},
		IsBase64Encoded: false,
	}

	// headers
	for k, v := range r.Headers {
		if 0 == strings.Compare(strings.ToLower(k), "location") {
			locationInHeader = aws.String(v)
		}

		response.Headers[k] = v
	}
	r.Headers = nil

	if nil != apiError {
		r.Error = apiError.ErrorCode
		r.Message = apiError.Error()
		response.StatusCode = apiError.GetStatusCode()
	} else {
		r.Error = "00"
		r.Message = "Success"

		if nil != locationInHeader {
			response.StatusCode = 301
		} else {
			response.StatusCode = 200
		}
	}

	if isBaredBody := r.IsBaredBody; nil != isBaredBody && *isBaredBody {
		response.Body = StructToString(r.Data)
	} else {
		response.Body = StructToString(*r)
	}

	return
}

type ErrorCode struct {
	Message    string `json:"message"`
	StatusCode int    `json:"statusCode"`
}

func _mustBuildPayload(requestProxy *events.APIGatewayProxyRequest) (payload interface{}) {
	var _err error
	payloadMap := map[string]interface{}{}

	// stage variable
	if nil != requestProxy.StageVariables {
		for k, v := range requestProxy.StageVariables {
			payloadMap[k] = v
		}
	}

	// body
	if "" != requestProxy.Body {
		_err = json.Unmarshal([]byte(requestProxy.Body), &payloadMap)

		if nil != _err {
			var parsedUrl *url.URL
			var decodedBody string

			decodedBody, _err = url.QueryUnescape(requestProxy.Body)
			if nil == _err {
				parsedUrl, _err = url.Parse(fmt.Sprintf("?%s", decodedBody))
				if nil == _err {
					for key, values := range parsedUrl.Query() {
						if 1 == len(values) {
							payloadMap[key] = values[0]
						} else if 1 < len(values) {
							payloadMap[key] = values
						}
					}
				}
			}
		}
	}

	// path
	if nil != requestProxy.PathParameters {
		for k, v := range requestProxy.PathParameters {
			payloadMap[k] = v
		}
	}

	// querystring
	if nil != requestProxy.QueryStringParameters {
		for k, v := range requestProxy.QueryStringParameters {
			payloadMap[k] = v
		}
	}

	// cookie
	if nil != requestProxy.Headers {
		for k, v := range requestProxy.Headers {
			if 0 == strings.Compare(strings.ToLower(k), "cookie") {
				cookieArray := strings.Split(v, "; ")

				for _, _v := range cookieArray {
					valueArray := strings.Split(_v, "=")

					if 2 == len(valueArray) {
						payloadMap[valueArray[0]] = valueArray[1]
					}
				}
			}
		}
	}

	payload = payloadMap

	return
}

type Error struct {
	ErrorCode string `json:"errorCode"`
	Err       error  `json:"err"`
}

func (ae *Error) Error() string {
	errorCode, err := ae.getErrorCodes()
	if nil != err {
		return fmt.Sprintf("%s:%s", ae.ErrorCode, err.Error())
	}

	return fmt.Sprintf("%s:%s:%s", ae.ErrorCode, errorCode.Message, ae.Err)
}

func (ae *Error) GetStatusCode() int {
	errorCode, err := ae.getErrorCodes()
	if nil != err {
		return 500
	}

	return errorCode.StatusCode
}

func (ae *Error) getErrorCodes() (errorCode *ErrorCode, err error) {
	if nil == ErrorCodes {
		err = errors.New("errorCodes not registered")
		return
	}

	if _errorCode, ok := ErrorCodes[ae.ErrorCode]; ok {
		errorCode = &_errorCode
		return
	}

	err = fmt.Errorf("not found in errorCodes")

	return
}

func StructToString(s interface{}) string {
	bytes, err := json.Marshal(s)
	if nil != err {
		return ""
	}

	return string(bytes)
}
