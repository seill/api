package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/seill/api/acl"
	"github.com/seill/api/acl/authorizerFactory"
)

var Handlers []Handler
var ErrorCodes []ErrorCode

type Handler struct {
	Method        string             `json:"method"`
	Resource      string             `json:"resource"`
	FunctionName  string             `json:"functionName"`
	Authorization *acl.Authorization `json:"authorization"`
}

type Request struct {
	Stage     string        `json:"stage"`
	RequestId string        `json:"requestId"`
	Payload   interface{}   `json:"payload,omitempty"`
	Identity  *acl.Identity `json:"identity,omitempty"`
	Roles     []string      `json:"roles,omitempty"`
	Action    *acl.Action   `json:"action,omitempty"`
}

func (r *Request) Execute(httpMethod string, resource string, service interface{}) (apiResponse Response, apiError *Error) {
	var _err error

	for _, handler := range Handlers {
		if 0 == strings.Compare(httpMethod, handler.Method) && 0 == strings.Compare(resource, handler.Resource) {
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

			// call method by name
			value := reflect.ValueOf(service).MethodByName(handler.FunctionName)
			responseValues := value.Call([]reflect.Value{reflect.ValueOf(*r)})
			if 2 == len(responseValues) {
				if value := responseValues[0].Interface(); nil != value {
					apiResponse = value.(Response)
				}
				if value := responseValues[1].Interface(); nil != value {
					apiError = value.(*Error)
				}
				return
			} else {
				apiError = &Error{
					ErrorCode: "99",
					Err:       errors.New("invalid length of responseValues"),
				}
				return
			}
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

func (r *Response) MustBuildProxyResponse(apiError *Error) (response events.APIGatewayProxyResponse) {
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
	Code       string `json:"error"`
	Message    string `json:"message"`
	StatusCode int    `json:"statusCode"`
}

func MustBuildPayload(requestProxy events.APIGatewayProxyRequest) (payload interface{}) {
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
	for _, _errorCode := range ErrorCodes {
		if 0 == strings.Compare(_errorCode.Code, ae.ErrorCode) {
			errorCode = &_errorCode
			return
		}
	}

	return nil, errors.New("not found in errorCodes")
}

func StructToString(s interface{}) string {
	bytes, err := json.Marshal(s)
	if nil != err {
		return ""
	}

	return string(bytes)
}
