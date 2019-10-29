package site

import (
	"encoding/json"
//	"fmt"
//	"log"
	"net/http"
)

// ClientError is an error whose details to be shared with client.
type ClientError interface {
	Error() string
	// ResponseBody returns response body.
	ResponseBody() ([]byte, error)
	// ResponseHeaders returns http status code and headers.
	ResponseHeaders() (int, map[string]string)
}


// HTTPError implements ClientError interface.
type HTTPError struct {
	Cause  error  `json:"-"`
	Detail string `json:"detail"`
	Status int    `json:"statuscode"`
}

func (e *HTTPError) Error() string {
	if e.Cause == nil {
		return e.Detail
	}
	return e.Detail + " : " + e.Cause.Error()
}

// ResponseBody returns JSON response body.
func (e *HTTPError) ResponseBody(w http.ResponseWriter) /*([]byte, error)*/ {
	//body, err := json.Marshal(e)
	/*if err != nil {
		return nil, fmt.Errorf("Error while parsing response body: %v", err)
	}*/
	json.NewEncoder(w).Encode(e)
	//return body, nil
	return
}

// ResponseHeaders returns http status code and headers.
func (e *HTTPError) ResponseHeaders() (int, map[string]string) {
	//func (e *HTTPError) ResponseHeaders() (int) {
	return e.Status, map[string]string{
		"Content-Type": "application/json; charset=utf-8",
	//return e.Status
	}
}
/*
func NewHTTPError(err error, status int, detail string) error {
	return &HTTPError{
		Cause:  err,
		Detail: detail,
		Status: status,
	}
}
*/
func NewHTTPError (w http.ResponseWriter, err error, status int, detail string) /*[]byte*/ {
	
	e :=HTTPError{
		Cause: err,
		Detail: detail,
		Status: status}

	//body, err2 := e.ResponseBody()
	e.ResponseBody(w)

	/*
	if err2 != nil {
		log.Printf("An error accured: %v", err2)
		w.WriteHeader(500)
		return body
	}
	*/

	_,headers := e.ResponseHeaders()
	
	for k, v := range headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(status)
	//w.Write(body)

	//return body
	return


}