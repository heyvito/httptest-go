// Package httptest provides facilities for handling HTTP tests for servers.
package httptest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/go-chi/chi"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// RequestMutator represents a mutation to be applied against an HTTP request.
// It takes a request, and returns a mutated copy of it.
type RequestMutator func(r *http.Request) *http.Request

// CloneRequest takes a given http.Request, and clones it into a new
// http.Request, preserving its body, if any. Use this instead of
// http.Request#Clone
func CloneRequest(r *http.Request) *http.Request {
	nr := r.Clone(r.Context())
	if r.Body != nil {
		var b bytes.Buffer
		_, err := b.ReadFrom(r.Body)
		if err != nil {
			panic(err)
		}
		r.Body = ioutil.NopCloser(&b)
		nr.Body = ioutil.NopCloser(bytes.NewReader(b.Bytes()))
	}
	return nr
}

// ChiContextFromRequest returns a chi.Context associated with a given
// http.Request, creating a new one in case the request does not have one yet.
func ChiContextFromRequest(r *http.Request) *chi.Context {
	rawChi := r.Context().Value(chi.RouteCtxKey)
	if rawChi == nil {
		return chi.NewRouteContext()
	} else {
		return rawChi.(*chi.Context)
	}
}

// WithURLParam adds a given chi URLParam with key k and value v into a provided
// http.Request. Useful for handlers using chi.URLParam to obtain URL
// parameters.
func WithURLParam(k, v string) RequestMutator {
	return func(r *http.Request) *http.Request {
		ctx := ChiContextFromRequest(r)
		ctx.URLParams.Add(k, v)
		return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
	}
}

// WithBody associates a body to the http.Request.
// See also: WithBodyString, WithBodyJSON, WithForm
func WithBody(reader io.Reader) RequestMutator {
	return func(r *http.Request) *http.Request {
		nr := CloneRequest(r)
		nr.Body = ioutil.NopCloser(reader)
		return nr
	}
}

// WithBodyString adds a given data string into the http.Request body.
// See also: WithBody
func WithBodyString(data string) RequestMutator {
	return WithBody(bytes.NewReader([]byte(data)))
}

// WithBodyJSON accepts an arbitrary data, marshals it into a JSON structure
// using json.Marshal, and sets the request body to it. Panics in case
// marshalling fails.
// See also: WithBody
func WithBodyJSON(data interface{}) RequestMutator {
	j, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	return WithBody(bytes.NewReader(j))
}

// WithForm takes a form represented by url.Values, encodes it, and sets it to
// the http.Request body.
// Changes the request method to POST in case it is not set or set to GET, and
// defines Content-Type to application/x-www-form-urlencoded.
// See also: WithBody
func WithForm(form url.Values) RequestMutator {
	return func(r *http.Request) *http.Request {
		nr := CloneRequest(r)
		str := form.Encode()
		nr.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		nr.Header.Add("Content-Length", strconv.Itoa(len(str)))
		if nr.Method == "" || nr.Method == "GET" {
			nr.Method = "POST"
		}
		nr.Body = ioutil.NopCloser(bytes.NewReader([]byte(str)))
		return nr
	}
}

// WithQueryString sets the provided url.Values as the request RawQuery field
// after encoding it.
func WithQueryString(query url.Values) RequestMutator {
	return func(r *http.Request) *http.Request {
		nr := CloneRequest(r)
		nr.URL.RawQuery = query.Encode()
		return nr
	}
}

// WithHeader sets a given HTTP header of the request to the provided key and
// value pair.
func WithHeader(key, value string) RequestMutator {
	return func(r *http.Request) *http.Request {
		nr := CloneRequest(r)
		nr.Header.Add(key, value)
		return nr
	}
}

// PrepareRequest takes an HTTP request instance and a set of mutators, applying
// them to it and returning a new request with all mutations applied.
func PrepareRequest(req *http.Request, mutators ...RequestMutator) *http.Request {
	if len(mutators) == 0 {
		return req
	}

	for _, fn := range mutators {
		req = fn(req)
	}

	return req
}

var src = rand.NewSource(time.Now().UnixNano())

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func unsafeRandomStringWithSize(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return *(*string)(unsafe.Pointer(&b))
}

// EmptyRequestHandler returns an http.Handler that simply returns 200, without
// a body
func EmptyRequestHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
}

// PassThroughRequestHandler returns an assertion function and an HTTP handler.
// After applying a request to the handler, the response can be tested by the
// returned assertion function, as to ensure that a response contains the body
// and header generated randomly by the handler.
//
// For instance:
// 		assertion, handler := test.PassThroughRequestHandler()
//		resp := test.ExecuteMiddlewareWithRequest(
//			test.EmptyRequest(),
//			handler,
//			ARandomMiddleware{})
//		assertion(t, resp)
//
func PassThroughRequestHandler() (func(*testing.T, *http.Response), http.Handler) {
	body := unsafeRandomStringWithSize(128)
	headerName := unsafeRandomStringWithSize(12)
	headerValue := unsafeRandomStringWithSize(64)
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add(headerName, headerValue)
		_, err := w.Write([]byte(body))
		if err != nil {
			panic(err)
		}
	}

	return func(t *testing.T, response *http.Response) {
		assert.Equal(t, headerValue, response.Header.Get(headerName))
		allBytes, err := ioutil.ReadAll(response.Body)
		assert.Nil(t, err)
		assert.Equal(t, body, string(allBytes))
	}, http.HandlerFunc(handler)
}

// ExecuteMiddlewareWithRequest takes an HTTP request, a base handler (your
// controller's action handler, for instance), and a set of middlewares to
// process the request, returning the response generated by applying the
// provided request through all middlewares and the provided base handler.
func ExecuteMiddlewareWithRequest(r *http.Request, baseHandler http.Handler, middlewares ...func(http.Handler) http.Handler) *http.Response {
	rec := httptest.NewRecorder()
	var h http.Handler
	if len(middlewares) == 0 {
		h = baseHandler
	} else {
		// Wrap the baseHandler handler with the middleware chain
		h = middlewares[len(middlewares)-1](baseHandler)
		for i := len(middlewares) - 2; i >= 0; i-- {
			h = middlewares[i](h)
		}
	}

	// Then, run the complete chain
	h.ServeHTTP(rec, r)
	return rec.Result()
}

// EmptyRequest returns a dummy GET request to a "foo" endpoint, without a body.
// Useful for testing middlewares and handlers.
func EmptyRequest() *http.Request {
	r, _ := http.NewRequest("GET", "foo", nil)
	return r
}

// RequestInterceptorHandler provides a handler that returns an HTTP 200 with no
// body, and intercepts the request, storing a reference to it for later
// inspection.
func RequestInterceptorHandler() (handler http.Handler, capturedRequest *http.Request) {
	capturedRequest = &http.Request{}
	handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rv := reflect.ValueOf(capturedRequest)
		rv.Elem().Set(reflect.ValueOf(r).Elem())
		w.WriteHeader(200)
	})
	return
}

// ExecuteLogHandler takes a request and applies it to a handler that uses
// middleware.LoggerHandler
func ExecuteLogHandler(r *http.Request, handler func(http.ResponseWriter, *http.Request, *zap.Logger)) *http.Response {
	return ExecuteLogHandlerWithMiddlewares(r, handler)
}

// ExecuteLogHandlerWithMiddlewares takes a handler that uses
// middleware.LoggerHandler and an arbitrary number of middlewares and
// executes all of them.
func ExecuteLogHandlerWithMiddlewares(r *http.Request, handler func(http.ResponseWriter, *http.Request, *zap.Logger), middlewares ...func(http.Handler) http.Handler) *http.Response {
	l := zap.NewNop()
	baseHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(w, r, l)
	})

	rec := httptest.NewRecorder()
	var h http.Handler
	if len(middlewares) == 0 {
		h = baseHandler
	} else {
		// Wrap the baseHandler handler with the middleware chain
		h = middlewares[len(middlewares)-1](baseHandler)
		for i := len(middlewares) - 2; i >= 0; i-- {
			h = middlewares[i](h)
		}
	}

	// Then, run the complete chain
	h.ServeHTTP(rec, r)
	return rec.Result()
}

// JSONFromResponse attempts to unmarshal a given http.Response body into the
// provided interface. Panics if reading the body or unmarshalling fails.
func JSONFromResponse(r *http.Response, into interface{}) {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(b, into)
	if err != nil {
		panic(err)
	}
}

// ExecuteRequest simply executes the handler with a given http.Request and
// returns its response.
func ExecuteRequest(req *http.Request, handler func(w http.ResponseWriter, r *http.Request)) *http.Response {
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec.Result()
}
