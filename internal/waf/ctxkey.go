package waf

import "context"

type ctxKey int

const (
	ctxKeyRequestContext ctxKey = iota
)

// NewContext returns a new context with the given RequestContext.
func NewContext(ctx context.Context, rc *RequestContext) context.Context {
	return context.WithValue(ctx, ctxKeyRequestContext, rc)
}

// FromContext returns the RequestContext from the context, or nil.
func FromContext(ctx context.Context) *RequestContext {
	rc, _ := ctx.Value(ctxKeyRequestContext).(*RequestContext)
	return rc
}
