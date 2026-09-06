package api

// ctxKey is the private context key type for request-scoped values.
type ctxKey int

const requestIDKey ctxKey = iota
