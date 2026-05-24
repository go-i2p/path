package ssu2path

// ListenerRef is an opaque reference to an SSU2Listener.
// It is stored by path types but not directly called.
// L-02 fix: GetAddr provides a minimal method so that wrong-type arguments
// are caught at compile time rather than silently accepted as interface{}.
type ListenerRef interface {
	GetAddr() string
}
