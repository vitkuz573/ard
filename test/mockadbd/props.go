package mockadbd

import (
	"sort"
	"strings"
	"sync"
)

// Properties is an Android property store: a flat, string-valued map with the lookup
// rules getprop relies on.
//
// The pattern matters as much as the values. A single trailing dot is the documented way
// to ask "every property whose name starts with this", and code that shells out to getprop
// uses it constantly -- so a store that ignores it makes callers fall back to enumerating,
// which is how a simulator starts diverging from the thing it stands in for.
type Properties struct {
	mu     sync.RWMutex
	values map[string]string
}

// NewProperties returns a store seeded with a copy of defaults.
func NewProperties(defaults map[string]string) *Properties {
	p := &Properties{values: make(map[string]string, len(defaults))}
	for k, v := range defaults {
		p.values[k] = v
	}
	return p
}

// Get returns one value. An unset property reads as empty, the way Android does, rather
// than as an error: getprop on an unknown key prints nothing and exits zero.
func (p *Properties) Get(name string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.values[name]
}

// Has reports whether a property is set, which is different from being empty. Several
// system properties are meaningfully empty and callers check for presence.
func (p *Properties) Has(name string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.values[name]
	return ok
}

// Set stores a value.
func (p *Properties) Set(name, value string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.values[name] = value
}

// Unset removes a property.
func (p *Properties) Unset(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.values, name)
}

// List returns every property whose name begins with prefix, sorted.
//
// A trailing dot in the prefix is stripped first, because "ro." and "ro" must both mean
// "everything under ro" -- the dot is a query convention, not part of a property name.
func (p *Properties) List(prefix string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	needle := strings.TrimSuffix(prefix, ".")
	out := make([]string, 0, len(p.values))
	for k := range p.values {
		if needle == "" || strings.HasPrefix(k, needle) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// All returns every property as name=value, sorted by name.
func (p *Properties) All() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, 0, len(p.values))
	for k, v := range p.values {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// Len reports how many properties are set.
func (p *Properties) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.values)
}
