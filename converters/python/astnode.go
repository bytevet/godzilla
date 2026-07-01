package py_converter

// astNode is a JSON object decoded from pyast.py's output. It is kept as a
// generic map (rather than a fixed struct per node kind) because the JSON
// schema is a tagged union over ~20 statement/expression kinds; a generic
// accessor layer is far less code than one struct + custom unmarshaler per
// kind, and this converter only reads a handful of fields per kind anyway.
// See pyast.py's module docstring for the authoritative schema.
type astNode map[string]any

func (n astNode) kind() string {
	if n == nil {
		return ""
	}
	s, _ := n["kind"].(string)
	return s
}

func (n astNode) str(key string) string {
	if n == nil {
		return ""
	}
	s, _ := n[key].(string)
	return s
}

// node returns the child value at key as an astNode, or nil if absent/null/
// not an object.
func (n astNode) node(key string) astNode {
	if n == nil {
		return nil
	}
	v, ok := n[key]
	if !ok || v == nil {
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return astNode(m)
}

// list returns the child value at key as a slice of astNode, skipping
// non-object entries (e.g. a stray null).
func (n astNode) list(key string) []astNode {
	if n == nil {
		return nil
	}
	v, ok := n[key]
	if !ok || v == nil {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]astNode, 0, len(arr))
	for _, item := range arr {
		if m, ok := item.(map[string]any); ok {
			out = append(out, astNode(m))
		} else {
			out = append(out, nil)
		}
	}
	return out
}

// strList returns the child value at key as a slice of strings (used for
// FunctionDef.params).
func (n astNode) strList(key string) []string {
	if n == nil {
		return nil
	}
	v, ok := n[key]
	if !ok || v == nil {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// raw returns the raw decoded JSON value at key (used for Constant.value,
// which may be a bool/json.Number/string/nil depending on value_type).
func (n astNode) raw(key string) any {
	if n == nil {
		return nil
	}
	return n[key]
}
