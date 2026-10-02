package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"go.yaml.in/yaml/v3"
)

// Definitions (plugins, apps, stacks, host configs) are written in YAML or JSON with the same
// schema and the same rules: YAML is converted to JSON first, then every format is decoded
// strictly (an unknown field is an error, so a typo never silently drops a setting).

// ToJSON returns data as JSON: JSON is returned as is, YAML (one document) is converted.
func ToJSON(data []byte) ([]byte, error) {
	t := bytes.TrimSpace(data)
	if len(t) > 0 && (t[0] == '{' || t[0] == '[') {
		return data, nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("yaml: one document per file")
	}
	v, err := jsonable(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// jsonable rejects what JSON can't represent (non-string keys) and keeps timestamps as text.
func jsonable(v any) (any, error) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			c, err := jsonable(e)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			x[k] = c
		}
		return x, nil
	case map[any]any:
		return nil, fmt.Errorf("mapping keys must be strings")
	case []any:
		for i, e := range x {
			c, err := jsonable(e)
			if err != nil {
				return nil, err
			}
			x[i] = c
		}
		return x, nil
	case time.Time:
		return x.Format(time.RFC3339), nil
	}
	return v, nil
}

// DecodeStrict decodes YAML or JSON into v, rejecting unknown fields and trailing data.
func DecodeStrict(data []byte, v any) error {
	j, err := ToJSON(data)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(j))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("unexpected data after the definition")
	}
	return nil
}

// Kind tells what a definition is from its shape: "stack" (a top-level stack name and apps),
// "host" (a top-level host section), "app" (components) or "plugin".
func Kind(data []byte) (string, error) {
	j, err := ToJSON(data)
	if err != nil {
		return "", err
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(j, &probe); err != nil {
		return "", fmt.Errorf("not a definition: %w", err)
	}
	switch {
	case probe["stack"] != nil:
		return "stack", nil
	case probe["host"] != nil:
		return "host", nil
	case probe["components"] != nil:
		return "app", nil
	}
	return "plugin", nil
}

// ToYAML renders v (via its JSON form, so field names and order follow the schema) as block YAML.
func ToYAML(v any) ([]byte, error) {
	j, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var n yaml.Node
	if err := yaml.Unmarshal(j, &n); err != nil {
		return nil, err
	}
	var block func(*yaml.Node)
	block = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode {
			n.Style = 0
		} else if n.Kind == yaml.ScalarNode && n.Style == yaml.DoubleQuotedStyle && n.Tag == "!!str" {
			n.Style = 0 // quoted only where YAML needs it
		}
		for _, c := range n.Content {
			block(c)
		}
	}
	block(&n)
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(&n); err != nil {
		return nil, err
	}
	return b.Bytes(), enc.Close()
}
