package pqsig

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const signatureMarker = "\nx-stackql-signature:\n"

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var documentEndPattern = regexp.MustCompile(`(?m)^\.\.\.[ \t]*(#[^\r\n]*)?\r?$`)

// Validate checks that an unsigned payload can carry the signature's final
// top-level YAML field. Values, aliases, numbers and formatting are not rewritten.
func Validate(data []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return fmt.Errorf("pqsig: decode document: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("pqsig: multiple YAML documents are not permitted")
		}
		return fmt.Errorf("pqsig: trailing document: %w", err)
	}
	if len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode ||
		root.Content[0].Style&yaml.FlowStyle != 0 {
		return fmt.Errorf("pqsig: document must be a block-style YAML mapping")
	}
	if documentEndPattern.Match(data) {
		return fmt.Errorf("pqsig: explicit YAML document-end markers are not permitted")
	}
	for i := 0; i < len(root.Content[0].Content); i += 2 {
		key := root.Content[0].Content[i]
		if key.Value == SignatureField {
			return fmt.Errorf("pqsig: reserved top-level %s outside the signature frame", SignatureField)
		}
	}
	return nil
}

func splitSignature(doc []byte) (payload []byte, kid, signature string, err error) {
	index := bytes.LastIndex(doc, []byte(signatureMarker))
	if index < 0 {
		return nil, "", "", fmt.Errorf("pqsig: missing or invalid %s frame", SignatureField)
	}
	lines := strings.Split(string(doc[index+len(signatureMarker):]), "\n")
	if len(lines) != 6 || lines[0] != "  format: raw-v1" ||
		lines[1] != "  alg: "+Algorithm || lines[5] != "" || lines[4] != "  end: stackql-provider-signature" {
		return nil, "", "", fmt.Errorf("pqsig: invalid signature frame or unsupported format/algorithm")
	}
	kid, ok := strings.CutPrefix(lines[2], "  kid: ")
	if !ok || !keyIDPattern.MatchString(kid) {
		return nil, "", "", fmt.Errorf("pqsig: invalid signature key ID")
	}
	signature, ok = strings.CutPrefix(lines[3], "  sig: ")
	if !ok {
		return nil, "", "", fmt.Errorf("pqsig: invalid signature frame")
	}
	return doc[:index], kid, signature, nil
}
