package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	// See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_effect.html
	EffectAllow = "Allow"
	EffectDeny  = "Deny"

	// See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html
	Version2012_10_17 = "2012-10-17"
	Version2008_10_17 = "2008-10-17"
	VersionLatest     = Version2012_10_17

	ErrorInvalidStatementSlice   = "StatementOrSlice is not a slice of statements"
	ErrorInvalidStatementOrSlice = "StatementOrSlice must be a single Statement or a slice of Statements"
)

// Policy is a policy document.
type Policy struct {
	Id         string            `json:"Id,omitempty"`
	Statements *StatementOrSlice `json:"Statement"`
	Version    string            `json:"Version"`
}

// Statement is a single statement in a policy document.
type Statement struct {
	Action       *StringOrSlice                        `json:"Action,omitempty"`
	Condition    map[string]map[string]*ConditionValue `json:"Condition,omitempty"`
	Effect       string                                `json:"Effect"`
	NotAction    *StringOrSlice                        `json:"NotAction,omitempty"`
	NotResource  *StringOrSlice                        `json:"NotResource,omitempty"`
	Principal    *Principal                            `json:"Principal,omitempty"`
	NotPrincipal *Principal                            `json:"NotPrincipal,omitempty"`
	Resource     *StringOrSlice                        `json:"Resource,omitempty"`
	Sid          string                                `json:"Sid,omitempty"`
}

func equalCondition(a, b map[string]map[string]*ConditionValue) bool {
	if len(a) != len(b) {
		return false
	}
	for k1, v1 := range a {
		// check if the key exists in b and if the values have the same length. If
		// the length is different, drop out early.
		v1b, ok := b[k1]
		if !ok || len(v1b) != len(v1) {
			return false
		}
		// now the length is the same, check if the values are the same.
		for k2, v2 := range v1 {
			v2b, ok := v1b[k2]
			if !ok || !v2.Equal(v2b) {
				return false
			}
		}
	}
	return true
}

// Equal returns true if the Statement is equal to the other Statement.
func (s *Statement) Equal(other *Statement) bool {
	if s == nil || other == nil {
		return s == other
	}

	// check simple string fields first
	if s.Effect != other.Effect || s.Sid != other.Sid {
		return false
	}

	return s.Action.Equal(other.Action) &&
		s.NotAction.Equal(other.NotAction) &&
		s.NotResource.Equal(other.NotResource) &&
		s.Principal.Equal(other.Principal) &&
		s.NotPrincipal.Equal(other.NotPrincipal) &&
		s.Resource.Equal(other.Resource) &&
		equalCondition(s.Condition, other.Condition)
}

// StatementOrSlice represents Statements that can be marshaled to a single Statement or a slice of Statements.
type StatementOrSlice struct {
	values   []Statement
	singular bool
}

// NewSingularStatementOrSlice creates a new StatementOrSlice with a single Statement.
func NewSingularStatementOrSlice(statements Statement) *StatementOrSlice {
	return &StatementOrSlice{
		values:   []Statement{statements},
		singular: true,
	}
}

// NewStatementOrSlice creates a new StatementOrSlice with a slice of Statements.
func NewStatementOrSlice(statements ...Statement) *StatementOrSlice {
	return &StatementOrSlice{
		values:   statements,
		singular: false,
	}
}

// ConditionValue is a value in a condition statement.
func (s *StatementOrSlice) Add(statements ...Statement) {
	s.values = append(s.values, statements...)
	if len(s.values) > 1 {
		s.singular = false
	}
}

func (s *StatementOrSlice) UnmarshalJSON(data []byte) error {
	var tmp interface{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	_, ok := tmp.([]interface{})
	if ok {
		// TODO: can we avoid strict decoding and defer to the outer
		values := []Statement{}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&values)
		if err != nil {
			return fmt.Errorf("%s: %v", ErrorInvalidStatementSlice, err)

		}
		s.values = values
		s.singular = false
		return nil
	}
	_, ok = tmp.(map[string]interface{})
	if ok {
		value := Statement{}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&value)
		if err != nil {
			return fmt.Errorf("%s: %v", ErrorInvalidStatementOrSlice, err)
		}
		s.values = []Statement{value}
		s.singular = false
		return nil
	}
	return errors.New(ErrorInvalidStatementOrSlice)
}

func (s *StatementOrSlice) MarshalJSON() ([]byte, error) {
	buf := bytes.Buffer{}
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)

	if s.singular && len(s.values) == 1 {
		err := enc.Encode(s.values[0])
		return []byte(strings.TrimSpace(buf.String())), err
	}
	err := enc.Encode(s.values)
	return []byte(strings.TrimSpace(buf.String())), err
}

// Values returns the statement values of the StatementOrSlice.
func (s *StatementOrSlice) Values() []Statement {
	return s.values
}

// Singular returns true if the StatementOrSlice is a single Statement.
func (s *StatementOrSlice) Singular() bool {
	return s.singular
}
