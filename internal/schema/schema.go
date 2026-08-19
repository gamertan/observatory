// SPDX-License-Identifier: AGPL-3.0-only

package schema

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"gamertan.com/observatory/internal/model"
)

const DescriptorVersion = 1

type Type string
type Sensitivity string
type Cardinality string
type IndexPolicy string
type RetentionClass string

const (
	TypeString   Type = "string"
	TypeInteger  Type = "integer"
	TypeFloat    Type = "float"
	TypeBoolean  Type = "boolean"
	TypeDuration Type = "duration"
	TypeTime     Type = "time"

	SensitivityPublic    Sensitivity = "public"
	SensitivityInternal  Sensitivity = "internal"
	SensitivitySensitive Sensitivity = "sensitive"

	CardinalityLow    Cardinality = "low"
	CardinalityMedium Cardinality = "medium"
	CardinalityHigh   Cardinality = "high"

	IndexNone  IndexPolicy = "none"
	IndexExact IndexPolicy = "exact"
	IndexRange IndexPolicy = "range"

	RetentionRaw      RetentionClass = "raw"
	RetentionMetric   RetentionClass = "metric"
	RetentionEvidence RetentionClass = "evidence"
)

var fieldPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.]{0,127}$`)
var unitPattern = regexp.MustCompile(`^[A-Za-z0-9%/._-]{0,64}$`)

type Descriptor struct {
	Version           int            `json:"version"`
	Signal            model.Signal   `json:"signal"`
	Field             string         `json:"field"`
	Type              Type           `json:"type"`
	Unit              string         `json:"unit,omitempty"`
	Meaning           string         `json:"meaning"`
	Sensitivity       Sensitivity    `json:"sensitivity"`
	Cardinality       Cardinality    `json:"cardinality"`
	Index             IndexPolicy    `json:"index"`
	Retention         RetentionClass `json:"retention"`
	ProjectionVersion int            `json:"projection_version"`
}

type Proposal struct {
	Descriptor     Descriptor `json:"descriptor"`
	ObservedValues int64      `json:"observed_values"`
	EstimatedBytes int64      `json:"estimated_bytes"`
	ExampleQueries []string   `json:"example_queries"`
}

func (d Descriptor) Validate() error {
	if d.Version != DescriptorVersion || !validSignal(d.Signal) || !fieldPattern.MatchString(d.Field) || !unitPattern.MatchString(d.Unit) {
		return errors.New("descriptor identity is invalid")
	}
	switch d.Type {
	case TypeString, TypeInteger, TypeFloat, TypeBoolean, TypeDuration, TypeTime:
	default:
		return errors.New("descriptor type is invalid")
	}
	if len(d.Meaning) < 1 || len(d.Meaning) > 512 || strings.IndexByte(d.Meaning, 0) >= 0 {
		return errors.New("descriptor meaning is invalid")
	}
	switch d.Sensitivity {
	case SensitivityPublic, SensitivityInternal, SensitivitySensitive:
	default:
		return errors.New("descriptor sensitivity is invalid")
	}
	switch d.Cardinality {
	case CardinalityLow, CardinalityMedium, CardinalityHigh:
	default:
		return errors.New("descriptor cardinality is invalid")
	}
	switch d.Index {
	case IndexNone, IndexExact, IndexRange:
	default:
		return errors.New("descriptor index policy is invalid")
	}
	if d.Cardinality == CardinalityHigh && d.Index == IndexExact {
		return errors.New("high-cardinality exact indexes require a reviewed exception")
	}
	switch d.Retention {
	case RetentionRaw, RetentionMetric, RetentionEvidence:
	default:
		return errors.New("descriptor retention class is invalid")
	}
	if d.ProjectionVersion < 1 {
		return errors.New("projection version must be positive")
	}
	return nil
}

func (p Proposal) Validate() error {
	if err := p.Descriptor.Validate(); err != nil {
		return err
	}
	if p.ObservedValues < 1 || p.EstimatedBytes < 0 || len(p.ExampleQueries) > 16 {
		return errors.New("proposal evidence is invalid")
	}
	for _, example := range p.ExampleQueries {
		if len(example) < 1 || len(example) > 4096 || strings.IndexByte(example, 0) >= 0 {
			return fmt.Errorf("proposal example query is invalid")
		}
	}
	return nil
}

func Unknown(signal model.Signal, field string) Descriptor {
	return Descriptor{Version: DescriptorVersion, Signal: signal, Field: field, Type: TypeString, Meaning: "Unreviewed field retained in raw evidence.", Sensitivity: SensitivitySensitive, Cardinality: CardinalityHigh, Index: IndexNone, Retention: RetentionRaw, ProjectionVersion: 1}
}

func validSignal(signal model.Signal) bool {
	switch signal {
	case model.SignalLogs, model.SignalMetrics, model.SignalTraces, model.SignalDeployments:
		return true
	default:
		return false
	}
}
