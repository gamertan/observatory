// SPDX-License-Identifier: AGPL-3.0-only

package schema

import (
	"testing"

	"gamertan.com/observatory/internal/model"
)

func TestUnknownFieldsAreSensitiveAndUnindexed(t *testing.T) {
	descriptor := Unknown(model.SignalLogs, "vendor.unreviewed")
	if err := descriptor.Validate(); err != nil {
		t.Fatal(err)
	}
	if descriptor.Sensitivity != SensitivitySensitive || descriptor.Index != IndexNone || descriptor.Cardinality != CardinalityHigh {
		t.Fatalf("descriptor=%+v", descriptor)
	}
}

func TestDescriptorRejectsHighCardinalityExactIndex(t *testing.T) {
	descriptor := Descriptor{Version: 1, Signal: model.SignalLogs, Field: "request.id", Type: TypeString, Meaning: "A request correlation identifier.", Sensitivity: SensitivityInternal, Cardinality: CardinalityHigh, Index: IndexExact, Retention: RetentionRaw, ProjectionVersion: 1}
	if err := descriptor.Validate(); err == nil {
		t.Fatal("expected unsafe index rejection")
	}
}
