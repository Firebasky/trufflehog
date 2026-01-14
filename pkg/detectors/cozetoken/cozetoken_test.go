package cozetoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestCozeToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid personal access token",
			input: `
				Coze Configuration
				API Token: pat_FzBqdi0lAvXGnM6GgS6hGbeV8JgQxSo6F8Obj5fcTG3Rde3dRC8rV7j4M4SieKQ2
				
				Please keep this token secure and do not expose it in public repositories.
			`,
			want: []string{
				"pat_FzBqdi0lAvXGnM6GgS6hGbeV8JgQxSo6F8Obj5fcTG3Rde3dRC8rV7j4M4SieKQ2",
			},
		},
		{
			name: "valid service access token",
			input: `
				Service Configuration
				COZE_TOKEN=sat_mO11PyjC5F82xSCchtx2hvlGn74Htf8z9HyO9Ig2ERlic2j2LXusPR1FhzibuhAG
			`,
			want: []string{
				"sat_mO11PyjC5F82xSCchtx2hvlGn74Htf8z9HyO9Ig2ERlic2j2LXusPR1FhzibuhAG",
			},
		},
		{
			name: "multiple tokens",
			input: `
				# Development tokens
				DEV_TOKEN=pat_FzBqdi0lAvXGnM6GgS6hGbeV8JgQxSo6F8Obj5fcTG3Rde3dRC8rV7j4M4SieKQ2
				
				# Production tokens
				PROD_TOKEN=sat_mO11PyjC5F82xSCchtx2hvlGn74Htf8z9HyO9Ig2ERlic2j2LXusPR1FhzibuhAG
			`,
			want: []string{
				"pat_FzBqdi0lAvXGnM6GgS6hGbeV8JgQxSo6F8Obj5fcTG3Rde3dRC8rV7j4M4SieKQ2",
				"sat_mO11PyjC5F82xSCchtx2hvlGn74Htf8z9HyO9Ig2ERlic2j2LXusPR1FhzibuhAG",
			},
		},
		{
			name: "token in JSON config",
			input: `
				{
					"coze": {
						"api_token": "pat_FzBqdi0lAvXGnM6GgS6hGbeV8JgQxSo6F8Obj5fcTG3Rde3dRC8rV7j4M4SieKQ2"
					}
				}
			`,
			want: []string{
				"pat_FzBqdi0lAvXGnM6GgS6hGbeV8JgQxSo6F8Obj5fcTG3Rde3dRC8rV7j4M4SieKQ2",
			},
		},
		{
			name: "invalid token - too short",
			input: `
				Invalid token: pat_abc123
			`,
			want: nil,
		},
		{
			name: "invalid token - wrong prefix",
			input: `
				Invalid token: tok_FzBqdi0lAvXGnM6GgS6hGbeV8JgQxSo6F8Obj5fcTG3Rde3dRC8rV7j4M4SieKQ2
			`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) == 0 && len(matchedDetectors) == 0 {
				return
			}
			if len(matchedDetectors) == 0 {
				t.Errorf("test %q failed: expected keywords %v to be found in the input", test.name, d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("mismatch in result count: expected %d, got %d", len(test.want), len(results))
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}

			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}

