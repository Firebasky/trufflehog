package bitcoinwif

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	// 主网未压缩私钥 (以 5 开头，51 位)
	validUncompressedWIF = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
	// 主网压缩私钥 (以 L 开头，52 位)
	validCompressedWIFL = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1"
	// 主网压缩私钥 (以 K 开头，52 位)
	validCompressedWIFK = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"

	// 测试网私钥 (不应该被检测到)
	testnetWIF = "cQhxRVxkBpTrwUHZmnv5M7ZvPcgp4cZ8csnenAfFLyoFgEVvN8yy"

	// 无效的私钥
	invalidWIF = "invalid_wif_key"
)

func TestBitcoinWIF_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid uncompressed WIF",
			input: "private_key: " + validUncompressedWIF,
			want:  []string{validUncompressedWIF},
		},
		{
			name:  "valid compressed WIF (L)",
			input: "WIF=" + validCompressedWIFL,
			want:  []string{validCompressedWIFL},
		},
		{
			name:  "valid compressed WIF (K)",
			input: "secretkey: " + validCompressedWIFK,
			want:  []string{validCompressedWIFK},
		},
		{
			name:  "testnet WIF should not match",
			input: "private_key: " + testnetWIF,
			want:  nil,
		},
		{
			name:  "invalid WIF",
			input: "wif: " + invalidWIF,
			want:  nil,
		},
		{
			name:  "multiple WIFs",
			input: "key1: " + validUncompressedWIF + " key2: " + validCompressedWIFL,
			want:  []string{validUncompressedWIF, validCompressedWIFL},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 && len(test.want) > 0 {
				t.Errorf("no matches found, expected %d", len(test.want))
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				t.Errorf("expected %d results, got %d", len(test.want), len(results))
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				actual[string(r.Raw)] = struct{}{}
			}

			for _, wantWIF := range test.want {
				if _, ok := actual[wantWIF]; !ok {
					t.Errorf("expected WIF %s not found in results", wantWIF)
				}
			}
		})
	}
}

func TestBitcoinWIF_FromChunk(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := Scanner{}

	tests := []struct {
		name    string
		data    []byte
		verify  bool
		want    []detectors.Result
		wantErr bool
	}{
		{
			name:   "found uncompressed WIF",
			data:   []byte("private_key = " + validUncompressedWIF),
			verify: false,
			want: []detectors.Result{
				{
					DetectorType: d.Type(),
					Raw:          []byte(validUncompressedWIF),
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name:   "found compressed WIF",
			data:   []byte("WIF: " + validCompressedWIFL),
			verify: false,
			want: []detectors.Result{
				{
					DetectorType: d.Type(),
					Raw:          []byte(validCompressedWIFL),
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name:    "not found",
			data:    []byte("just some random text without any keys"),
			verify:  false,
			want:    nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := d.FromData(ctx, tt.verify, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("FromData() got %d results, want %d", len(got), len(tt.want))
				return
			}

			for i := range got {
				if string(got[i].Raw) != string(tt.want[i].Raw) {
					t.Errorf("FromData() Raw = %s, want %s", string(got[i].Raw), string(tt.want[i].Raw))
				}
				if got[i].DetectorType != tt.want[i].DetectorType {
					t.Errorf("FromData() DetectorType = %v, want %v", got[i].DetectorType, tt.want[i].DetectorType)
				}
			}
		})
	}
}

func TestBitcoinWIF_Type(t *testing.T) {
	d := Scanner{}
	if d.Type().String() != "BitcoinWIF" {
		t.Errorf("Type() = %v, want BitcoinWIF", d.Type())
	}
}

func TestBitcoinWIF_Keywords(t *testing.T) {
	d := Scanner{}
	keywords := d.Keywords()
	if len(keywords) == 0 {
		t.Error("Keywords() should return at least one keyword")
	}
}

func TestBitcoinWIF_Description(t *testing.T) {
	d := Scanner{}
	desc := d.Description()
	if desc == "" {
		t.Error("Description() should not be empty")
	}
}

// BenchmarkFromData 性能测试
func BenchmarkFromData(b *testing.B) {
	ctx := context.Background()
	s := Scanner{}
	data := []byte("private_key: " + validUncompressedWIF + " another_key: " + validCompressedWIFL)

	for n := 0; n < b.N; n++ {
		_, _ = s.FromData(ctx, false, data)
	}
}

func TestIsValidWIF(t *testing.T) {
	tests := []struct {
		name string
		wif  string
		want bool
	}{
		{
			name: "valid uncompressed (5 prefix, 51 chars)",
			wif:  validUncompressedWIF,
			want: true,
		},
		{
			name: "valid compressed L prefix (52 chars)",
			wif:  validCompressedWIFL,
			want: true,
		},
		{
			name: "valid compressed K prefix (52 chars)",
			wif:  validCompressedWIFK,
			want: true,
		},
		{
			name: "invalid - testnet (c prefix)",
			wif:  testnetWIF,
			want: false,
		},
		{
			name: "invalid - too short",
			wif:  "5HueCGU8rMjx",
			want: false,
		},
		{
			name: "invalid - wrong prefix",
			wif:  "1HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidWIF(tt.wif)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("isValidWIF() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
