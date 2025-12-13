package ethereumprivatekey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	// 有效的以太坊私钥示例 (带 0x 前缀)
	validKeyWithPrefix = "0x4c0883a69102937d6231471b5dbb6204fe512961708279f1d7b1b3b9e1a1e3d4"
	// 有效的以太坊私钥示例 (不带前缀)
	validKeyNoPrefix = "4c0883a69102937d6231471b5dbb6204fe512961708279f1d7b1b3b9e1a1e3d4"
	// 另一个有效私钥
	validKey2 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

	// 无效的私钥 - 全 0
	invalidKeyAllZero = "0x0000000000000000000000000000000000000000000000000000000000000000"
	// 无效的私钥 - 全 f
	invalidKeyAllF = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	// 无效的私钥 - 超出曲线阶
	invalidKeyTooLarge = "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"
	// 无效的私钥 - 重复模式
	invalidKeyRepeating = "0xabababababababababababababababababababababababababababababababab"
	// 无效的私钥 - 长度不对
	invalidKeyWrongLength = "0x4c0883a69102937d6231471b5dbb6204fe5129617"
)

func TestEthereumPrivateKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid key with 0x prefix",
			input: "private_key: " + validKeyWithPrefix,
			want:  []string{validKeyWithPrefix},
		},
		{
			name:  "valid key without prefix with context",
			input: "private_key=" + validKeyNoPrefix,
			want:  []string{"0x" + validKeyNoPrefix},
		},
		{
			name:  "valid key in JSON format",
			input: `{"privateKey": "` + validKeyNoPrefix + `"}`,
			want:  []string{"0x" + validKeyNoPrefix},
		},
		{
			name:  "valid key with eth_private context",
			input: "eth_private: " + validKeyNoPrefix,
			want:  []string{"0x" + validKeyNoPrefix},
		},
		{
			name:  "invalid key - all zeros",
			input: "private_key: " + invalidKeyAllZero,
			want:  nil,
		},
		{
			name:  "invalid key - all f",
			input: "private_key: " + invalidKeyAllF,
			want:  nil,
		},
		{
			name:  "invalid key - repeating pattern",
			input: "private_key: " + invalidKeyRepeating,
			want:  nil,
		},
		{
			name:  "multiple valid keys",
			input: "key1: " + validKeyWithPrefix + " key2: " + validKey2,
			want:  []string{validKeyWithPrefix, validKey2},
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

			for _, wantKey := range test.want {
				if _, ok := actual[wantKey]; !ok {
					t.Errorf("expected key %s not found in results", wantKey)
				}
			}
		})
	}
}

func TestEthereumPrivateKey_FromChunk(t *testing.T) {
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
			name:   "found key with prefix",
			data:   []byte("private_key = " + validKeyWithPrefix),
			verify: false,
			want: []detectors.Result{
				{
					DetectorType: d.Type(),
					Raw:          []byte(validKeyWithPrefix),
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name:   "found key with context",
			data:   []byte(`secret_key: "` + validKeyNoPrefix + `"`),
			verify: false,
			want: []detectors.Result{
				{
					DetectorType: d.Type(),
					Raw:          []byte("0x" + validKeyNoPrefix),
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name:    "not found - no context for bare hex",
			data:    []byte("some random text " + validKeyNoPrefix + " more text"),
			verify:  false,
			want:    nil,
			wantErr: false,
		},
		{
			name:    "not found - invalid key",
			data:    []byte("private_key: " + invalidKeyAllZero),
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

func TestIsValidEthPrivateKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want bool
	}{
		{
			name: "valid key with prefix",
			key:  validKeyWithPrefix,
			want: true,
		},
		{
			name: "valid key without prefix",
			key:  validKeyNoPrefix,
			want: true,
		},
		{
			name: "invalid - all zeros",
			key:  invalidKeyAllZero,
			want: false,
		},
		{
			name: "invalid - all f",
			key:  invalidKeyAllF,
			want: false,
		},
		{
			name: "invalid - exceeds curve order",
			key:  invalidKeyTooLarge,
			want: false,
		},
		{
			name: "invalid - wrong length",
			key:  invalidKeyWrongLength,
			want: false,
		},
		{
			name: "invalid - repeating pattern",
			key:  invalidKeyRepeating,
			want: false,
		},
		{
			name: "invalid - common test key",
			key:  "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidEthPrivateKey(tt.key)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("isValidEthPrivateKey() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIsSimplePattern(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want bool
	}{
		{
			name: "repeating single char",
			key:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			want: true,
		},
		{
			name: "repeating two chars",
			key:  "abababababababababababababababababababababababababababababababab",
			want: true,
		},
		{
			name: "deadbeef pattern",
			key:  "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			want: true,
		},
		{
			name: "valid random key",
			key:  "4c0883a69102937d6231471b5dbb6204fe512961708279f1d7b1b3b9e1a1e3d4",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSimplePattern(tt.key)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("isSimplePattern() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestEthereumPrivateKey_Type(t *testing.T) {
	d := Scanner{}
	if d.Type().String() != "EthereumPrivateKey" {
		t.Errorf("Type() = %v, want EthereumPrivateKey", d.Type())
	}
}

func TestEthereumPrivateKey_Keywords(t *testing.T) {
	d := Scanner{}
	keywords := d.Keywords()
	if len(keywords) == 0 {
		t.Error("Keywords() should return at least one keyword")
	}

	// 检查是否包含关键的关键词
	expectedKeywords := []string{"private_key", "0x", "eth_private"}
	for _, expected := range expectedKeywords {
		found := false
		for _, kw := range keywords {
			if kw == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Keywords() should contain %s", expected)
		}
	}
}

func TestEthereumPrivateKey_Description(t *testing.T) {
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
	data := []byte("private_key: " + validKeyWithPrefix + " another_key: " + validKey2)

	for n := 0; n < b.N; n++ {
		_, _ = s.FromData(ctx, false, data)
	}
}

// TestRealWorldExamples 测试真实世界中可能出现的格式
func TestRealWorldExamples(t *testing.T) {
	d := Scanner{}
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantKeys int
	}{
		{
			name:     "env file format",
			input:    `PRIVATE_KEY=0x4c0883a69102937d6231471b5dbb6204fe512961708279f1d7b1b3b9e1a1e3d4`,
			wantKeys: 1,
		},
		{
			name:     "JSON config",
			input:    `{"wallet": {"privateKey": "4c0883a69102937d6231471b5dbb6204fe512961708279f1d7b1b3b9e1a1e3d4"}}`,
			wantKeys: 1,
		},
		{
			name:     "YAML config",
			input:    `private_key: "0x4c0883a69102937d6231471b5dbb6204fe512961708279f1d7b1b3b9e1a1e3d4"`,
			wantKeys: 1,
		},
		{
			name:     "JavaScript/TypeScript",
			input:    `const privateKey = "0x4c0883a69102937d6231471b5dbb6204fe512961708279f1d7b1b3b9e1a1e3d4";`,
			wantKeys: 1,
		},
		{
			name:     "Python",
			input:    `private_key = "0x4c0883a69102937d6231471b5dbb6204fe512961708279f1d7b1b3b9e1a1e3d4"`,
			wantKeys: 1,
		},
		{
			name:     "Hardhat config style",
			input:    `accounts: ["0x4c0883a69102937d6231471b5dbb6204fe512961708279f1d7b1b3b9e1a1e3d4"]`,
			wantKeys: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := d.FromData(ctx, false, []byte(tt.input))
			if err != nil {
				t.Errorf("FromData() error = %v", err)
				return
			}
			if len(results) != tt.wantKeys {
				t.Errorf("FromData() got %d keys, want %d", len(results), tt.wantKeys)
			}
		})
	}
}
