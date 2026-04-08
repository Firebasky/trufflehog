package hunyuan

import (
	"bytes"
	"fmt"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"io"
	"net/http"
	"strings"
)

import (
	"context"
	"encoding/json"
	regexp "github.com/wasilibs/go-re2"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

type ChatRequest struct {
	Model             string        `json:"model"`
	Messages          []ChatMessage `json:"messages"`
	EnableEnhancement bool          `json:"enable_enhancement"`
}

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

const HunYuanURL = "https://api.hunyuan.cloud.tencent.com/v1/chat/completions"

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	defaultClient = common.SaneHttpClient()

	SKToken = regexp.MustCompile(`\b(sk-[a-z0-9A-Z]{48})[\"';\s]*`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sk-", "hunyuan", "HUNYUAN_API_KEY"}
}

func (s Scanner) Description() string {
	return "hunyuan sk token"
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Alibaba secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := SKToken.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		tokenMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_HunYuan,
			Raw:          []byte(tokenMatch),
		}

		if verify {
			client := s.getClient()
			isVerified, extraData, verificationErr := verifyBaiLian(ctx, client, tokenMatch)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, tokenMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyBaiLian(ctx context.Context, client *http.Client, tokenMatch string) (bool, map[string]string, error) {
	body := ChatRequest{
		Model: "hunyuan-turbos-latest",
		Messages: []ChatMessage{
			{
				Role:    "user",
				Content: "hello",
			},
		},
		EnableEnhancement: true,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return false, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, HunYuanURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return false, nil, err
	}
	req.Header.Add("Authorization", "Bearer "+tokenMatch)
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36")
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer res.Body.Close()

	respBody, err := io.ReadAll(res.Body)
	if err != nil {
		return false, nil, err
	}
	if strings.Contains(string(respBody), "Incorrect API key provided") {
		return false, nil, err
	}
	switch res.StatusCode {
	case http.StatusOK:
		return true, nil, nil
	case http.StatusNotFound:
		return false, nil, nil
	default:
		err := fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
		return false, nil, err
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_HunYuan
}
