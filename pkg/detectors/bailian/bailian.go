package bailian

import (
	"bytes"
	"fmt"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
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

type QwenResponse struct {
	Choices []struct {
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
		Index        int    `json:"index"`
		LogProbs     any    `json:"logprobs"` // 可能为 null 或更复杂结构
	} `json:"choices"`
	Object string `json:"object"`
	Usage  struct {
		PromptTokens        int `json:"prompt_tokens"`
		CompletionTokens    int `json:"completion_tokens"`
		TotalTokens         int `json:"total_tokens"`
		PromptTokensDetails struct {
			CachedTokens int `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
	} `json:"usage"`
	Created           int64  `json:"created"`
	SystemFingerprint any    `json:"system_fingerprint"` // 可能为 null
	Model             string `json:"model"`
	ID                string `json:"id"`
}

type RequestBody struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

const BaiLianURL = "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	defaultClient = common.SaneHttpClient()

	SKToken = regexp.MustCompile(`\b(sk-(?:sp-)?[a-z0-9]{32})["';\s]*`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
// add
func (s Scanner) Keywords() []string {
	return []string{"sk-", "DASHSCOPE","sk-sp-"}
}

func (s Scanner) Description() string {
	return "aliyun bailian sk token"
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
			DetectorType: detectorspb.DetectorType_BaiLian,
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
	body := RequestBody{
		Model: "qwen-plus",
		Messages: []Message{
			{},
		},
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return false, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, BaiLianURL, bytes.NewBuffer(jsonBody))
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
	if strings.Contains(string(respBody), "invalid_api_key") {
		return false, nil, err
	}
	switch res.StatusCode {
	case http.StatusBadRequest:
		return true, nil, nil
	case http.StatusNotFound:
		return false, nil, nil
	default:
		err := fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
		return false, nil, err
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_BaiLian
}
