package baiduapikey

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

type RequestBody struct {
	AppID string `json:"app_id"`
}

const BaiduApiKeyURL = "https://qianfan.baidubce.com/v2/app/conversation"

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	defaultClient = common.SaneHttpClient()

	apikey = regexp.MustCompile(`\b(bce-v3/ALTAK-[0-9a-zA-Z]{21}/[0-9a-z]{40})[\"';\s]*`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"qianfan", "ALTAK", "bce-v3"}
}

func (s Scanner) Description() string {
	return "baidu api key(qianfan)"
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

	matches := apikey.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		tokenMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_BaiduApiKey,
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
		AppID: "1",
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return false, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, BaiduApiKeyURL, bytes.NewBuffer(jsonBody))
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
	if strings.Contains(string(respBody), "Fail to authn apikey") {
		return false, nil, err
	}
	switch res.StatusCode {
	case http.StatusBadRequest:
		return true, nil, nil
	default:
		err := fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
		return false, nil, err
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_BaiduApiKey
}
