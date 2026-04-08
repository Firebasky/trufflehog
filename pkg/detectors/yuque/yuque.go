package yuque

import (
	"fmt"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
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

type yuqueResp struct {
	Data yuqueRespData `json:"data"`
}

type yuqueRespData struct {
	Message string `json:"message"`
}

const YuqueURL = "https://www.yuque.com/api/v2/hello"

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	defaultClient = common.SaneHttpClient()

	AAuthToken = regexp.MustCompile(`\b([a-zA-Z0-9]{40})[\"';\s]*`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"yuque", "X-Auth-Token"}
}

func (s Scanner) Description() string {
	return "yuque doc X-Auth-Token"
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

	matches := AAuthToken.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		tokenMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_YuQue,
			Raw:          []byte(tokenMatch),
		}

		if verify {
			client := s.getClient()
			isVerified, extraData, verificationErr := verifyYuQue(ctx, client, tokenMatch)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, tokenMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyYuQue(ctx context.Context, client *http.Client, tokenMatch string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, YuqueURL, nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Add("X-Auth-Token", tokenMatch)
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36")

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer res.Body.Close()

	var yuqueResp yuqueResp
	if err = json.NewDecoder(res.Body).Decode(&yuqueResp); err != nil {
		return false, nil, err
	}
	switch res.StatusCode {
	case http.StatusOK:
		extraData := map[string]string{
			"message": yuqueResp.Data.Message,
		}
		return true, extraData, nil
	case http.StatusNotFound, http.StatusBadRequest:
		return false, nil, nil
	default:
		err := fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
		return false, nil, err
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_YuQue
}
