package dingdoc

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

type dingResp struct {
	Status    int      `json:"status"`
	IsSuccess bool     `json:"isSuccess"`
	Data      dingData `json:"data"`
	Message   string   `json:"message,omitempty"` // 如果有 message 字段的话
	Code      string   `json:"code,omitempty"`    // 如果有 code 字段的话
}

type dingData struct {
	AliDingtalk        bool   `json:"aliDingtalk"`
	AvatarMediaId      string `json:"avatarMediaId"`
	DesensitizedMobile string `json:"desensitizedMobile"`
	IsDingTalkVip      bool   `json:"isDingTalkVip"`
	MobileShortCode    string `json:"mobileShortCode"`
	Name               string `json:"name"`
	Uid                string `json:"uid"`
}

const DingdocURL = "https://alidocs.dingtalk.com/portal/api/v1/mine/info"

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	defaultClient = common.SaneHttpClient()

	AToken = regexp.MustCompile(`\b(Mz[a-zA-Z0-9]{42})[\"';\s]*`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"Mz"}
}

func (s Scanner) Description() string {
	return "dingding doc A-Token"
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

	matches := AToken.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		tokenMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_DingDoc,
			Raw:          []byte(tokenMatch),
		}

		if verify {
			client := s.getClient()
			isVerified, extraData, verificationErr := verifyDingDoc(ctx, client, tokenMatch)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, tokenMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyDingDoc(ctx context.Context, client *http.Client, tokenMatch string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, DingdocURL, nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Add("A-Token", tokenMatch)

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer res.Body.Close()

	var dingResp dingResp
	if err = json.NewDecoder(res.Body).Decode(&dingResp); err != nil {
		return false, nil, err
	}
	switch res.StatusCode {
	case http.StatusOK:
		extraData := map[string]string{
			"desensitizedMobile": dingResp.Data.DesensitizedMobile,
			"uid":                dingResp.Data.Uid,
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
	return detector_typepb.DetectorType_DingDoc
}
