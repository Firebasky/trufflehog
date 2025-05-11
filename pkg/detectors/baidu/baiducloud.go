package baidu

import (
	"github.com/baidubce/bce-sdk-go/services/bcc"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"net/http"
	"strings"
)

import (
	"context"
	regexp "github.com/wasilibs/go-re2"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey []byte
}

type BaiduResp struct {
	RequestId string `json:"RequestId"`
	Message   string `json:"Message"`
	Recommend string `json:"Recommend"`
	HostId    string `json:"HostId"`
	Code      string `json:"Code"`
}

const BaiduURL = "http://bcc.bj.baidubce.com/v2/zone"

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`)
	idPat  = regexp.MustCompile(`\b(ALTAK[a-zA-Z0-9]{17,21})[\"';\s]*`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"ALTAK"}
}

func (s Scanner) Description() string {
	return "baidu cloud ak/sk"
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify baidu secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {

			resIdMatch := strings.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Baidu,
				Raw:          []byte(resIdMatch + ":" + resMatch),
				RawV2:        []byte(resMatch),
			}

			if verify {
				client := s.getClient()
				isVerified, verificationErr := verifyBaidu(ctx, client, resIdMatch, resMatch)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, resMatch)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyBaidu(ctx context.Context, client *http.Client, resIdMatch, resMatch string) (bool, error) {
	AK, SK := resIdMatch, resMatch
	ENDPOINT := "bcc.bj.baidubce.com"
	bccClient, err := bcc.NewClient(AK, SK, ENDPOINT)
	_, err = bccClient.ListZone()
	if err != nil {
		if strings.Contains(err.Error(), "IamSignatureInvalid") {
			return false, nil
		}
		return true, nil
	} else {
		return true, nil
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Baidu
}
