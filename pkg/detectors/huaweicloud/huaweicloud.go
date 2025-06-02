package huaweicloud

import (
	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
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

const HuaweicloudURL = "https://obs.cn-north-4.myhuaweicloud.com"

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	idPat  = regexp.MustCompile(`\b([a-zA-Z0-9]{20})\b`)
	keyPat = regexp.MustCompile(`\b([a-zA-Z0-9]{40})[\"';\s]*`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"HPUA", "ak", "Access_Key_Id", "AccessKey"}
}

func (s Scanner) Description() string {
	return "Huawei cloud ak/sk"
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {

			resIdMatch := strings.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Huawei,
				Raw:          []byte(resIdMatch + ":" + resMatch),
				RawV2:        []byte(resMatch),
			}

			if verify {
				client := s.getClient()
				isVerified, verificationErr := verifyHuawei(ctx, client, resIdMatch, resMatch)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, resMatch)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyHuawei(ctx context.Context, client *http.Client, resIdMatch, resMatch string) (bool, error) {
	AK, SK := resIdMatch, resMatch
	obsClient, err := obs.New(AK, SK, HuaweicloudURL /*, obs.WithSecurityToken(securityToken)*/)
	if err != nil {
		return false, nil
	}
	input := &obs.ListBucketsInput{}
	input.QueryLocation = true
	input.BucketType = obs.OBJECT
	_, err = obsClient.ListBuckets(input)
	if err == nil {
		return true, nil
	}
	if obsError, ok := err.(obs.ObsError); ok {
		if strings.Contains(obsError.Error(), "InvalidAccessKeyId") {
			return false, nil
		}
		if strings.Contains(obsError.Error(), "SignatureDoesNotMatch") {
			return false, nil
		}
		return true, nil
	}
	return false, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Huawei
}
