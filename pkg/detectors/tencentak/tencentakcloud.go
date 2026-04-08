package tencentak

import (
	tencentcommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/regions"
	cvm "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cvm/v20170312"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
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

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	//keyPat = regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`)
	idPat = regexp.MustCompile(`\b(AKID[a-zA-Z0-9]{32})[\"';\s]*`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{
		"AKID",
		"AccessKey",
		// AK（Access Key ID）
		"AccessKeyId",
		"access_key_id",
		"AccessKeyID",
		"ACCESS_KEY_ID",
		"Access_Key_Id",
		"access-key-id",
		"secret_id", // 腾讯云使用 SecretId 作为 AK
		"SecretId",
		"AWS_ACCESS_KEY_ID",
		"AWS_ACCESS_KEY",
		"ACCESS_KEY",

		// SK（Secret Access Key）
		"AccessKeySecret",
		"access_key_secret",
		"AccessKeySECRET",
		"ACCESS_KEY_SECRET",
		"Access_Key_Secret",
		"access-key-secret",
		"secret_key", // 华为云、MinIO 等通用
		"SecretKey",
		"secretkey",
		"SECRET_KEY",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SECRET_KEY",
		"AWS_SESSION_TOKEN", // 如果包含临时凭证的话
	}
}

func (s Scanner) Description() string {
	return "tencent cloud only ak"
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Tencent secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)
	for _, idMatch := range idMatches {

		resIdMatch := strings.TrimSpace(idMatch[1])

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_TencentAK,
			Raw:          []byte(resIdMatch),
			RawV2:        []byte(resIdMatch),
		}
		resMatch := strings.TrimSpace("test")
		if verify {
			client := s.getClient()
			isVerified, verificationErr := verifyTencent(ctx, client, resIdMatch, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
		}
		results = append(results, s1)
	}

	return results, nil
}

func verifyTencent(ctx context.Context, client *http.Client, resIdMatch, resMatch string) (bool, error) {
	AK, SK := resIdMatch, resMatch
	credential := tencentcommon.NewCredential(AK, SK)
	TencentClient, _ := cvm.NewClient(credential, regions.Guangzhou, profile.NewClientProfile())
	request := cvm.NewDescribeInstancesRequest()
	_, err := TencentClient.DescribeInstances(request)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		//AuthFailure.SecretIdNotFound
		//AuthFailure.SignatureFailure TencentCloudSDKError
		if strings.Contains(err.Error(), "AuthFailure.SecretIdNotFound") {
			return false, nil
		}
		return true, nil
	}
	if err != nil {
		panic(err)
	}
	return true, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_TencentAK
}
