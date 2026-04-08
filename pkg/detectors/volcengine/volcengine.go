package volcengine

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/volcengine/volcengine-go-sdk/service/vpc"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
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

	// 字节的sk 是2次 base64
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b([A-Za-z0-9+/=]{58,60})`)
	idPat  = regexp.MustCompile(`\b(AKLT[a-zA-Z0-9]{43})[\"';\s]*`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"AKLT",
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
	return "volcengine cloud ak/sk"
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Volcengine secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {

			resIdMatch := strings.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_Volcengine,
				Raw:          []byte(resIdMatch + ":" + resMatch),
				RawV2:        []byte(resMatch),
			}

			if verify {
				client := s.getClient()
				isVerified, verificationErr := verifyVolcengine(ctx, client, resIdMatch, resMatch)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, resMatch)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyVolcengine(ctx context.Context, client *http.Client, resIdMatch, resMatch string) (bool, error) {
	AK, SK := resIdMatch, resMatch
	var (
		ak     = AK // 替换为你的 AK
		sk     = SK // 替换为你的 SK
		region = "cn-beijing"
		err    error
	)
	config := volcengine.NewConfig().
		WithCredentials(credentials.NewStaticCredentials(ak, sk, "")).
		WithRegion(region)
	sess, err := session.NewSession(config)
	if err != nil {
		return false, nil
	}
	VolcengineClient := vpc.New(sess)
	_, err = VolcengineClient.DescribeVpcs(&vpc.DescribeVpcsInput{
		PageNumber: volcengine.Int64(1),
		PageSize:   volcengine.Int64(10),
	})
	if err != nil {
		println(err.Error())
		if strings.Contains(err.Error(), "SignatureDoesNotMatch") {
			return false, nil
		}
		if strings.Contains(err.Error(), "InvalidAccessKey") {
			return false, nil
		}
		return true, nil
	}
	return true, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Volcengine
}
