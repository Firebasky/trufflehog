package alibaba

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

type alibabaResp struct {
	RequestId string `json:"RequestId"`
	Message   string `json:"Message"`
	Recommend string `json:"Recommend"`
	HostId    string `json:"HostId"`
	Code      string `json:"Code"`
}

const alibabaURL = "https://ecs.aliyuncs.com"

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b([a-zA-Z0-9]{30})\b`)
	// 匹配 LTAI 开头，后面跟着 12、16、17、18、20、21、22 位的 alnum 字符串
	// 16,20,22,24,26
	idPat = regexp.MustCompile(`\b(LTAI[a-zA-Z0-9]{12,22})[\"';\s]*`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"LTAI", "AccessKey",
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
	return "Alibaba Cloud is a cloud computing service that provides a suite of cloud computing services including data storage, relational databases, big-data processing, and content delivery networks (CDNs). Alibaba Cloud API keys can be used to access and manage these services."
}

func randString(n int) string {
	const alphanum = "0123456789abcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, n)
	_, _ = rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(bytes)
}

func GetSignature(input, key string) string {
	key_for_sign := []byte(key)
	h := hmac.New(sha1.New, key_for_sign)
	h.Write([]byte(input))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func buildStringToSign(method, input string) string {
	filter := strings.Replace(input, "+", "%20", -1)
	filter = strings.Replace(filter, "%7E", "~", -1)
	filter = strings.Replace(filter, "*", "%2A", -1)
	filter = method + "&%2F&" + url.QueryEscape(filter)
	return filter
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
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {

			resIdMatch := strings.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Alibaba,
				Raw:          []byte(resIdMatch + ":" + resMatch),
				RawV2:        []byte(resMatch),
			}

			if verify {
				client := s.getClient()
				isVerified, verificationErr := verifyAlibaba(ctx, client, resIdMatch, resMatch)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, resMatch)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyAlibaba(ctx context.Context, client *http.Client, resIdMatch, resMatch string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, alibabaURL, nil)
	if err != nil {
		return false, err
	}

	dateISO := time.Now().UTC().Format("2006-01-02T15:04:05Z07:00")
	params := req.URL.Query()
	params.Add("AccessKeyId", resIdMatch)
	params.Add("Action", "DescribeRegions")
	params.Add("Format", "JSON")
	params.Add("SignatureMethod", "HMAC-SHA1")
	params.Add("SignatureNonce", randString(16))
	params.Add("SignatureVersion", "1.0")
	params.Add("Timestamp", dateISO)
	params.Add("Version", "2014-05-26")

	stringToSign := buildStringToSign(req.Method, params.Encode())
	signature := GetSignature(stringToSign, resMatch+"&") // Get Signature HMAC SHA1
	params.Add("Signature", signature)
	req.URL.RawQuery = params.Encode()

	req.Header.Add("Content-Type", "text/xml;charset=utf-8")
	req.Header.Add("Content-Length", strconv.Itoa(len(params.Encode())))

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	var alibabaResp alibabaResp
	if err = json.NewDecoder(res.Body).Decode(&alibabaResp); err != nil {
		return false, err
	}

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound, http.StatusBadRequest:
		// 400 used for most of error cases
		// 404 used if the AccessKeyId is not valid
		return false, nil
	default:
		err := fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
		if alibabaResp.Message != "" {
			err = fmt.Errorf("%s: %s, %s", err, alibabaResp.Message, alibabaResp.Code)
		}
		return false, err
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Alibaba
}
