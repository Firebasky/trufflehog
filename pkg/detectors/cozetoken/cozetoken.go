package cozetoken

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Coze token patterns:
	// pat_ - Personal Access Token
	// sat_ - Service Access Token
	// Both are followed by 64 alphanumeric characters
	keyPat = regexp.MustCompile(`\b((?:pat|sat)_[A-Za-z0-9]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"pat_", "sat_"}
}

// userResponse represents the response from Coze API
type userResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		UserID    string `json:"user_id"`
		UserName  string `json:"user_name"`
		NickName  string `json:"nick_name"`
		AvatarURL string `json:"avatar_url"`
	} `json:"data"`
}

// FromData will find and optionally verify Coze tokens in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		token := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_CozeToken,
			Raw:          []byte(token),
			ExtraData:    make(map[string]string),
		}

		// Determine token type
		if strings.HasPrefix(token, "pat_") {
			s1.ExtraData["Type"] = "Personal Access Token"
		} else if strings.HasPrefix(token, "sat_") {
			s1.ExtraData["Type"] = "Service Access Token"
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, userData, err := verifyCozeToken(ctx, client, token)
			s1.Verified = isVerified
			s1.SetVerificationError(err, token)

			if isVerified && userData != nil {
				s1.ExtraData["user_id"] = userData.Data.UserID
				s1.ExtraData["user_name"] = userData.Data.UserName
				s1.ExtraData["nick_name"] = userData.Data.NickName
				s1.AnalysisInfo = map[string]string{
					"token": token,
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

// verifyCozeToken verifies the Coze token by calling the /v1/users/me API
func verifyCozeToken(ctx context.Context, client *http.Client, token string) (bool, *userResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.coze.cn/v1/users/me", http.NoBody)
	if err != nil {
		return false, nil, nil
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		var userResp userResponse
		if err := json.NewDecoder(res.Body).Decode(&userResp); err != nil {
			return false, nil, err
		}
		// Check if the API returned success (code 0)
		if userResp.Code == 0 && userResp.Data.UserID != "" {
			return true, &userResp, nil
		}
		// API returned error code, token is invalid
		return false, nil, nil

	case http.StatusUnauthorized, http.StatusForbidden:
		// Token is invalid
		return false, nil, nil

	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_CozeToken
}

func (s Scanner) Description() string {
	return "Coze is an AI application development platform. The tokens can be used to access Coze APIs and services."
}

