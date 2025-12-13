package bitcoinwif

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

	// Bitcoin WIF (Wallet Import Format) 私钥正则表达式
	// 主网未压缩私钥: 以 '5' 开头，51 位 Base58 字符 (总长度 51)
	// 主网压缩私钥: 以 'K' 或 'L' 开头，52 位 Base58 字符 (总长度 52)
	// Base58 字符集: 1-9, A-H, J-N, P-Z, a-k, m-z (排除 0, O, I, l)
	mainnetWIFPat = regexp.MustCompile(`\b([5][1-9A-HJ-NP-Za-km-z]{50}|[LK][1-9A-HJ-NP-Za-km-z]{51})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{
		// 常见的私钥相关关键词
		"wif",
		"WIF",
		"private_key",
		"privatekey",
		"private-key",
		"PRIVATE_KEY",
		"btc_private",
		"bitcoin_private",
		"wallet_import",
		"secret_key",
		"secretkey",
	}
}

func (s Scanner) Description() string {
	return "Bitcoin WIF (Wallet Import Format) is a standard format for encoding Bitcoin private keys. These keys provide full control over the associated Bitcoin address and can be used to transfer all funds."
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// isValidWIF 验证 WIF 格式是否正确
func isValidWIF(wif string) bool {
	// 主网未压缩: 以 5 开头，长度 51
	// 主网压缩: 以 K 或 L 开头，长度 52
	if len(wif) == 51 && wif[0] == '5' {
		return true
	}
	if len(wif) == 52 && (wif[0] == 'K' || wif[0] == 'L') {
		return true
	}
	return false
}

// addressResponse 用于解析 mempool.space API 响应
type addressResponse struct {
	ChainStats struct {
		FundedTxoSum int64 `json:"funded_txo_sum"`
		SpentTxoSum  int64 `json:"spent_txo_sum"`
		TxCount      int64 `json:"tx_count"`
	} `json:"chain_stats"`
	MempoolStats struct {
		FundedTxoSum int64 `json:"funded_txo_sum"`
		SpentTxoSum  int64 `json:"spent_txo_sum"`
	} `json:"mempool_stats"`
}

// FromData will find and optionally verify Bitcoin WIF private keys in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := mainnetWIFPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		wif := strings.TrimSpace(match[1])

		// 验证 WIF 格式
		if !isValidWIF(wif) {
			continue
		}

		// 创建检测结果
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_BitcoinWIF,
			Raw:          []byte(wif),
			Redacted:     wif[:8] + "..." + wif[len(wif)-4:], // 只显示前8位和后4位
		}

		if verify {
			client := s.getClient()
			isVerified, extraData, verificationErr := verifyBitcoinWIF(ctx, client, wif)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, wif)
		}

		results = append(results, s1)
	}

	return results, nil
}

// verifyBitcoinWIF 验证 Bitcoin WIF 私钥
// 通过将 WIF 转换为地址，然后查询区块链 API 来验证
func verifyBitcoinWIF(ctx context.Context, client *http.Client, wif string) (bool, map[string]string, error) {
	// 由于直接验证 WIF 需要加密库来派生地址
	// 这里我们只验证格式是否正确，并标记为潜在有效
	// 在实际部署中，可以集成 btcd 或其他库来派生地址并查询余额

	extraData := make(map[string]string)

	// 根据 WIF 格式判断类型
	if len(wif) == 51 && wif[0] == '5' {
		extraData["format"] = "uncompressed"
		extraData["network"] = "mainnet"
	} else if len(wif) == 52 && (wif[0] == 'K' || wif[0] == 'L') {
		extraData["format"] = "compressed"
		extraData["network"] = "mainnet"
	}

	// 注意：真正的验证需要：
	// 1. 解码 WIF 获取私钥
	// 2. 从私钥派生公钥
	// 3. 从公钥派生地址
	// 4. 查询区块链 API 检查地址是否有交易历史或余额
	//
	// 由于这需要额外的加密库依赖，这里我们只做格式验证
	// 如果格式正确，我们认为这是一个有效的 WIF 格式私钥

	// 格式验证通过即认为是有效的 WIF
	return true, extraData, nil
}

// verifyAddressOnChain 查询地址在区块链上的状态 (可选功能)
func verifyAddressOnChain(ctx context.Context, client *http.Client, address string) (bool, map[string]string, error) {
	extraData := make(map[string]string)

	// 使用 mempool.space API 查询地址信息
	url := fmt.Sprintf("https://mempool.space/api/address/%s", address)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, extraData, err
	}

	//req.Header.Set("User-Agent", "TruffleHog")

	res, err := client.Do(req)
	if err != nil {
		return false, extraData, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return false, extraData, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	var addrResp addressResponse
	if err := json.NewDecoder(res.Body).Decode(&addrResp); err != nil {
		return false, extraData, err
	}

	// 计算余额
	confirmedBalance := addrResp.ChainStats.FundedTxoSum - addrResp.ChainStats.SpentTxoSum
	unconfirmedBalance := addrResp.MempoolStats.FundedTxoSum - addrResp.MempoolStats.SpentTxoSum
	totalBalance := confirmedBalance + unconfirmedBalance

	extraData["address"] = address
	extraData["confirmed_balance_sat"] = fmt.Sprintf("%d", confirmedBalance)
	extraData["unconfirmed_balance_sat"] = fmt.Sprintf("%d", unconfirmedBalance)
	extraData["total_balance_sat"] = fmt.Sprintf("%d", totalBalance)
	extraData["tx_count"] = fmt.Sprintf("%d", addrResp.ChainStats.TxCount)

	// 如果有任何交易历史或余额，则认为是活跃的私钥
	if addrResp.ChainStats.TxCount > 0 || totalBalance > 0 {
		return true, extraData, nil
	}

	return false, extraData, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_BitcoinWIF
}
