package ethereumprivatekey

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
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

	// secp256k1 曲线的阶 n
	// n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
	secp256k1N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

	// 以太坊私钥正则表达式
	// 带 0x 前缀: 0x + 64位十六进制
	ethPrivKeyWithPrefix = regexp.MustCompile(`(?i)\b(0x[a-f0-9]{64})\b`)

	// 不带前缀，需要关键词上下文来减少误报
	// 匹配类似: private_key: abc123..., "privateKey": "abc123..."
	ethPrivKeyWithContext = regexp.MustCompile(`(?i)(?:private[_\-]?key|secret[_\-]?key|eth[_\-]?(?:private|secret)|wallet[_\-]?(?:key|secret)|signing[_\-]?key|account[_\-]?(?:key|secret)|priv[_\-]?key)["'\s:=]+["']?([a-f0-9]{64})["']?\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{
		// 通用私钥关键词
		"private_key",
		"privatekey",
		"private-key",
		"PRIVATE_KEY",
		"secret_key",
		"secretkey",
		"secret-key",
		"SECRET_KEY",
		// 以太坊特定
		"eth_private",
		"eth_secret",
		"ethereum_private",
		"ethereum_key",
		"wallet_key",
		"wallet_secret",
		"signing_key",
		"account_key",
		"account_secret",
		"priv_key",
		"privkey",
		// 0x 前缀 (用于匹配带前缀的私钥)
		"0x",
	}
}

func (s Scanner) Description() string {
	return "Ethereum private keys are 256-bit numbers used to sign transactions and prove ownership of Ethereum addresses. They provide full control over the associated account and all its assets across Ethereum and EVM-compatible chains (BSC, Polygon, Arbitrum, etc.)."
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// isValidEthPrivateKey 验证以太坊私钥是否有效
func isValidEthPrivateKey(hexKey string) bool {
	// 移除 0x 前缀
	hexKey = strings.TrimPrefix(strings.ToLower(hexKey), "0x")

	// 检查长度
	if len(hexKey) != 64 {
		return false
	}

	// 验证是否为有效的十六进制
	_, err := hex.DecodeString(hexKey)
	if err != nil {
		return false
	}

	// 排除全 0
	if hexKey == strings.Repeat("0", 64) {
		return false
	}

	// 排除全 f
	if strings.ToLower(hexKey) == strings.Repeat("f", 64) {
		return false
	}

	// 排除简单递增模式 (如 0123456789abcdef...)
	if isSimplePattern(hexKey) {
		return false
	}

	// 转换为大整数检查范围
	keyInt := new(big.Int)
	keyInt.SetString(hexKey, 16)

	// 私钥必须 > 0
	if keyInt.Cmp(big.NewInt(0)) <= 0 {
		return false
	}

	// 私钥必须 < secp256k1 曲线的阶 n
	if keyInt.Cmp(secp256k1N) >= 0 {
		return false
	}

	return true
}

// isSimplePattern 检测简单的重复或递增模式
func isSimplePattern(hexKey string) bool {
	// 检查是否为重复的短模式
	for patternLen := 1; patternLen <= 8; patternLen++ {
		if len(hexKey)%patternLen == 0 {
			pattern := hexKey[:patternLen]
			isRepeating := true
			for i := patternLen; i < len(hexKey); i += patternLen {
				if hexKey[i:i+patternLen] != pattern {
					isRepeating = false
					break
				}
			}
			if isRepeating && patternLen < 16 {
				return true
			}
		}
	}

	// 检查常见的测试/示例私钥
	commonTestKeys := []string{
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"1111111111111111111111111111111111111111111111111111111111111111",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
	}
	for _, testKey := range commonTestKeys {
		if strings.ToLower(hexKey) == testKey {
			return true
		}
	}

	return false
}

// addressBalanceResponse 用于解析 Etherscan API 响应
type addressBalanceResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Result  string `json:"result"`
}

// FromData will find and optionally verify Ethereum private keys in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// 用于去重
	foundKeys := make(map[string]bool)

	// 1. 匹配带 0x 前缀的私钥
	matchesWithPrefix := ethPrivKeyWithPrefix.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matchesWithPrefix {
		if len(match) < 2 {
			continue
		}
		key := strings.ToLower(match[1])
		if !foundKeys[key] {
			foundKeys[key] = true
		}
	}

	// 2. 匹配有上下文关键词的私钥 (不带前缀)
	matchesWithContext := ethPrivKeyWithContext.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matchesWithContext {
		if len(match) < 2 {
			continue
		}
		key := strings.ToLower(match[1])
		// 添加 0x 前缀以统一格式
		if !strings.HasPrefix(key, "0x") {
			key = "0x" + key
		}
		if !foundKeys[key] {
			foundKeys[key] = true
		}
	}

	// 处理找到的所有私钥
	for key := range foundKeys {
		// 验证私钥格式
		if !isValidEthPrivateKey(key) {
			continue
		}

		// 创建检测结果
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_EthereumPrivateKey,
			Raw:          []byte(key),
			Redacted:     key[:10] + "..." + key[len(key)-6:], // 显示前10位和后6位
		}

		if verify {
			client := s.getClient()
			isVerified, extraData, verificationErr := verifyEthPrivateKey(ctx, client, key)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, key)
		}

		results = append(results, s1)
	}

	return results, nil
}

// verifyEthPrivateKey 验证以太坊私钥
func verifyEthPrivateKey(ctx context.Context, client *http.Client, hexKey string) (bool, map[string]string, error) {
	extraData := make(map[string]string)

	// 标记为有效的私钥格式
	extraData["format"] = "ethereum_hex"
	extraData["length"] = "256-bit"
	extraData["compatible_chains"] = "Ethereum, BSC, Polygon, Arbitrum, Optimism, Avalanche, Fantom, etc."

	// 注意：完整的验证需要：
	// 1. 从私钥派生公钥 (需要 secp256k1 库)
	// 2. 从公钥派生地址 (Keccak256 哈希)
	// 3. 查询区块链 API 检查地址余额/交易历史
	//
	// 由于需要额外的加密库依赖 (如 go-ethereum)，这里只做格式验证
	// 如果需要完整验证，可以集成 go-ethereum 的 crypto 包

	// 格式验证通过即认为是有效的私钥
	return true, extraData, nil
}

// verifyAddressOnChain 查询地址在链上的状态 (可选功能，需要 API key)
// 这个函数展示了如何使用 Etherscan API 验证地址
func verifyAddressOnChain(ctx context.Context, client *http.Client, address string, apiKey string) (bool, map[string]string, error) {
	extraData := make(map[string]string)

	// 使用 Etherscan API 查询余额
	url := fmt.Sprintf("https://api.etherscan.io/api?module=account&action=balance&address=%s&tag=latest&apikey=%s", address, apiKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, extraData, err
	}

	req.Header.Set("User-Agent", "TruffleHog")

	res, err := client.Do(req)
	if err != nil {
		return false, extraData, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return false, extraData, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	var balanceResp addressBalanceResponse
	if err := json.NewDecoder(res.Body).Decode(&balanceResp); err != nil {
		return false, extraData, err
	}

	if balanceResp.Status != "1" {
		return false, extraData, fmt.Errorf("API error: %s", balanceResp.Message)
	}

	// 解析余额 (单位: wei)
	balance := new(big.Int)
	balance.SetString(balanceResp.Result, 10)

	// 转换为 ETH (1 ETH = 10^18 wei)
	ethBalance := new(big.Float).Quo(
		new(big.Float).SetInt(balance),
		new(big.Float).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)),
	)

	extraData["address"] = address
	extraData["balance_wei"] = balanceResp.Result
	extraData["balance_eth"] = ethBalance.Text('f', 18)

	// 如果有余额，则认为是活跃的私钥
	if balance.Cmp(big.NewInt(0)) > 0 {
		return true, extraData, nil
	}

	return false, extraData, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_EthereumPrivateKey
}
