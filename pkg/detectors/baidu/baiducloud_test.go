package baidu

import (
	"fmt"
	"github.com/baidubce/bce-sdk-go/services/bcc"
	"strings"
	"testing"
)

var (
	validPattern = `x`
	secret       = ""
)

// Credentials 结构体用于保存 AK/SK
func TestYuQue_Pattern(t *testing.T) {
	//matches := idPat.FindAllStringSubmatch(validPattern, -1)
	//for _, match := range matches {
	//	tokenMatch := strings.TrimSpace(match[1])
	//	fmt.Printf(tokenMatch)
	//}
	// 用户的Access Key ID和Secret Access Key
	AK, SK := "f540f6ac0db3464680c5296a0db91757", "4f77e0685ad8462b8e9888bd69ae1914"
	ENDPOINT := "bcc.bj.baidubce.com"
	bccClient, err := bcc.NewClient(AK, SK, ENDPOINT)
	result, err := bccClient.ListZone()
	if err != nil {
		//list zone failed:  [Code: IamSignatureInvalid; Message: IamSignatureInvalid, cause: Could not find credential.; RequestId: e7afa78a-e9d4-46b8-9390-718a8addde18]
		//list zone failed:  [Code: IamSignatureInvalid; Message: IamSignatureInvalid, cause: Fail to authn user: Signature does not match; RequestId: d73e4197-0fa9-46a2-8a9d-5d99afdd0efb]
		if strings.Contains(err.Error(), "IamSignatureInvalid") {
			//list zone failed:  [Code: IamSignatureInvalid; Message: IamSignatureInvalid, cause: Could not find credential.; RequestId: f7031380-5490-47f3-b764-7411b076e604]
			fmt.Println("发现 IamSignatureInvalid 错误：可能是 AK/SK 错误或签名失败")
		}
		fmt.Println("list zone failed: ", err)
	} else {
		fmt.Println("list zone success: ", result)
	}
}
