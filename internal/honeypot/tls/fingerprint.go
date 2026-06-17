package tls

import "crypto/tls"

// Fingerprint 定义 TLS 指纹特征
type Fingerprint struct {
	MinVersion   uint16
	MaxVersion   uint16
	CipherSuites []uint16
}

// 预定义常见服务 TLS 指纹
var (
	Nginx124 = Fingerprint{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	Apache2437 = Fingerprint{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}

	OpenSSH93 = Fingerprint{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		},
	}
)

// Profile 根据指纹预定义的名称查找
var Profile = map[string]Fingerprint{
	"nginx-1.24":    Nginx124,
	"apache-2.4.37": Apache2437,
	"openssh-9.3":   OpenSSH93,
}

// Apply 将指纹应用到 TLS config
func Apply(f Fingerprint) *tls.Config {
	return &tls.Config{
		MinVersion:   f.MinVersion,
		MaxVersion:   f.MaxVersion,
		CipherSuites: f.CipherSuites,
	}
}
