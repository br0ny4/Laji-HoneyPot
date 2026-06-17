package mysql

// MySQL 协议常量与数据包格式

const (
	// 协议版本
	ProtocolVersion = 10

	// 能力标志
	ClientLongPassword  = 1
	ClientFoundRows     = 2
	ClientLongFlag      = 4
	ClientConnectWithDB = 8
	ClientProtocol41    = 512
	ClientSSL           = 2048
	ClientPluginAuth    = 1 << 19
	ClientSecureConn    = 1 << 15

	// 字符集
	CharsetUTF8 = 33 // utf8mb3_general_ci

	// 认证插件
	AuthPlugin = "mysql_native_password"

	// 服务器状态
	ServerStatusAutocommit = 2
)

// GreetingPacket 初始化握手包（服务端 → 客户端）
type GreetingPacket struct {
	ProtocolVersion byte
	ServerVersion   string
	ConnectionID    uint32
	AuthPluginData  []byte
	CapabilityFlags uint32
	Charset         byte
	StatusFlags     uint16
	AuthPluginName  string
}

// DefaultGreeting 默认 MySQL 8.0.35 问候包
func DefaultGreeting(connID uint32) *GreetingPacket {
	return &GreetingPacket{
		ProtocolVersion: ProtocolVersion,
		ServerVersion:   "8.0.35",
		ConnectionID:    connID,
		AuthPluginData:  generateAuthData(),
		CapabilityFlags: ClientProtocol41 | ClientSecureConn | ClientPluginAuth | ClientLongPassword | ClientConnectWithDB,
		Charset:         CharsetUTF8,
		StatusFlags:     ServerStatusAutocommit,
		AuthPluginName:  AuthPlugin,
	}
}

func generateAuthData() []byte {
	data := make([]byte, 21)
	for i := range data {
		data[i] = byte(i + 0x30)
	}
	data[20] = 0x00
	return data
}
