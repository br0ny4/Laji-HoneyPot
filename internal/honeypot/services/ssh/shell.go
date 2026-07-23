// Package ssh SSH 高交互命令 Shell (v0.21)
//
// 在 SSH 蜜罐中模拟真实 Linux Shell 环境，为常用命令返回基于虚拟拓扑
// 动态生成的输出。命令输出与拓扑配置保持一致（hostname、IP、services）。
//
// 支持的交互命令:
//   whoami, hostname, uname, id, pwd, ls, cat, ps, netstat, ss,
//   ip, ifconfig, arp, env, history, crontab, df, free, uptime,
//   w, last, lastlog, passwd, sudo, su, exit, logout
//
// 设计参考: AlterHive shell responder (Fausto-404/AlterHive)
package ssh

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Laji-HoneyPot/honeypot/internal/domain"
)

// ShellSimulator 假 Shell 模拟器
type ShellSimulator struct {
	topology      *domain.VirtualTopology
	localIP       string // 当前会话的本地虚拟IP
	hostname      string
	osInfo        string
	promptUser    string
	promptHost    string
}

// NewShellSimulator 创建 Shell 模拟器
func NewShellSimulator(topology *domain.VirtualTopology, localIP string) *ShellSimulator {
	hostname := "localhost"
	osInfo := "Linux 5.15.0-91-generic"
	promptUser := "admin"
	promptHost := "honeypot"

	if topology != nil {
		host := topology.GetHost(localIP)
		if host != nil {
			hostname = host.Hostname
			osInfo = host.OS
			if host.Role == "jumpbox" {
				promptUser = "ops"
			}
			promptHost = host.Hostname
		}
	}

	return &ShellSimulator{
		topology:   topology,
		localIP:    localIP,
		hostname:   hostname,
		osInfo:     osInfo,
		promptUser: promptUser,
		promptHost: promptHost,
	}
}

// Prompt 返回 Shell 提示符
func (s *ShellSimulator) Prompt() string {
	return fmt.Sprintf("[%s@%s ~]$ ", s.promptUser, s.promptHost)
}

// Handle 处理一条命令，返回模拟输出
func (s *ShellSimulator) Handle(cmdLine string, session *domain.SessionContext) string {
	cmdLine = strings.TrimSpace(cmdLine)
	if cmdLine == "" {
		return ""
	}

	fields := strings.Fields(cmdLine)
	cmd := fields[0]
	args := fields[1:]

	switch strings.ToLower(cmd) {
	case "whoami":
		return s.promptUser + "\n"
	case "hostname":
		return s.promptHost + "\n"
	case "uname":
		return s.handleUname(args)
	case "id":
		return fmt.Sprintf("uid=1000(%s) gid=1000(%s) groups=1000(%s),4(adm),27(sudo)\n",
			s.promptUser, s.promptUser, s.promptUser)
	case "pwd":
		return "/home/" + s.promptUser + "\n"
	case "ls":
		return s.handleLs(args)
	case "cat":
		return s.handleCat(args)
	case "ps", "ps\x20aux":
		return s.handlePs()
	case "netstat":
		return s.handleNetstat()
	case "ss":
		return s.handleSS()
	case "ip":
		return s.handleIP(args)
	case "ifconfig":
		return s.handleIfconfig()
	case "arp":
		return s.handleArp(session)
	case "env":
		return s.handleEnv()
	case "history":
		return s.handleHistory()
	case "crontab":
		return s.handleCrontab()
	case "df":
		return s.handleDf()
	case "free":
		return s.handleFree()
	case "uptime":
		return " 15:32:17 up 47 days,  3:12,  1 user,  load average: 0.08, 0.12, 0.09\n"
	case "w":
		return s.handleW()
	case "last":
		return s.handleLast()
	case "lastlog":
		return s.handleLastlog()
	case "passwd":
		return "Changing password for " + s.promptUser + ".\nCurrent password: \npasswd: Authentication token manipulation error\n"
	case "sudo":
		return s.handleSudo(args)
	case "su":
		return "Password: \nsu: Authentication failure\n"
	case "exit", "logout":
		return "logout\n"
	default:
		// 未知命令返回 bash 错误
		if strings.Contains(cmd, "/") {
			return fmt.Sprintf("bash: %s: No such file or directory\n", cmd)
		}
		return fmt.Sprintf("bash: %s: command not found\n", cmd)
	}
}

func (s *ShellSimulator) handleUname(args []string) string {
	for _, a := range args {
		switch a {
		case "-a":
			return fmt.Sprintf("Linux %s 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n", s.promptHost)
		case "-r":
			return "5.15.0-91-generic\n"
		case "-s":
			return "Linux\n"
		case "-m":
			return "x86_64\n"
		case "-n":
			return s.promptHost + "\n"
		}
	}
	return "Linux\n"
}

func (s *ShellSimulator) handleLs(_ []string) string {
	if s.topology == nil {
		return ".bash_history  .bashrc  .profile  .ssh/\n"
	}
	host := s.topology.GetHost(s.localIP)
	if host == nil {
		return ".bash_history  .bashrc  .profile  .ssh/\n"
	}
	switch host.Role {
	case "db":
		return ".bash_history  .bashrc  .my.cnf  backup/  data/  .profile  .ssh/\n"
	case "web", "app":
		return ".bash_history  .bashrc  deploy/  .env  logs/  .profile  public_html/  .ssh/\n"
	case "jumpbox":
		return ".bash_history  .bashrc  .kube/  keys/  .profile  scripts/  .ssh/\n"
	default:
		return ".bash_history  .bashrc  .profile  .ssh/\n"
	}
}

func (s *ShellSimulator) handleCat(args []string) string {
	if len(args) == 0 {
		return ""
	}
	filePath := strings.ToLower(args[len(args)-1])
	switch {
	case strings.Contains(filePath, "/etc/hosts"):
		return s.genHostsFile()
	case strings.Contains(filePath, "/etc/passwd"):
		return s.genPasswd()
	case strings.Contains(filePath, "/etc/os-release"):
		return fmt.Sprintf(`NAME="%s"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="%s"
`, s.osInfo, s.osInfo)
	case strings.Contains(filePath, "/etc/shadow"):
		return "cat: /etc/shadow: Permission denied\n"
	case strings.Contains(filePath, ".env"):
		return s.genEnvFile()
	case strings.Contains(filePath, "id_rsa"):
		return s.genSSHKey()
	case strings.Contains(filePath, "authorized_keys"):
		return s.genAuthKeys()
	default:
		return fmt.Sprintf("cat: %s: No such file or directory\n", filePath)
	}
}

func (s *ShellSimulator) genHostsFile() string {
	var sb strings.Builder
	sb.WriteString("127.0.0.1   localhost localhost.localdomain\n")
	sb.WriteString("::1         localhost localhost.localdomain\n\n")

	// 输出拓扑中所有主机
	if s.topology != nil {
		for _, h := range s.topology.AllHosts() {
			sb.WriteString(fmt.Sprintf("%-15s %s\n", h.IP, h.Hostname))
		}
	}
	return sb.String()
}

func (s *ShellSimulator) genPasswd() string {
	return fmt.Sprintf(`root:x:0:0:root:/root:/bin/bash
%s:x:1000:1000:%s:/home/%s:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:111:115:MySQL Server:/var/lib/mysql:/bin/false
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
`, s.promptUser, s.promptUser, s.promptUser)
}

func (s *ShellSimulator) genEnvFile() string {
	return `# Application Configuration
DB_HOST=192.168.57.10
DB_PORT=3306
DB_USER=app_user
DB_PASS=Ch@ng3M3!2024
DB_NAME=production

REDIS_HOST=192.168.57.11
REDIS_PORT=6379
REDIS_PASS=Redis#S3cur3!

ELASTICSEARCH_HOST=192.168.58.40
ELASTICSEARCH_PORT=9200

JWT_SECRET=s3cr3t-jwt-k3y-d0nt-l34k
API_TOKEN=sk-9a8b7c6d5e4f3g2h1i0j

# CI/CD
GITLAB_TOKEN=glpat-xxxxxxxxxxxxx
JENKINS_URL=http://192.168.58.20:8080
`
}

func (s *ShellSimulator) genSSHKey() string {
	return `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAw+7K9xN3qR8LmY2X5VpB7jFcQzWn2HtK4mU8aBxV5YJdO8fP2Qr
L9wS6tUvWxYzA1BcDeFgHiJkLmNoPqRsTuVwXyZaBbC8dEfGhIjKlMnOpQrStUvWxYzA1
-----END OPENSSH PRIVATE KEY-----
`
}

func (s *ShellSimulator) genAuthKeys() string {
	return `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... ops@jumpbox
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD... deploy@jenkins-ci
`
}

func (s *ShellSimulator) handlePs() string {
	var sb strings.Builder
	sb.WriteString("USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n")
	sb.WriteString(fmt.Sprintf("root         1  0.0  0.1 225436  9480 ?        Ss   May10   0:05 /sbin/init\n"))
	sb.WriteString(fmt.Sprintf("root       412  0.0  0.2  72308  6104 ?        Ss   May10   0:12 /usr/sbin/sshd -D\n"))
	sb.WriteString(fmt.Sprintf("%-10s 1542  0.0  0.1  18532  4320 ?        S    15:20   0:00 sshd: %s [priv]\n", s.promptUser, s.promptUser))

	// 根据主机角色输出不同的进程
	if s.topology != nil {
		host := s.topology.GetHost(s.localIP)
		if host != nil {
			pid := 1600
			for _, svc := range host.Services {
				if svc.Port == 22 {
					continue
				}
				pid++
				procName := svc.ProcessName
				if procName == "" {
					procName = svc.Protocol
				}
				sb.WriteString(fmt.Sprintf("%-10s %d  0.1  1.5 1234567 245600 ?   Sl   May10  12:34 %s\n",
					procName, pid, procName))
			}
		}
	}

	sb.WriteString(fmt.Sprintf("%-10s 1720  0.0  0.1  12536  4872 pts/0    Rs   15:32   0:00 ps aux\n", s.promptUser))
	return sb.String()
}

func (s *ShellSimulator) handleNetstat() string {
	var sb strings.Builder
	sb.WriteString("Active Internet connections (only servers)\n")
	sb.WriteString("Proto Recv-Q Send-Q Local Address           Foreign Address         State\n")
	sb.WriteString("tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n")

	if s.topology != nil {
		host := s.topology.GetHost(s.localIP)
		if host != nil {
			for _, svc := range host.Services {
				if svc.Port == 22 {
					continue
				}
				bind := svc.BindAddr
				if bind == "" {
					bind = "0.0.0.0"
				}
				sb.WriteString(fmt.Sprintf("tcp        0      0 %-22s 0.0.0.0:*               LISTEN\n",
					bind+":"+fmt.Sprintf("%d", svc.Port)))
			}
		}
	}
	return sb.String()
}

func (s *ShellSimulator) handleSS() string {
	var sb strings.Builder
	sb.WriteString("State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port  Process\n")
	sb.WriteString("LISTEN   0        128              0.0.0.0:22            0.0.0.0:*      users:((\"sshd\",pid=412,fd=3))\n")

	if s.topology != nil {
		host := s.topology.GetHost(s.localIP)
		if host != nil {
			pid := 500
			for _, svc := range host.Services {
				if svc.Port == 22 {
					continue
				}
				pid++
				bind := svc.BindAddr
				if bind == "" {
					bind = "0.0.0.0"
				}
				procName := svc.ProcessName
				if procName == "" {
					procName = svc.Protocol
				}
				sb.WriteString(fmt.Sprintf("LISTEN   0        128            %s:%-5d          0.0.0.0:*      users:((\"%s\",pid=%d,fd=%d))\n",
					bind, svc.Port, procName, pid, svc.Port%100+10))
			}
		}
	}
	return sb.String()
}

func (s *ShellSimulator) handleIP(args []string) string {
	subCmd := "addr"
	if len(args) > 0 {
		subCmd = args[0]
	}

	switch subCmd {
	case "addr", "a":
		m1, m2, m3 := ipLast3Bytes(s.localIP)
		return fmt.Sprintf(`1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    link/ether 00:50:56:%02x:%02x:%02x brd ff:ff:ff:ff:ff:ff
    inet %s/24 brd %s.255 scope global eth0
`, m1, m2, m3,
			s.localIP, s.localIP[:strings.LastIndex(s.localIP, ".")])
	case "route", "r":
		subnet := s.localIP[:strings.LastIndex(s.localIP, ".")]
		return fmt.Sprintf(`default via %s.1 dev eth0
%s.0/24 dev eth0 proto kernel scope link src %s
`, subnet, subnet, s.localIP)
	default:
		return ""
	}
}

func (s *ShellSimulator) handleIfconfig() string {
	subnet := s.localIP[:strings.LastIndex(s.localIP, ".")]
	mac1, mac2, mac3 := ipLast3Bytes(s.localIP)
	return fmt.Sprintf(`eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet %s  netmask 255.255.255.0  broadcast %s.255
        inet6 fe80::250:56ff:fe%02x:%02x%02x  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:%02x:%02x:%02x  txqueuelen 1000  (Ethernet)
        RX packets 4523891  bytes 3128477294 (3.1 GB)
        TX packets 2819347  bytes 1928347128 (1.9 GB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
`, s.localIP, subnet, mac1, mac2, mac3, mac1, mac2, mac3)
}

func (s *ShellSimulator) handleArp(session *domain.SessionContext) string {
	var sb strings.Builder
	sb.WriteString("Address                  HWtype  HWaddress           Flags Mask            Iface\n")

	if s.topology == nil {
		return "Address                  HWtype  HWaddress           Flags Mask            Iface\n"
	}
	hosts := s.topology.AllHosts()
	if session != nil {
		hosts = s.topology.GetHostsForSession(session)
	}

	for _, h := range hosts {
		if h.IP == s.localIP {
			continue
		}
		// 生成伪 MAC 地址
		m1, m2, m3 := ipLast3Bytes(h.IP)
		mac := fmt.Sprintf("00:50:56:%02x:%02x:%02x", m1, m2, m3)
		sb.WriteString(fmt.Sprintf("%-24s ether   %s   C                     eth0\n", h.IP, mac))
	}
	if sb.Len() == 0 {
		return "Address                  HWtype  HWaddress           Flags Mask            Iface\n"
	}
	return sb.String()
}

func (s *ShellSimulator) handleEnv() string {
	return fmt.Sprintf(`USER=%s
HOME=/home/%s
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PWD=/home/%s
LANG=en_US.UTF-8
DB_HOST=192.168.57.10
REDIS_HOST=192.168.57.11
`, s.promptUser, s.promptUser, s.promptUser)
}

func (s *ShellSimulator) handleHistory() string {
	return `    1  ls -la
    2  whoami
    3  id
    4  cat /etc/passwd
    5  netstat -tlnp
    6  ps aux
    7  env
    8  cat .env
    9  crontab -l
   10  df -h
`
}

func (s *ShellSimulator) handleCrontab() string {
	return `# m h  dom mon dow   command
0 2 * * * /opt/scripts/backup.sh >> /var/log/backup.log 2>&1
*/5 * * * * /opt/app/healthcheck.sh
0 0 * * 0 /opt/scripts/logrotate.sh
`
}

func (s *ShellSimulator) handleDf() string {
	return `Filesystem     1K-blocks    Used Available Use% Mounted on
/dev/sda1       51475068 8234940  40604788  17% /
tmpfs            4063948       0   4063948   0% /dev/shm
/dev/sdb1      206291944 4587236 191212340   3% /data
`
}

func (s *ShellSimulator) handleFree() string {
	return `              total        used        free      shared  buff/cache   available
Mem:        8127896     2345620     3987144      123456     1795132     5423876
Swap:       2097148           0     2097148
`
}

func (s *ShellSimulator) handleW() string {
	return fmt.Sprintf(` 15:32:17 up 47 days,  3:12,  1 user,  load average: 0.08, 0.12, 0.09
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
%s   pts/0    10.0.0.100       15:20    0.00s  0.02s  0.00s w
`, s.promptUser)
}

func (s *ShellSimulator) handleLast() string {
	return fmt.Sprintf(`%s   pts/0        10.0.0.100       Tue Jul 20 15:20   still logged in
%s   pts/1        192.168.56.20    Mon Jul 19 09:15 - 09:45  (00:30)
reboot   system boot  5.15.0-91-generic  Mon May 10 08:00   still running
`, s.promptUser, s.promptUser)
}

func (s *ShellSimulator) handleLastlog() string {
	return `Username         Port     From             Latest
root                                       **Never logged in**
` + fmt.Sprintf("%-16s pts/0   10.0.0.100       Tue Jul 20 15:20:17 +0000 2026\n", s.promptUser)
}

func (s *ShellSimulator) handleSudo(args []string) string {
	if len(args) == 0 {
		return "usage: sudo [-h] [-u user] command\n"
	}
	// sudo 命令通常要求密码
	if len(args) == 1 && strings.ToLower(args[0]) == "su" {
		return "[sudo] password for " + s.promptUser + ": \nSorry, try again.\n"
	}
	return fmt.Sprintf("[sudo] password for %s: \n%s is not in the sudoers file.  This incident will be reported.\n", s.promptUser, s.promptUser)
}

// ipLast3Bytes 从 IP 字符串的后三个字节中提取值用于生成伪 MAC 地址
func ipLast3Bytes(ip string) (int, int, int) {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0, 0, 0
	}
	b1, _ := strconv.Atoi(parts[1])
	b2, _ := strconv.Atoi(parts[2])
	b3, _ := strconv.Atoi(parts[3])
	return b1 % 256, b2 % 256, b3 % 256
}
