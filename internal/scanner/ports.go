package scanner

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// PortScanResult represents port scan results
type PortScanResult struct {
	Target  string       `json:"target"`
	Ports   []PortInfo   `json:"ports"`
	State   string       `json:"state"`
	Success bool         `json:"success"`
	Error   string       `json:"error,omitempty"`
}

// PortInfo represents information about a single port
type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Banner   string `json:"banner,omitempty"`
	Version  string `json:"version,omitempty"`
}

// Common ports to scan in quick mode (top 250 most common ports)
var commonPorts = []int{
	// Top 50
	80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
	1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
	10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515,
	8008, 49154, 1027, 5666, 646,
	// Top 51-100
	5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513,
	990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
	7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755,
	2717, 4899, 9100, 119, 37,
	// Top 101-150
	1000, 3001, 5001, 82, 10010, 1030, 9090, 2107, 1024, 2103, 6004, 1801, 5050, 19, 8031,
	1041, 255, 1048, 1049, 1053, 1054, 1056, 1064, 1065, 2967, 3703, 17185, 4001, 5989, 6005,
	6667, 6668, 7000, 7001, 8082, 8090, 9080, 9090, 11211, 27017, 50000, 50001, 50002, 50003, 161,
	162, 1812, 1813, 2222, 4444,
	// Top 151-200
	32769, 32770, 32771, 32772, 32773, 32774, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176,
	5555, 10001, 10002, 10003, 10004, 10009, 6002, 6003, 6006, 1002, 1003, 1004, 1005, 1006, 1007,
	1008, 1009, 8200, 3003, 9001, 9002, 9003, 6379, 7002, 2375, 2376, 3690, 5003, 5004, 5005,
	5006, 5007, 5008, 6881, 6882,
	// Top 201-250
	1234, 2323, 3690, 9091, 9200, 9300, 11111, 27018, 47001, 49152, 54321, 55555, 55600, 60000, 60001,
	1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1042, 1043, 1044, 1045, 1046,
	1047, 1050, 1051, 1052, 1055, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1066, 1067, 1068,
	1069, 1070, 1071, 1072, 1073,
}

// ScanPorts scans ports on a target
func ScanPorts(target string, scanType string) (*PortScanResult, error) {
	var ports []int

	switch scanType {
	case "quick":
		ports = commonPorts
	case "full":
		// Scan all 65535 ports (this will take a while!)
		ports = make([]int, 65535)
		for i := 0; i < 65535; i++ {
			ports[i] = i + 1
		}
	default:
		ports = commonPorts
	}

	portInfos := scanPortsConcurrent(target, ports)

	state := "up"
	if len(portInfos) == 0 {
		state = "filtered"
	}

	return &PortScanResult{
		Target:  target,
		Ports:   portInfos,
		State:   state,
		Success: true,
	}, nil
}

// scanPortsConcurrent scans ports concurrently and grabs banners
func scanPortsConcurrent(target string, ports []int) []PortInfo {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var portInfos []PortInfo

	// Use a worker pool to limit concurrent connections
	workers := 100
	portChan := make(chan int, len(ports))

	// Start workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				if portInfo := scanPort(target, port); portInfo != nil {
					mu.Lock()
					portInfos = append(portInfos, *portInfo)
					mu.Unlock()
				}
			}
		}()
	}

	// Send ports to workers
	for _, port := range ports {
		portChan <- port
	}
	close(portChan)

	wg.Wait()
	return portInfos
}

// scanPort scans a single port and grabs banner if open
func scanPort(host string, port int) *PortInfo {
	timeout := 2 * time.Second
	address := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Port is open, grab banner
	banner := grabBanner(conn, port)
	service := getServiceName(port)
	version := extractVersion(banner, service)

	return &PortInfo{
		Port:     port,
		Protocol: "tcp",
		State:    "open",
		Service:  service,
		Banner:   banner,
		Version:  version,
	}
}

// grabBanner attempts to read a banner from an open connection
func grabBanner(conn net.Conn, port int) string {
	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// For some services, we need to send data first
	switch port {
	case 80, 8080, 8443: // HTTP
		conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	case 443: // HTTPS (we'll just try to read, won't work well without TLS)
		return "" // Skip HTTPS banner grabbing for now
	case 25: // SMTP
		// SMTP servers send banner automatically, just read
	case 21: // FTP
		// FTP servers send banner automatically
	case 22: // SSH
		// SSH servers send banner automatically
	default:
		// Try sending a newline for other services
		conn.Write([]byte("\r\n"))
	}

	// Read response
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return ""
	}

	banner := string(buffer[:n])
	// Clean up the banner (remove excessive whitespace, newlines)
	if len(banner) > 200 {
		banner = banner[:200] + "..."
	}

	return banner
}

// extractVersion attempts to extract version information from a banner
func extractVersion(banner, service string) string {
	if banner == "" {
		return ""
	}

	// Common version patterns
	patterns := map[string]*regexp.Regexp{
		"ssh":   regexp.MustCompile(`SSH-[\d\.]+-([^\s\r\n]+)`),
		"ftp":   regexp.MustCompile(`(?i)(vsftpd|proftpd|filezilla)[\s/]*([\d\.]+)`),
		"smtp":  regexp.MustCompile(`(?i)(postfix|exim|sendmail)[\s/]*([\d\.]+)`),
		"http":  regexp.MustCompile(`(?i)(apache|nginx|microsoft-iis|lighttpd)[/\s]*([\d\.]+)?`),
		"mysql": regexp.MustCompile(`([\d\.]+)-MariaDB|MySQL[\s/]*([\d\.]+)`),
	}

	// Try service-specific pattern first
	if pattern, ok := patterns[service]; ok {
		if matches := pattern.FindStringSubmatch(banner); len(matches) > 0 {
			// Return the full match or combine product + version
			if len(matches) > 2 && matches[2] != "" {
				return matches[1] + " " + matches[2]
			}
			return matches[1]
		}
	}

	// Try generic version pattern
	genericPattern := regexp.MustCompile(`([\w\-]+)[/\s]+([\d]+\.[\d]+(?:\.[\d]+)?)`)
	if matches := genericPattern.FindStringSubmatch(banner); len(matches) > 2 {
		return matches[1] + " " + matches[2]
	}

	// Return first line of banner if no version found
	lines := strings.Split(banner, "\n")
	if len(lines) > 0 {
		firstLine := strings.TrimSpace(lines[0])
		if len(firstLine) > 50 {
			firstLine = firstLine[:50] + "..."
		}
		return firstLine
	}

	return ""
}

// getServiceName returns the common service name for a port
func getServiceName(port int) string {
	services := map[int]string{
		7:     "echo",
		9:     "discard",
		13:    "daytime",
		19:    "chargen",
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		26:    "rsftp",
		37:    "time",
		53:    "dns",
		79:    "finger",
		80:    "http",
		81:    "http-alt",
		82:    "http-alt",
		88:    "kerberos",
		106:   "pop3pw",
		110:   "pop3",
		111:   "rpcbind",
		113:   "ident",
		119:   "nntp",
		135:   "msrpc",
		139:   "netbios-ssn",
		143:   "imap",
		144:   "news",
		161:   "snmp",
		162:   "snmptrap",
		179:   "bgp",
		199:   "smux",
		389:   "ldap",
		427:   "svrloc",
		443:   "https",
		444:   "snpp",
		445:   "microsoft-ds",
		465:   "smtps",
		514:   "shell",
		515:   "printer",
		543:   "klogin",
		544:   "kshell",
		548:   "afp",
		554:   "rtsp",
		587:   "submission",
		631:   "ipp",
		646:   "ldp",
		873:   "rsync",
		990:   "ftps",
		993:   "imaps",
		995:   "pop3s",
		1025:  "NFS-or-IIS",
		1026:  "LSA-or-nterm",
		1027:  "IIS",
		1028:  "ms-lsa",
		1029:  "ms-lsa",
		1110:  "nfsd",
		1433:  "ms-sql-s",
		1720:  "h323q931",
		1723:  "pptp",
		1755:  "wms",
		1900:  "upnp",
		2000:  "cisco-sccp",
		2001:  "dc",
		2049:  "nfs",
		2121:  "ccproxy-ftp",
		2375:  "docker",
		2376:  "docker-s",
		3000:  "ppp",
		3128:  "squid-http",
		3306:  "mysql",
		3389:  "ms-wbt-server",
		3690:  "svn",
		5000:  "upnp",
		5060:  "sip",
		5432:  "postgresql",
		5555:  "freeciv",
		5800:  "vnc-http",
		5900:  "vnc",
		6000:  "X11",
		6379:  "redis",
		6667:  "irc",
		7000:  "afs3-fileserver",
		8000:  "http-alt",
		8008:  "http",
		8009:  "ajp13",
		8080:  "http-proxy",
		8081:  "blackice-icecap",
		8082:  "blackice-alerts",
		8090:  "opsmessaging",
		8443:  "https-alt",
		8888:  "sun-answerbook",
		9090:  "zeus-admin",
		9100:  "jetdirect",
		9200:  "elasticsearch",
		9999:  "abyss",
		10000: "snet-sensor-mgmt",
		11211: "memcache",
		27017: "mongod",
		27018: "mongod",
	}

	if service, ok := services[port]; ok {
		return service
	}
	return "unknown"
}

// ComparePortScans compares two port scan results
func ComparePortScans(previous, current *PortScanResult) *PortChanges {
	prevPorts := make(map[int]PortInfo)
	for _, p := range previous.Ports {
		prevPorts[p.Port] = p
	}

	currPorts := make(map[int]PortInfo)
	for _, p := range current.Ports {
		currPorts[p.Port] = p
	}

	var newPorts, closedPorts []PortInfo

	// Find new ports
	for port, info := range currPorts {
		if _, exists := prevPorts[port]; !exists {
			newPorts = append(newPorts, info)
		}
	}

	// Find closed ports
	for port, info := range prevPorts {
		if _, exists := currPorts[port]; !exists {
			closedPorts = append(closedPorts, info)
		}
	}

	return &PortChanges{
		NewPorts:     newPorts,
		ClosedPorts:  closedPorts,
		TotalNew:     len(newPorts),
		TotalClosed:  len(closedPorts),
	}
}

// PortChanges represents changes between port scans
type PortChanges struct {
	NewPorts     []PortInfo `json:"new_ports"`
	ClosedPorts  []PortInfo `json:"closed_ports"`
	TotalNew     int        `json:"total_new"`
	TotalClosed  int        `json:"total_closed"`
}

// ToJSON converts result to JSON string
func (r *PortScanResult) ToJSON() (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// PortScanResultFromJSON parses JSON string to PortScanResult
func PortScanResultFromJSON(data string) (*PortScanResult, error) {
	var result PortScanResult
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return nil, err
	}
	return &result, nil
}
