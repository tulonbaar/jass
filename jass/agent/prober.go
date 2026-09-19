package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	portFlag = flag.Int("port", 8443, "Port to listen on")
	ttlFlag  = flag.Int("ttl", 3600, "Time to live in seconds")
	pskFlag  = flag.String("psk", "", "Pre-shared key")

	globalLogPath    string
	modAdvapi32      = syscall.NewLazyDLL("advapi32.dll")
	procRtlGenRandom = modAdvapi32.NewProc("SystemFunction036")
)

// getRandomBytes fills b with cryptographically secure random bytes using
// RtlGenRandom (SystemFunction036) from advapi32.dll, supported across all Windows
// versions (Windows 2000 through Windows 11 / Server 2025). Avoids Go 1.22+ ProcessPrng
// dependency that causes panics on Windows Server 2008 / 2008 R2 / 7 / 2012.
func getRandomBytes(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if procRtlGenRandom.Find() == nil {
		r1, _, err := procRtlGenRandom.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
		if r1 != 0 {
			return nil
		}
		if err != nil && err != syscall.Errno(0) {
			log.Printf("[CRYPTO] Warning: RtlGenRandom call error: %v", err)
		}
	}
	// Fallback PRNG in case RtlGenRandom is unavailable
	now := time.Now().UnixNano()
	pid := int64(os.Getpid())
	for i := range b {
		now ^= now << 13
		now ^= now >> 7
		now ^= now << 17
		b[i] = byte((now ^ pid ^ int64(i*101)) & 0xFF)
	}
	return nil
}

// initLogging sets up logging to both stdout and prober-log.log in the executable's directory.
func initLogging() (*os.File, string) {
	exePath, err := os.Executable()
	var exeDir string
	if err == nil {
		exeDir = filepath.Dir(exePath)
	} else {
		exeDir = "."
	}
	logFilePath := filepath.Join(exeDir, "prober-log.log")
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Warning: failed to open log file %s: %v\n", logFilePath, err)
		return nil, logFilePath
	}

	multi := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multi)
	flag.CommandLine.SetOutput(multi)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	globalLogPath = logFilePath
	return logFile, logFilePath
}

// getAESKey ensures the key is exactly 32 bytes for AES-256
func getAESKey(psk string) []byte {
	key := make([]byte, 32)
	copy(key, psk)
	return key
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if err = getRandomBytes(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short (%d bytes, expected >= %d)", len(ciphertext), nonceSize)
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

type ExecRequest struct {
	Script string `json:"script"`
}

type ExecResponse struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

func executeHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[EXEC] Incoming request from %s (Method: %s)", r.RemoteAddr, r.Method)
	if r.Method != "POST" {
		log.Printf("[EXEC] Rejected non-POST method %s from %s", r.Method, r.RemoteAddr)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[EXEC] Error reading request body from %s: %v", r.RemoteAddr, err)
		http.Error(w, "Error reading body", http.StatusBadRequest)
		return
	}

	key := getAESKey(*pskFlag)
	plaintext, err := decrypt(body, key)
	if err != nil {
		log.Printf("[EXEC] Decryption failed for request from %s: %v (verify PSK match)", r.RemoteAddr, err)
		http.Error(w, "Decryption failed", http.StatusForbidden)
		return
	}

	var req ExecRequest
	if err := json.Unmarshal(plaintext, &req); err != nil {
		log.Printf("[EXEC] Invalid JSON payload from %s: %v", r.RemoteAddr, err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	log.Printf("[EXEC] Executing PowerShell script (%d chars) from %s", len(req.Script), r.RemoteAddr)

	// Execute PowerShell
	cmd := exec.Command("powershell.exe", "-NonInteractive", "-NoProfile", "-Command", req.Script)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = -1
		}
	}

	log.Printf("[EXEC] Finished execution: exitCode=%d, stdout=%d bytes, stderr=%d bytes",
		exitCode, stdout.Len(), stderr.Len())
	if stderr.Len() > 0 {
		log.Printf("[EXEC] Stderr preview: %s", stderr.String())
	}

	resp := ExecResponse{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
	}

	respJSON, _ := json.Marshal(resp)
	ciphertext, err := encrypt(respJSON, key)
	if err != nil {
		log.Printf("[EXEC] Encryption failed for response to %s: %v", r.RemoteAddr, err)
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(ciphertext)
	log.Printf("[EXEC] Response delivered successfully to %s", r.RemoteAddr)
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[PING] Received ping from %s -> responding with PONG", r.RemoteAddr)
	w.Write([]byte("PONG"))
}

type LogsResponse struct {
	Logs []string `json:"logs"`
}

func logsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	key := getAESKey(*pskFlag)
	_, err = decrypt(body, key)
	if err != nil {
		log.Printf("[LOGS] Authentication failed for %s: %v", r.RemoteAddr, err)
		http.Error(w, "Authentication failed", http.StatusForbidden)
		return
	}

	var lines []string
	if globalLogPath != "" {
		data, err := os.ReadFile(globalLogPath)
		if err == nil {
			allLines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
			var clean []string
			for _, l := range allLines {
				if strings.TrimSpace(l) != "" {
					clean = append(clean, l)
				}
			}
			start := 0
			if len(clean) > 100 {
				start = len(clean) - 100
			}
			lines = clean[start:]
		}
	}

	resp := LogsResponse{Logs: lines}
	respJSON, _ := json.Marshal(resp)
	ciphertext, err := encrypt(respJSON, key)
	if err != nil {
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(ciphertext)
}

func terminateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	key := getAESKey(*pskFlag)
	_, err = decrypt(body, key)
	if err != nil {
		log.Printf("[TERMINATE] Authentication failed for %s: %v", r.RemoteAddr, err)
		http.Error(w, "Authentication failed", http.StatusForbidden)
		return
	}

	log.Printf("[TERMINATE] Terminate command received from %s. Removing firewall and triggering self-destruct...", r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"terminating"}`))

	go func() {
		time.Sleep(500 * time.Millisecond)
		manageFirewall(*portFlag, false)
		selfDestruct()
		os.Exit(0)
	}()
}

func manageFirewall(port int, add bool) {
	var cmd *exec.Cmd
	if add {
		log.Printf("[FIREWALL] Adding Windows firewall rule 'JASS-Prober' for TCP port %d...", port)
		cmd = exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name=JASS-Prober", "dir=in", "action=allow", "protocol=TCP", fmt.Sprintf("localport=%d", port))
	} else {
		log.Printf("[FIREWALL] Deleting Windows firewall rule 'JASS-Prober'...")
		cmd = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=JASS-Prober")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[FIREWALL] Note: Firewall command returned: %v (output: %s)", err, bytes.TrimSpace(out))
	} else {
		log.Printf("[FIREWALL] Firewall rule operation succeeded.")
	}
}

func selfDestruct() {
	exePath, err := os.Executable()
	if err != nil {
		log.Printf("[CLEANUP] Failed to get executable path for self-destruct: %v", err)
		return
	}
	batPath := filepath.Join(os.TempDir(), "jass_cleanup.bat")
	batContent := fmt.Sprintf("@echo off\ntimeout /t 2 /nobreak > NUL\ndel \"%s\"\ndel \"%%~f0\"\n", exePath)
	if err := os.WriteFile(batPath, []byte(batContent), 0644); err != nil {
		log.Printf("[CLEANUP] Failed to write cleanup batch file %s: %v", batPath, err)
		return
	}
	log.Printf("[CLEANUP] Triggered self-destruct batch %s (will delete %s)", batPath, exePath)
	exec.Command("cmd.exe", "/c", batPath).Start()
}

func main() {
	logFile, logPath := initLogging()
	if logFile != nil {
		defer logFile.Close()
	}

	exePath, _ := os.Executable()
	log.Println("==================================================")
	log.Printf("JASS Prober Agent starting up")
	log.Printf("Executable path: %s", exePath)
	log.Printf("Log file path: %s", logPath)

	flag.Parse()

	if *pskFlag == "" {
		log.Fatal("Fatal error: PSK is required (--psk <key>)")
	}

	log.Printf("Configuration: Port=%d, TTL=%ds, PSK length=%d", *portFlag, *ttlFlag, len(*pskFlag))

	manageFirewall(*portFlag, true)

	go func() {
		log.Printf("TTL timer started: will self-destruct in %d seconds", *ttlFlag)
		time.Sleep(time.Duration(*ttlFlag) * time.Second)
		log.Printf("TTL (%ds) reached. Initiating shutdown and self-destruct...", *ttlFlag)
		manageFirewall(*portFlag, false)
		selfDestruct()
		os.Exit(0)
	}()

	http.HandleFunc("/execute", executeHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/logs", logsHandler)
	http.HandleFunc("/terminate", terminateHandler)

	addr := fmt.Sprintf("0.0.0.0:%d", *portFlag)
	log.Printf("Prober server listening on %s (TTL: %ds)", addr, *ttlFlag)
	log.Println("==================================================")
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Fatal error: HTTP server failed: %v", err)
	}
}
