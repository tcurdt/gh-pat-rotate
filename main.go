package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/term"
)

const (
	defaultSecretName = "PAT_RELEASE"
	defaultEnvironment = "release"
	githubAPIBase     = "https://api.github.com"
	githubTokensURL   = "https://github.com/settings/tokens"
)

var repoRegex = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// openBrowserFunc is a variable so tests can replace it with a no-op.
var openBrowserFunc = openBrowser

// getAuthToken is a variable so tests can replace it with a stub.
var getAuthToken = func() (string, error) {
	out, err := exec.Command("gh", "auth", "token").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get management token via `gh auth token`: %v\nTip: try `gh auth refresh -s repo` if scope appears insufficient", err)
	}
	token := strings.TrimSpace(string(out))
	if token == "" {
		return "", fmt.Errorf("gh auth token returned empty token")
	}
	return token, nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot determine home directory: %v\n", err)
		return 2
	}

	fs := flag.NewFlagSet("gh-pat-rotate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	reposPath := fs.String("repos", filepath.Join(homeDir, ".releases"), "path to repo list file")
	secretName := fs.String("secret-name", defaultSecretName, "secret name to upsert")
	environment := fs.String("environment", defaultEnvironment, "environment name to target")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	fmt.Fprintln(stderr, "Create a classic PAT with scopes: repo, write:packages — expiry: 90 days")
	openBrowserFunc(githubTokensURL)

	repos, err := readRepos(*reposPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if len(repos) == 0 {
		fmt.Fprintf(stderr, "error: no repositories found in %s\n", *reposPath)
		return 2
	}

	pat, err := readPAT(stdin, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: reading PAT: %v\n", err)
		return 2
	}

	if !strings.HasPrefix(pat, "ghp_") && !strings.HasPrefix(pat, "github_pat_") {
		fmt.Fprintf(stderr, "error: invalid PAT format: must start with ghp_ or github_pat_\n")
		return 2
	}

	apiBase := os.Getenv("GH_API_URL")
	if apiBase == "" {
		apiBase = githubAPIBase
	}

	if err := validatePAT(pat, apiBase); err != nil {
		fmt.Fprintf(stderr, "error: PAT validation failed: %v\n", err)
		return 2
	}

	mgmtToken, err := getAuthToken()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	total := len(repos)
	updated := 0
	failed := 0

	for _, repo := range repos {
		if err := processRepo(repo, pat, mgmtToken, *secretName, *environment, apiBase); err != nil {
			fmt.Fprintf(stdout, "%s failed: %s\n", repo, err)
			failed++
		} else {
			fmt.Fprintf(stdout, "%s updated\n", repo)
			updated++
		}
	}

	fmt.Fprintf(stdout, "\ntotal: %d, updated: %d, failed: %d\n", total, updated, failed)

	if failed > 0 {
		return 1
	}
	return 0
}

func openBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{url}
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", url}
	default:
		cmd = "xdg-open"
		args = []string{url}
	}
	_ = exec.Command(cmd, args...).Start()
}

func readRepos(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("repos file not found: %s", path)
		}
		return nil, fmt.Errorf("cannot open repos file: %v", err)
	}
	defer f.Close()

	var repos []string
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !repoRegex.MatchString(line) {
			return nil, fmt.Errorf("invalid repo format on line %d: %q", lineNum, line)
		}
		repos = append(repos, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading repos file: %v", err)
	}
	return repos, nil
}

func readPAT(r io.Reader, prompt io.Writer) (string, error) {
	if f, ok := r.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		return readMasked(f, prompt)
	}

	var pat string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && pat == "" {
			pat = line
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if pat == "" {
		return "", fmt.Errorf("no PAT provided on stdin")
	}
	return pat, nil
}

func readMasked(f *os.File, prompt io.Writer) (string, error) {
	fmt.Fprint(prompt, "PAT: ")

	fd := int(f.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return "", err
	}
	defer term.Restore(fd, oldState)

	var buf []byte
	b := make([]byte, 1)
	for {
		if _, err := f.Read(b); err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}
		switch b[0] {
		case '\r', '\n':
			fmt.Fprint(prompt, "\r\n")
			return strings.TrimSpace(string(buf)), nil
		case 127, '\b': // DEL / backspace
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				fmt.Fprint(prompt, "\b \b")
			}
		case 3: // Ctrl+C
			fmt.Fprint(prompt, "\r\n")
			return "", fmt.Errorf("interrupted")
		case 4: // Ctrl+D
			fmt.Fprint(prompt, "\r\n")
			break
		default:
			if b[0] >= 32 {
				buf = append(buf, b[0])
				fmt.Fprint(prompt, "*")
			}
		}
	}

	if len(buf) == 0 {
		return "", fmt.Errorf("no PAT provided on stdin")
	}
	return string(buf), nil
}

func validatePAT(pat, apiBase string) error {
	req, err := http.NewRequest("GET", apiBase+"/user", nil)
	if err != nil {
		return err
	}
	setGitHubHeaders(req, pat)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("API request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("PAT rejected by GitHub API (status %d)", resp.StatusCode)
	}
	return nil
}

func processRepo(repo, pat, mgmtToken, secretName, environment, apiBase string) error {
	owner, repoName, _ := strings.Cut(repo, "/")

	if err := ensureEnvironment(owner, repoName, environment, mgmtToken, apiBase); err != nil {
		return fmt.Errorf("ensure environment: %v", err)
	}

	keyID, pubKey, err := getPublicKey(owner, repoName, environment, mgmtToken, apiBase)
	if err != nil {
		return fmt.Errorf("get public key: %v", err)
	}

	encrypted, err := sealedBox(pubKey, []byte(pat))
	if err != nil {
		return fmt.Errorf("encrypt secret: %v", err)
	}

	if err := upsertSecret(owner, repoName, environment, secretName, keyID, encrypted, mgmtToken, apiBase); err != nil {
		return fmt.Errorf("upsert secret: %v", err)
	}
	return nil
}

func setGitHubHeaders(req *http.Request, token string) {
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
}

func ghRequest(method, url, token string, body any) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	setGitHubHeaders(req, token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return http.DefaultClient.Do(req)
}

func ensureEnvironment(owner, repo, environment, token, apiBase string) error {
	url := fmt.Sprintf("%s/repos/%s/%s/environments/%s", apiBase, owner, repo, environment)

	resp, err := ghRequest("GET", url, token, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("GET environment returned status %d", resp.StatusCode)
	}

	resp, err = ghRequest("PUT", url, token, map[string]any{})
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("PUT environment returned status %d", resp.StatusCode)
	}
	return nil
}

func getPublicKey(owner, repo, environment, token, apiBase string) (string, []byte, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/environments/%s/secrets/public-key", apiBase, owner, repo, environment)

	resp, err := ghRequest("GET", url, token, nil)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("GET public key returned status %d", resp.StatusCode)
	}

	var result struct {
		KeyID string `json:"key_id"`
		Key   string `json:"key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", nil, fmt.Errorf("decode public key response: %v", err)
	}

	pubKey, err := base64.StdEncoding.DecodeString(result.Key)
	if err != nil {
		return "", nil, fmt.Errorf("decode public key: %v", err)
	}
	return result.KeyID, pubKey, nil
}

func upsertSecret(owner, repo, environment, secretName, keyID string, encrypted []byte, token, apiBase string) error {
	url := fmt.Sprintf("%s/repos/%s/%s/environments/%s/secrets/%s", apiBase, owner, repo, environment, secretName)
	payload := map[string]string{
		"encrypted_value": base64.StdEncoding.EncodeToString(encrypted),
		"key_id":          keyID,
	}
	resp, err := ghRequest("PUT", url, token, payload)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("PUT secret returned status %d", resp.StatusCode)
	}
	return nil
}

// sealedBox implements libsodium's crypto_box_seal:
// ephemeral X25519 keypair, Blake2b nonce, XSalsa20-Poly1305 encryption.
func sealedBox(recipientPublicKey, message []byte) ([]byte, error) {
	if len(recipientPublicKey) != 32 {
		return nil, fmt.Errorf("invalid public key length: %d", len(recipientPublicKey))
	}

	ephPub, ephPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	var recip [32]byte
	copy(recip[:], recipientPublicKey)

	// nonce = Blake2b(ephPub || recipientPub), first 24 bytes
	h, err := blake2b.New(24, nil)
	if err != nil {
		return nil, err
	}
	h.Write(ephPub[:])
	h.Write(recip[:])
	var nonce [24]byte
	copy(nonce[:], h.Sum(nil))

	var sharedKey [32]byte
	box.Precompute(&sharedKey, &recip, ephPriv)

	encrypted := secretbox.Seal(nil, message, &nonce, &sharedKey)

	result := make([]byte, 32+len(encrypted))
	copy(result[:32], ephPub[:])
	copy(result[32:], encrypted)
	return result, nil
}
