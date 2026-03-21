package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestMain(m *testing.M) {
	openBrowserFunc = func(string) {} // suppress browser during tests
	os.Exit(m.Run())
}

// mockServer is a minimal GitHub API mock for testing.
type mockServer struct {
	*httptest.Server
	envExists map[string]bool   // key: "owner/repo/env"
	secrets   map[string]string // key: "owner/repo/env/secret", value: encrypted_value
	pubKey    [32]byte
	pubKeyB64 string
	failRepos map[string]int // repo "owner/repo" -> HTTP status for secret upsert
}

func newMockServer(t *testing.T) *mockServer {
	t.Helper()

	pub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ms := &mockServer{
		envExists: make(map[string]bool),
		secrets:   make(map[string]string),
		pubKey:    *pub,
		pubKeyB64: base64.StdEncoding.EncodeToString(pub[:]),
		failRepos: make(map[string]int),
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"login":"testuser"}`)
	})

	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		// Path forms:
		//   /repos/{owner}/{repo}/environments/{env}
		//   /repos/{owner}/{repo}/environments/{env}/secrets/public-key
		//   /repos/{owner}/{repo}/environments/{env}/secrets/{name}
		trimmed := strings.TrimPrefix(r.URL.Path, "/repos/")
		parts := strings.Split(trimmed, "/")
		if len(parts) < 4 || parts[2] != "environments" {
			http.NotFound(w, r)
			return
		}
		owner, repo, env := parts[0], parts[1], parts[3]
		repoKey := owner + "/" + repo
		envKey := repoKey + "/" + env

		if len(parts) == 4 {
			// Environment CRUD
			switch r.Method {
			case http.MethodGet:
				if ms.envExists[envKey] {
					w.WriteHeader(http.StatusOK)
					fmt.Fprintln(w, `{}`)
				} else {
					w.WriteHeader(http.StatusNotFound)
					fmt.Fprintln(w, `{"message":"Not Found"}`)
				}
			case http.MethodPut:
				ms.envExists[envKey] = true
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, `{}`)
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
			return
		}

		if len(parts) == 6 && parts[4] == "secrets" {
			name := parts[5]
			if name == "public-key" && r.Method == http.MethodGet {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"key_id":"key-123","key":%q}`+"\n", ms.pubKeyB64)
				return
			}
			if r.Method == http.MethodPut {
				if status, ok := ms.failRepos[repoKey]; ok {
					w.WriteHeader(status)
					return
				}
				var payload struct {
					EncryptedValue string `json:"encrypted_value"`
					KeyID          string `json:"key_id"`
				}
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				ms.secrets[envKey+"/"+name] = payload.EncryptedValue
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}

		http.NotFound(w, r)
	})

	ms.Server = httptest.NewServer(mux)
	t.Cleanup(ms.Server.Close)
	return ms
}

// tempReposFile writes content to a temp file and returns the path.
func tempReposFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "repos")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// stubToken replaces getAuthToken with one that returns token, and restores on cleanup.
func stubToken(t *testing.T, token string) {
	t.Helper()
	orig := getAuthToken
	getAuthToken = func() (string, error) { return token, nil }
	t.Cleanup(func() { getAuthToken = orig })
}

// runWith is a helper that calls run() with a string stdin and captures stdout/stderr.
func runWith(args []string, stdin string) (stdout, stderr string, code int) {
	var outBuf, errBuf bytes.Buffer
	code = run(args, strings.NewReader(stdin), &outBuf, &errBuf)
	return outBuf.String(), errBuf.String(), code
}

// --- Repo file parsing ---

func TestReadRepos_CommentsAndBlanks(t *testing.T) {
	path := tempReposFile(t, `
# this is a comment
alice/service-a

# another comment
alice/service-b
`)
	repos, err := readRepos(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 2 || repos[0] != "alice/service-a" || repos[1] != "alice/service-b" {
		t.Fatalf("unexpected repos: %v", repos)
	}
}

func TestReadRepos_InvalidFormat(t *testing.T) {
	path := tempReposFile(t, "not-a-valid-repo\n")
	_, err := readRepos(path)
	if err == nil {
		t.Fatal("expected error for invalid repo format")
	}
}

func TestReadRepos_MissingFile(t *testing.T) {
	_, err := readRepos("/no/such/file")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestReadRepos_Empty(t *testing.T) {
	path := tempReposFile(t, "# only comments\n\n")
	repos, err := readRepos(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 0 {
		t.Fatalf("expected 0 repos, got %d", len(repos))
	}
}

// --- PAT format validation ---

func TestPATFormat_Valid(t *testing.T) {
	for _, pat := range []string{"ghp_abc123", "github_pat_abc123"} {
		if !strings.HasPrefix(pat, "ghp_") && !strings.HasPrefix(pat, "github_pat_") {
			t.Errorf("expected %q to be valid", pat)
		}
	}
}

func TestPATFormat_Invalid_ExitCode(t *testing.T) {
	ms := newMockServer(t)
	t.Setenv("GH_API_URL", ms.URL)
	stubToken(t, "fake-mgmt-token")
	path := tempReposFile(t, "alice/repo\n")

	_, stderr, code := runWith([]string{"--repos", path}, "invalid-token\n")
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(stderr, "invalid PAT format") {
		t.Fatalf("expected PAT format error in stderr, got: %s", stderr)
	}
}

// --- Environment auto-creation ---

func TestEnvironmentAutoCreated(t *testing.T) {
	ms := newMockServer(t)
	t.Setenv("GH_API_URL", ms.URL)
	stubToken(t, "fake-mgmt-token")
	path := tempReposFile(t, "alice/repo\n")

	// Environment does NOT exist initially — mock will auto-create on PUT.
	stdout, _, code := runWith([]string{"--repos", path}, "ghp_validtoken\n")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s", code, stdout)
	}
	if !ms.envExists["alice/repo/release"] {
		t.Fatal("expected environment to be created")
	}
}

func TestEnvironmentAlreadyExists(t *testing.T) {
	ms := newMockServer(t)
	ms.envExists["alice/repo/release"] = true
	t.Setenv("GH_API_URL", ms.URL)
	stubToken(t, "fake-mgmt-token")
	path := tempReposFile(t, "alice/repo\n")

	_, _, code := runWith([]string{"--repos", path}, "ghp_validtoken\n")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
}

// --- Secret encryption and upsert ---

func TestSecretUpserted(t *testing.T) {
	ms := newMockServer(t)
	t.Setenv("GH_API_URL", ms.URL)
	stubToken(t, "fake-mgmt-token")
	path := tempReposFile(t, "alice/repo\n")

	_, _, code := runWith([]string{"--repos", path}, "ghp_validtoken\n")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if _, ok := ms.secrets["alice/repo/release/PAT_RELEASE"]; !ok {
		t.Fatal("expected secret to be stored")
	}
}

// --- Per-repo failure handling ---

func TestPerRepoFailure_ContinuesAndExits1(t *testing.T) {
	ms := newMockServer(t)
	ms.failRepos["alice/bad-repo"] = http.StatusForbidden
	t.Setenv("GH_API_URL", ms.URL)
	stubToken(t, "fake-mgmt-token")
	path := tempReposFile(t, "alice/bad-repo\nalice/good-repo\n")

	stdout, _, code := runWith([]string{"--repos", path}, "ghp_validtoken\n")
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	if !strings.Contains(stdout, "alice/bad-repo failed:") {
		t.Fatalf("expected failure line for alice/bad-repo, got: %s", stdout)
	}
	if !strings.Contains(stdout, "alice/good-repo updated") {
		t.Fatalf("expected success line for alice/good-repo, got: %s", stdout)
	}
	if !strings.Contains(stdout, "total: 2, updated: 1, failed: 1") {
		t.Fatalf("expected summary line, got: %s", stdout)
	}
}

// --- Summary output ---

func TestSummaryAllSuccess(t *testing.T) {
	ms := newMockServer(t)
	t.Setenv("GH_API_URL", ms.URL)
	stubToken(t, "fake-mgmt-token")
	path := tempReposFile(t, "alice/a\nalice/b\nalice/c\n")

	stdout, _, code := runWith([]string{"--repos", path}, "ghp_validtoken\n")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "total: 3, updated: 3, failed: 0") {
		t.Fatalf("unexpected summary: %s", stdout)
	}
}

// --- Fatal preflight errors ---

func TestMissingReposFile_ExitCode2(t *testing.T) {
	ms := newMockServer(t)
	t.Setenv("GH_API_URL", ms.URL)
	stubToken(t, "fake-mgmt-token")

	_, stderr, code := runWith([]string{"--repos", "/no/such/file"}, "ghp_validtoken\n")
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(stderr, "repos file not found") {
		t.Fatalf("unexpected stderr: %s", stderr)
	}
}

func TestEmptyReposList_ExitCode2(t *testing.T) {
	ms := newMockServer(t)
	t.Setenv("GH_API_URL", ms.URL)
	stubToken(t, "fake-mgmt-token")
	path := tempReposFile(t, "# no repos\n")

	_, stderr, code := runWith([]string{"--repos", path}, "ghp_validtoken\n")
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(stderr, "no repositories found") {
		t.Fatalf("unexpected stderr: %s", stderr)
	}
}

func TestAuthTokenFailure_ExitCode2(t *testing.T) {
	ms := newMockServer(t)
	t.Setenv("GH_API_URL", ms.URL)
	orig := getAuthToken
	getAuthToken = func() (string, error) { return "", fmt.Errorf("gh auth token failed") }
	t.Cleanup(func() { getAuthToken = orig })
	path := tempReposFile(t, "alice/repo\n")

	_, stderr, code := runWith([]string{"--repos", path}, "ghp_validtoken\n")
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(stderr, "gh auth token failed") {
		t.Fatalf("unexpected stderr: %s", stderr)
	}
}

// --- Security: no PAT or token in output ---

func TestNoPATInOutput(t *testing.T) {
	ms := newMockServer(t)
	t.Setenv("GH_API_URL", ms.URL)
	stubToken(t, "fake-mgmt-token")
	path := tempReposFile(t, "alice/repo\n")

	const pat = "ghp_supersecrettoken"
	stdout, stderr, _ := runWith([]string{"--repos", path}, pat+"\n")
	if strings.Contains(stdout, pat) {
		t.Fatalf("PAT leaked in stdout: %s", stdout)
	}
	if strings.Contains(stderr, pat) {
		t.Fatalf("PAT leaked in stderr: %s", stderr)
	}
}

func TestNoTokenInOutput(t *testing.T) {
	ms := newMockServer(t)
	t.Setenv("GH_API_URL", ms.URL)
	const mgmtToken = "ghs_management_token_secret"
	stubToken(t, mgmtToken)
	path := tempReposFile(t, "alice/repo\n")

	stdout, stderr, _ := runWith([]string{"--repos", path}, "ghp_validtoken\n")
	if strings.Contains(stdout, mgmtToken) {
		t.Fatalf("mgmt token leaked in stdout: %s", stdout)
	}
	if strings.Contains(stderr, mgmtToken) {
		t.Fatalf("mgmt token leaked in stderr: %s", stderr)
	}
}

// --- Custom flags ---

func TestCustomEnvironmentAndSecretName(t *testing.T) {
	ms := newMockServer(t)
	t.Setenv("GH_API_URL", ms.URL)
	stubToken(t, "fake-mgmt-token")
	path := tempReposFile(t, "alice/repo\n")

	_, _, code := runWith([]string{
		"--repos", path,
		"--environment", "staging",
		"--secret-name", "MY_SECRET",
	}, "ghp_validtoken\n")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if _, ok := ms.secrets["alice/repo/staging/MY_SECRET"]; !ok {
		t.Fatal("expected secret under custom env/name")
	}
}
