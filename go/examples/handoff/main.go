// Command handoff is the Go equivalent of examples/test-handoff-hmac.js and
// examples/test-handoff-ed25519.js. It reads the same repo-root .env as the Node examples (the
// first .env found walking up from the working directory; real environment variables win).
//
//	cd go && go run ./examples/handoff hmac
//	cd go && go run ./examples/handoff ed25519
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	partnersigned "github.com/mdarifahammedreza/partner-signed-client/go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Request failed:", err)
		os.Exit(1)
	}
}

func run() error {
	if err := loadEnv(); err != nil {
		return err
	}

	scheme := partnersigned.SchemeHMAC
	if len(os.Args) > 1 {
		switch arg := strings.ToLower(os.Args[1]); arg {
		case "hmac":
		case "ed25519":
			scheme = partnersigned.SchemeEd25519
		default:
			return fmt.Errorf(`unknown scheme %q, expected "hmac" or "ed25519"`, arg)
		}
	}
	prefix := "HMAC"
	if scheme == partnersigned.SchemeEd25519 {
		prefix = "ED25519"
	}

	var secret string
	var err error
	if scheme == partnersigned.SchemeHMAC {
		secret, err = env("HMAC_SECRET")
	} else {
		secret, err = env("ED25519_PRIVATE_KEY_PEM")
		// .env can only carry the PEM with real newlines escaped as literal "\n".
		secret = strings.ReplaceAll(secret, `\n`, "\n")
	}
	if err != nil {
		return err
	}

	opts := partnersigned.HandoffOptions{Scheme: scheme, Secret: secret}
	for name, dst := range map[string]*string{
		"API_BASE_URL":                   &opts.BaseURL,
		prefix + "_PARTNER_SLUG":         &opts.PartnerID,
		prefix + "_TEST_PARTNER_USER_ID": &opts.PartnerUserID,
		prefix + "_TEST_PHONE_NUMBER":    &opts.PhoneNumber,
	} {
		if *dst, err = env(name); err != nil {
			return err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := partnersigned.Handoff(ctx, opts)
	if err != nil {
		return err
	}

	fmt.Println("status:", resp.Status)
	if resp.OK {
		if result, err := partnersigned.DataAs[partnersigned.HandoffResult](resp); err == nil && result.EntryURL != "" {
			fmt.Printf("entryUrl: %s (expires in %ds)\n", result.EntryURL, result.ExpiresIn)
		}
	}

	var pretty any
	if resp.IsJSON() && json.Unmarshal(resp.RawBody, &pretty) == nil {
		out, _ := json.MarshalIndent(pretty, "", "  ")
		fmt.Println("body:", string(out))
	} else {
		fmt.Println("body:", string(resp.RawBody))
	}
	return nil
}

func env(name string) (string, error) {
	if v := os.Getenv(name); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("missing env var %s: copy .env.example to .env and fill it in", name)
}

// loadEnv is a minimal .env loader. It walks up from the working directory to the first .env and
// sets every KEY=value line that isn't already set in the environment.
func loadEnv() error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	for {
		f, err := os.Open(filepath.Join(dir, ".env"))
		if err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64*1024), 1024*1024)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				key, value, ok := strings.Cut(line, "=")
				key = strings.TrimSpace(key)
				if !ok || key == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if _, set := os.LookupEnv(key); !set {
					os.Setenv(key, strings.TrimSpace(value))
				}
			}
			return scanner.Err()
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil // no .env anywhere; rely on the real environment
		}
		dir = parent
	}
}
