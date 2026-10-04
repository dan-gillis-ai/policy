package policy

import (
	"strings"
	"testing"
)

func TestFilterEnvDropsCredentials(t *testing.T) {
	in := map[string]string{
		"PATH":                           "/usr/bin:/bin",
		"HOME":                           "/Users/me",
		"LANG":                           "en_US.UTF-8",
		"TZ":                             "UTC",
		"TERM":                           "xterm-256color",
		"SSH_AUTH_SOCK":                  "/private/tmp/com.apple.launchd/listeners",
		"AWS_SECRET_ACCESS_KEY":          "topsecret",
		"AWS_ACCESS_KEY_ID":              "AKIA...",
		"AZURE_CLIENT_SECRET":            "topsecret",
		"GOOGLE_APPLICATION_CREDENTIALS": "/secrets.json",
		"ANTHROPIC_API_KEY":              "sk-...",
		"OPENAI_API_KEY":                 "sk-...",
		"GITHUB_TOKEN":                   "ghp_...",
		"SOMETHING_RANDOM":               "leak-me",
	}
	out := FilterEnv(in)
	for _, k := range BaseEnvKeys {
		if _, ok := out[k]; !ok {
			t.Errorf("allowed key %s was dropped", k)
		}
	}
	for k := range out {
		switch k {
		case "PATH", "HOME", "LANG", "TZ", "TERM":
		default:
			t.Errorf("unexpected key %s survived the filter", k)
		}
	}
	if len(out) != len(BaseEnvKeys) {
		t.Errorf("got %d keys, want %d", len(out), len(BaseEnvKeys))
	}
}

func TestSanitizedEnvRedirectsHomeAndInjectsCorrelation(t *testing.T) {
	environ := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/Users/me",
		"SSH_AUTH_SOCK=/private/tmp/listener",
		"OS_USER=someone",
	}
	out := SanitizedEnv(environ, "trace-1", "run-2", "cap-3", "/state/sandbox/run-2")
	joined := strings.Join(out, "\n")
	if !strings.Contains(joined, "HOME=/state/sandbox/run-2") {
		t.Errorf("HOME must point at the sandbox home: %s", joined)
	}
	if strings.Contains(joined, "/Users/me") {
		t.Errorf("real HOME must not leak: %s", joined)
	}
	for _, want := range []string{
		"AGENT_TRACE_ID=trace-1",
		"AGENT_RUN_ID=run-2",
		"AGENT_CAP_ID=cap-3",
		"PATH=/usr/bin:/bin",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s in %s", want, joined)
		}
	}
	for _, banned := range []string{"SSH_AUTH_SOCK", "OS_USER"} {
		if strings.Contains(joined, banned+"=") {
			t.Errorf("%s must not reach the spawned process", banned)
		}
	}
}
