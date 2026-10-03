package policy

import (
	"sort"
	"strings"
)

// Spawned processes get a fixed, sanitised environment (docs/05):
//
//   - A fixed allowlist of variables: PATH, HOME, LANG, TZ, TERM. Everything
//     else inherited from the agent's environment is dropped — no
//     SSH_AUTH_SOCK, no cloud credentials (AWS_*, AZURE_*, GOOGLE_*), no
//     provider tokens, no secrets that happen to be in the agent's env.
//   - HOME is redirected into a per-run sandbox directory under the state
//     dir, so ~/.gitconfig, ~/.ssh, and ~/.aws/credentials are not reachable
//     even if a tool goes looking.
//   - Correlation variables are injected: AGENT_TRACE_ID, AGENT_RUN_ID,
//     AGENT_CAP_ID, so a stray pytest stack trace can be traced back to the
//     run that spawned it.
//
// The request's env_allowlist can only narrow PATH-style access, never add
// credentials: the device ignores any env the caller asks to pass through.
const (
	EnvTraceID = "AGENT_TRACE_ID"
	EnvRunID   = "AGENT_RUN_ID"
	EnvCapID   = "AGENT_CAP_ID"
)

// BaseEnvKeys is the fixed allowlist of inherited environment variables.
var BaseEnvKeys = []string{"PATH", "HOME", "LANG", "TZ", "TERM"}

// AgentEnvKeys are the correlation variables the device injects itself.
var AgentEnvKeys = []string{EnvTraceID, EnvRunID, EnvCapID}

// FilterEnv keeps only the base allowlist from a key=value environment map.
// Returns a fresh map; the input is not modified.
func FilterEnv(env map[string]string) map[string]string {
	out := make(map[string]string, len(BaseEnvKeys))
	for _, k := range BaseEnvKeys {
		if v, ok := env[k]; ok {
			out[k] = v
		}
	}
	return out
}

// FilterEnviron is FilterEnv over an os.Environ()-style key=value slice.
func FilterEnviron(environ []string) map[string]string {
	return FilterEnv(splitEnv(environ))
}

// SanitizedEnv builds the key=value environment for a spawned process:
// base allowlist, HOME redirected into sandboxHome, and the correlation
// variables injected. The output is sorted for determinism.
func SanitizedEnv(environ []string, traceID, runID, capID, sandboxHome string) []string {
	env := FilterEnviron(environ)
	if sandboxHome != "" {
		env["HOME"] = sandboxHome
	}
	if traceID != "" {
		env[EnvTraceID] = traceID
	}
	if runID != "" {
		env[EnvRunID] = runID
	}
	if capID != "" {
		env[EnvCapID] = capID
	}
	return renderEnv(env)
}

// SanitizedEnvMap is SanitizedEnv over a map.
func SanitizedEnvMap(env map[string]string, traceID, runID, capID, sandboxHome string) []string {
	return SanitizedEnv(renderEnv(env), traceID, runID, capID, sandboxHome)
}

func splitEnv(environ []string) map[string]string {
	out := make(map[string]string, len(environ))
	for _, kv := range environ {
		if i := strings.IndexByte(kv, '='); i > 0 {
			out[kv[:i]] = kv[i+1:]
		}
	}
	return out
}

func renderEnv(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}
