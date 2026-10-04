package policy

import (
	"strings"
	"testing"

	"github.com/dan-gillis-ai/contracts/gen/agentharness/v1"
	"github.com/dan-gillis-ai/taint"
)

// TestWebContentCannotReachAShell is THE invariant of the taint system:
// content that has touched a web page (untrusted) or a blocklisted source
// (hostile) must never drive shell.run, shell.test, a write, a delete, a
// commit, a push, or an accessibility actuation — in any approval mode.
// Above a ceiling, Deny wins even if the user would click "approve": the
// device must not let a fast-clicking user become the injection's last mile.
func TestWebContentCannotReachAShell(t *testing.T) {
	mutating := []agentharnessv1.Capability{
		agentharnessv1.Capability_CAPABILITY_FS_WRITE,
		agentharnessv1.Capability_CAPABILITY_FS_DELETE,
		agentharnessv1.Capability_CAPABILITY_GIT_COMMIT,
		agentharnessv1.Capability_CAPABILITY_GIT_PUSH,
		agentharnessv1.Capability_CAPABILITY_SHELL_RUN,
		agentharnessv1.Capability_CAPABILITY_SHELL_TEST,
		agentharnessv1.Capability_CAPABILITY_AX_CLICK,
		agentharnessv1.Capability_CAPABILITY_AX_TYPE,
	}
	for _, cap := range mutating {
		for _, mode := range []string{"auto", "ask"} {
			for _, in := range []taint.Level{taint.Untrusted, taint.Hostile} {
				d, reason := Decide(cap, in, mode)
				if d != DecisionDeny {
					t.Fatalf("%s with %s input in mode %q: decision = %s (reason %q); web content must be denied outright",
						CapName(cap), in, mode, d, reason)
				}
				if !strings.Contains(reason, "never approvable") {
					t.Errorf("%s denial must state that ceilings are not approvable upward: %q", CapName(cap), reason)
				}
			}
		}
	}
}

func TestDecideReadOnlyAlwaysAllows(t *testing.T) {
	for _, cap := range []agentharnessv1.Capability{
		agentharnessv1.Capability_CAPABILITY_FS_READ,
		agentharnessv1.Capability_CAPABILITY_FS_LIST,
		agentharnessv1.Capability_CAPABILITY_FS_SEARCH,
		agentharnessv1.Capability_CAPABILITY_GIT_STATUS,
		agentharnessv1.Capability_CAPABILITY_GIT_LOG,
		agentharnessv1.Capability_CAPABILITY_GIT_DIFF,
		agentharnessv1.Capability_CAPABILITY_DEVICE_STATE,
	} {
		for _, in := range taint.AllLevels {
			d, _ := Decide(cap, in, "ask")
			if d != DecisionAllow {
				t.Errorf("%s with %s input in ask mode: read-only caps always allow, got %s",
					CapName(cap), in, d)
			}
		}
	}
}

func TestDecideMutatingSemi(t *testing.T) {
	cases := []struct {
		mode string
		in   taint.Level
		want Decision
	}{
		{"auto", taint.Trusted, DecisionAllow},
		{"auto", taint.Semi, DecisionAllow},
		{"ask", taint.Semi, DecisionNeedsApproval},
		{"ask", taint.Trusted, DecisionNeedsApproval},
		{"never", taint.Semi, DecisionDeny},
		{"bogus", taint.Semi, DecisionDeny}, // unknown mode fails closed
	}
	for _, cap := range []agentharnessv1.Capability{
		agentharnessv1.Capability_CAPABILITY_FS_WRITE,
		agentharnessv1.Capability_CAPABILITY_SHELL_RUN,
		agentharnessv1.Capability_CAPABILITY_GIT_COMMIT,
	} {
		for _, tc := range cases {
			d, reason := Decide(cap, tc.in, tc.mode)
			if d != tc.want {
				t.Errorf("%s mode=%s in=%s: got %s (reason %q), want %s",
					CapName(cap), tc.mode, tc.in, d, reason, tc.want)
			}
		}
	}
}

func TestDecideUnknownCapabilityDenied(t *testing.T) {
	for _, cap := range []agentharnessv1.Capability{
		agentharnessv1.Capability_CAPABILITY_UNSPECIFIED,
		agentharnessv1.Capability(4242),
	} {
		d, reason := Decide(cap, taint.Trusted, "auto")
		if d != DecisionDeny {
			t.Fatalf("unknown capability must be denied, got %s", d)
		}
		if !strings.Contains(reason, "not a known device capability") {
			t.Errorf("denial should be explicit: %q", reason)
		}
	}
}

func TestDecideDenialsAreHumanReadable(t *testing.T) {
	d, reason := Decide(agentharnessv1.Capability_CAPABILITY_SHELL_RUN, taint.Untrusted, "ask")
	if d != DecisionDeny {
		t.Fatalf("expected deny, got %s", d)
	}
	if !strings.Contains(reason, "untrusted") || !strings.Contains(reason, "CAPABILITY_SHELL_RUN") {
		t.Errorf("denial reason should name the taint level and the capability: %q", reason)
	}
}
