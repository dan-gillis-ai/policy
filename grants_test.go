package policy

import (
	"testing"

	"github.com/dan-gillis-ai/contracts/gen/agentharness/v1"
)

func testClaims() *agentharnessv1.RunTokenClaims {
	return &agentharnessv1.RunTokenClaims{
		RunId:       "run-1",
		TenantId:    "acme",
		GraphDigest: "sha256:abcd",
		Capabilities: []agentharnessv1.Capability{
			agentharnessv1.Capability_CAPABILITY_FS_READ,
			agentharnessv1.Capability_CAPABILITY_SHELL_RUN,
		},
		ExpiresUnixMs: 9999999999999,
		ApprovalMode:  "auto",
	}
}

func TestGrantSetAllows(t *testing.T) {
	g, err := NewGrantSet(testClaims())
	if err != nil {
		t.Fatal(err)
	}
	if !g.Allows(agentharnessv1.Capability_CAPABILITY_FS_READ) {
		t.Error("fs.read should be granted")
	}
	if !g.Allows(agentharnessv1.Capability_CAPABILITY_SHELL_RUN) {
		t.Error("shell.run should be granted")
	}
	if g.Allows(agentharnessv1.Capability_CAPABILITY_FS_WRITE) {
		t.Error("fs.write must not be granted — a stolen token cannot escalate")
	}
	if g.Allows(agentharnessv1.Capability_CAPABILITY_GIT_PUSH) {
		t.Error("git.push must not be granted")
	}
	if g.RunID() != "run-1" || g.TenantID() != "acme" {
		t.Errorf("binding mismatch: run=%q tenant=%q", g.RunID(), g.TenantID())
	}
	if g.ApprovalMode() != "auto" {
		t.Errorf("approval mode = %q, want auto", g.ApprovalMode())
	}
}

func TestGrantSetNilGrantsNothing(t *testing.T) {
	var g *GrantSet
	if g.Allows(agentharnessv1.Capability_CAPABILITY_FS_READ) {
		t.Fatal("nil grant set must grant nothing")
	}
}

func TestGrantSetEmptyCapsGrantNothing(t *testing.T) {
	c := testClaims()
	c.Capabilities = nil
	g, err := NewGrantSet(c)
	if err != nil {
		t.Fatal(err)
	}
	for cap := range map[agentharnessv1.Capability]bool{
		agentharnessv1.Capability_CAPABILITY_FS_READ:   true,
		agentharnessv1.Capability_CAPABILITY_SHELL_RUN: true,
	} {
		if g.Allows(cap) {
			t.Errorf("empty caps must grant nothing, but %s allowed", CapName(cap))
		}
	}
}

func TestGrantSetRejectsMalformed(t *testing.T) {
	c := testClaims()
	c.RunId = ""
	if _, err := NewGrantSet(c); err == nil {
		t.Error("missing run_id must be rejected")
	}
	c = testClaims()
	c.TenantId = ""
	if _, err := NewGrantSet(c); err == nil {
		t.Error("missing tenant_id must be rejected")
	}
	c = testClaims()
	c.ApprovalMode = "yolo"
	if _, err := NewGrantSet(c); err == nil {
		t.Error("unknown approval mode must be rejected")
	}
	c = testClaims()
	c.Capabilities = []agentharnessv1.Capability{agentharnessv1.Capability_CAPABILITY_UNSPECIFIED}
	if _, err := NewGrantSet(c); err == nil {
		t.Error("CAPABILITY_UNSPECIFIED in claims must be rejected")
	}
	if _, err := NewGrantSet(nil); err == nil {
		t.Error("nil claims must be rejected")
	}
}

func TestGrantSetEmptyModeFailsClosedToAsk(t *testing.T) {
	c := testClaims()
	c.ApprovalMode = ""
	g, err := NewGrantSet(c)
	if err != nil {
		t.Fatal(err)
	}
	if g.ApprovalMode() != ModeAsk {
		t.Errorf("empty approval mode must fail closed to ask, got %q", g.ApprovalMode())
	}
}

func TestEffectiveModeStricterWins(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"auto", "auto"}, "auto"},
		{[]string{"auto", "ask"}, "ask"},
		{[]string{"ask", "auto"}, "ask"},
		{[]string{"ask", "never"}, "never"},
		{[]string{"auto", "never"}, "never"},
		{[]string{"auto", "nonsense"}, "never"},
		{[]string{}, "auto"},
	}
	for _, tc := range cases {
		if got := EffectiveMode(tc.in...); got != tc.want {
			t.Errorf("EffectiveMode(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
