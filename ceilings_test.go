package policy

import (
	"testing"

	"github.com/dan-gillis-ai/contracts/gen/agentharness/v1"
	"github.com/dan-gillis-ai/taint"
)

func TestCeilingsMatchSpec(t *testing.T) {
	cases := []struct {
		cap     agentharnessv1.Capability
		class   Class
		ceiling taint.Level
	}{
		// Read-only: taint.Untrusted
		{agentharnessv1.Capability_CAPABILITY_FS_READ, ClassReadOnly, taint.Untrusted},
		{agentharnessv1.Capability_CAPABILITY_FS_LIST, ClassReadOnly, taint.Untrusted},
		{agentharnessv1.Capability_CAPABILITY_FS_SEARCH, ClassReadOnly, taint.Untrusted},
		{agentharnessv1.Capability_CAPABILITY_GIT_STATUS, ClassReadOnly, taint.Untrusted},
		{agentharnessv1.Capability_CAPABILITY_GIT_LOG, ClassReadOnly, taint.Untrusted},
		{agentharnessv1.Capability_CAPABILITY_GIT_DIFF, ClassReadOnly, taint.Untrusted},
		{agentharnessv1.Capability_CAPABILITY_DEVICE_STATE, ClassReadOnly, taint.Untrusted},
		{agentharnessv1.Capability_CAPABILITY_SCREEN_CAPTURE, ClassReadOnly, taint.Untrusted},
		{agentharnessv1.Capability_CAPABILITY_AX_TREE, ClassReadOnly, taint.Untrusted},
		// Mutating: taint.Semi
		{agentharnessv1.Capability_CAPABILITY_FS_WRITE, ClassMutating, taint.Semi},
		{agentharnessv1.Capability_CAPABILITY_FS_DELETE, ClassMutating, taint.Semi},
		{agentharnessv1.Capability_CAPABILITY_GIT_COMMIT, ClassMutating, taint.Semi},
		{agentharnessv1.Capability_CAPABILITY_GIT_PUSH, ClassMutating, taint.Semi},
		{agentharnessv1.Capability_CAPABILITY_SHELL_RUN, ClassMutating, taint.Semi},
		{agentharnessv1.Capability_CAPABILITY_SHELL_TEST, ClassMutating, taint.Semi},
		{agentharnessv1.Capability_CAPABILITY_AX_CLICK, ClassMutating, taint.Semi},
		{agentharnessv1.Capability_CAPABILITY_AX_TYPE, ClassMutating, taint.Semi},
		{agentharnessv1.Capability_CAPABILITY_AX_FOCUS, ClassMutating, taint.Semi},
		// Remote: input ceiling untrusted (documented in ceilings.go)
		{agentharnessv1.Capability_CAPABILITY_NET_FETCH, ClassRemote, taint.Untrusted},
		{agentharnessv1.Capability_CAPABILITY_MCP_INVOKE, ClassRemote, taint.Untrusted},
		{agentharnessv1.Capability_CAPABILITY_SANDBOX_EXECUTE, ClassRemote, taint.Untrusted},
	}
	for _, tc := range cases {
		cls, ok := CapabilityClass(tc.cap)
		if !ok || cls != tc.class {
			t.Errorf("%s: class = %v ok=%v, want %v", CapName(tc.cap), cls, ok, tc.class)
		}
		ceiling, ok := Ceiling(tc.cap)
		if !ok || ceiling != tc.ceiling {
			t.Errorf("%s: ceiling = %v ok=%v, want %v", CapName(tc.cap), ceiling, ok, tc.ceiling)
		}
	}
}

func TestUnknownCapabilityHasNoCeiling(t *testing.T) {
	if _, ok := Ceiling(agentharnessv1.Capability_CAPABILITY_UNSPECIFIED); ok {
		t.Fatal("unspecified capability must have no ceiling (deny by default)")
	}
	if _, ok := Ceiling(agentharnessv1.Capability(999)); ok {
		t.Fatal("unknown capability must have no ceiling (deny by default)")
	}
}

func TestResultTaintFloors(t *testing.T) {
	cases := []struct {
		cap   agentharnessv1.Capability
		input taint.Level
		want  taint.Level
	}{
		// A read of local content is at least semi (local files sit at semi
		// on the ladder; the device cannot prove provenance).
		{agentharnessv1.Capability_CAPABILITY_FS_READ, taint.Trusted, taint.Semi},
		{agentharnessv1.Capability_CAPABILITY_FS_READ, taint.Semi, taint.Semi},
		{agentharnessv1.Capability_CAPABILITY_FS_READ, taint.Untrusted, taint.Untrusted},
		{agentharnessv1.Capability_CAPABILITY_FS_READ, taint.Hostile, taint.Hostile},
		// device.state facts are computed by the device itself.
		{agentharnessv1.Capability_CAPABILITY_DEVICE_STATE, taint.Trusted, taint.Trusted},
		// Screen contents can be showing a hostile page.
		{agentharnessv1.Capability_CAPABILITY_SCREEN_CAPTURE, taint.Trusted, taint.Untrusted},
		// Mutating effects are at least semi.
		{agentharnessv1.Capability_CAPABILITY_GIT_COMMIT, taint.Semi, taint.Semi},
		{agentharnessv1.Capability_CAPABILITY_SHELL_RUN, taint.Trusted, taint.Semi},
		// Remote output is untrusted by definition.
		{agentharnessv1.Capability_CAPABILITY_NET_FETCH, taint.Semi, taint.Untrusted},
	}
	for _, tc := range cases {
		got, err := ResultTaint(tc.cap, tc.input)
		if err != nil {
			t.Fatalf("%s: %v", CapName(tc.cap), err)
		}
		if got != tc.want {
			t.Errorf("%s input=%s: result taint = %s, want %s",
				CapName(tc.cap), tc.input, got, tc.want)
		}
	}
}

func TestResultTaintHostilePropagatesForever(t *testing.T) {
	for cap := range DefaultArgvRules() {
		_ = cap
	}
	// Hostile in, hostile out, for every known capability.
	for _, c := range []agentharnessv1.Capability{
		agentharnessv1.Capability_CAPABILITY_FS_READ,
		agentharnessv1.Capability_CAPABILITY_FS_WRITE,
		agentharnessv1.Capability_CAPABILITY_SHELL_RUN,
		agentharnessv1.Capability_CAPABILITY_GIT_COMMIT,
		agentharnessv1.Capability_CAPABILITY_NET_FETCH,
	} {
		got, err := ResultTaint(c, taint.Hostile)
		if err != nil {
			t.Fatal(err)
		}
		if got != taint.Hostile {
			t.Errorf("%s: hostile input yielded %s; hostile propagates forever", CapName(c), got)
		}
	}
}

func TestTaintProtoRoundTrip(t *testing.T) {
	for l := taint.Trusted; l <= taint.Hostile; l++ {
		if got := TaintFromProto(TaintToProto(l)); got != l {
			t.Errorf("round trip %s -> %s", l, got)
		}
	}
	if TaintFromProto(agentharnessv1.TaintLevel_TAINT_LEVEL_UNSPECIFIED) != taint.Hostile {
		t.Error("unspecified wire taint must be treated as hostile")
	}
}
