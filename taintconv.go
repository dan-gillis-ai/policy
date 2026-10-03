package policy

import (
	"github.com/agent-harness/contracts/gen/agentharness/v1"
	"github.com/agent-harness/taint"
)

// TaintFromProto converts a wire taint level to the lattice. Fail closed: an
// unset or unknown TaintLevel is Hostile — per the proto contract, "an unset
// taint must be treated as hostile".
func TaintFromProto(l agentharnessv1.TaintLevel) taint.Level {
	switch l {
	case agentharnessv1.TaintLevel_TAINT_LEVEL_TRUSTED:
		return taint.Trusted
	case agentharnessv1.TaintLevel_TAINT_LEVEL_SEMI:
		return taint.Semi
	case agentharnessv1.TaintLevel_TAINT_LEVEL_UNTRUSTED:
		return taint.Untrusted
	case agentharnessv1.TaintLevel_TAINT_LEVEL_HOSTILE:
		return taint.Hostile
	default:
		// TAINT_LEVEL_UNSPECIFIED and any value the binary does not know.
		return taint.Hostile
	}
}

// TaintToProto converts a lattice level to the wire form.
func TaintToProto(l taint.Level) agentharnessv1.TaintLevel {
	switch l {
	case taint.Trusted:
		return agentharnessv1.TaintLevel_TAINT_LEVEL_TRUSTED
	case taint.Semi:
		return agentharnessv1.TaintLevel_TAINT_LEVEL_SEMI
	case taint.Untrusted:
		return agentharnessv1.TaintLevel_TAINT_LEVEL_UNTRUSTED
	default:
		return agentharnessv1.TaintLevel_TAINT_LEVEL_HOSTILE
	}
}

// CapName returns the proto enum name for a capability (e.g.
// "CAPABILITY_FS_READ"), for logs and human-readable denials.
func CapName(cap agentharnessv1.Capability) string {
	return agentharnessv1.Capability_name[int32(cap)]
}
