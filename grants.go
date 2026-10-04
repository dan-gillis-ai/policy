package policy

import (
	"fmt"

	"github.com/dan-gillis-ai/contracts/gen/agentharness/v1"
)

// Approval modes carried in RunTokenClaims.approval_mode. "never" means the
// run may not take approvals at all (not even ask): a mutating capability
// under "never" is denied outright, never paused.
const (
	ModeAuto  = "auto"
	ModeAsk   = "ask"
	ModeNever = "never"
)

// ValidMode reports whether s is a known approval mode.
func ValidMode(s string) bool {
	return s == ModeAuto || s == ModeAsk || s == ModeNever || s == ""
}

// EffectiveMode resolves a list of candidate modes to the strictest one.
// The device's own mode always participates (the device wins); a request-side
// mode can only narrow, never widen. Unknown values fail closed to "never".
func EffectiveMode(modes ...string) string {
	strictest := ModeAuto
	for _, m := range modes {
		switch m {
		case ModeNever:
			return ModeNever
		case ModeAsk:
			strictest = ModeAsk
		case ModeAuto, "":
			// no narrowing
		default:
			// Unknown mode strings fail closed.
			return ModeNever
		}
	}
	return strictest
}

// GrantSet is the effective grant derived from a *verified* RunTokenClaims.
// The caller must have already checked the HMAC and the TTL; GrantSet only
// encodes membership. A stolen token cannot escalate because the device
// re-derives everything from the token's claims and never from the request.
type GrantSet struct {
	runID         string
	tenantID      string
	graphDigest   string
	approvalMode  string
	expiresUnixMs int64
	caps          map[agentharnessv1.Capability]struct{}
	ordered       []agentharnessv1.Capability
}

// NewGrantSet folds verified claims into a grant set. It rejects malformed
// claims (empty run/tenant ids, unknown approval mode, UNSPECIFIED capability
// entries) — a token whose claims do not parse cleanly is not a token to
// reason leniently about.
func NewGrantSet(claims *agentharnessv1.RunTokenClaims) (*GrantSet, error) {
	if claims == nil {
		return nil, fmt.Errorf("policy: run token claims are missing")
	}
	if claims.GetRunId() == "" {
		return nil, fmt.Errorf("policy: run token claims missing run_id")
	}
	if claims.GetTenantId() == "" {
		return nil, fmt.Errorf("policy: run token claims missing tenant_id")
	}
	if !ValidMode(claims.GetApprovalMode()) {
		return nil, fmt.Errorf("policy: run token claims carry unknown approval_mode %q", claims.GetApprovalMode())
	}
	mode := claims.GetApprovalMode()
	if mode == "" {
		mode = ModeAsk // fail closed: no mode declared means the stricter one
	}
	caps := make(map[agentharnessv1.Capability]struct{}, len(claims.GetCapabilities()))
	ordered := make([]agentharnessv1.Capability, 0, len(claims.GetCapabilities()))
	for _, c := range claims.GetCapabilities() {
		if c == agentharnessv1.Capability_CAPABILITY_UNSPECIFIED {
			return nil, fmt.Errorf("policy: run token claims contain CAPABILITY_UNSPECIFIED")
		}
		if _, dup := caps[c]; dup {
			continue
		}
		caps[c] = struct{}{}
		ordered = append(ordered, c)
	}
	return &GrantSet{
		runID:         claims.GetRunId(),
		tenantID:      claims.GetTenantId(),
		graphDigest:   claims.GetGraphDigest(),
		approvalMode:  mode,
		expiresUnixMs: claims.GetExpiresUnixMs(),
		caps:          caps,
		ordered:       ordered,
	}, nil
}

// Allows reports whether the capability is in the grant set. Empty grant sets
// grant nothing.
func (g *GrantSet) Allows(cap agentharnessv1.Capability) bool {
	if g == nil {
		return false
	}
	_, ok := g.caps[cap]
	return ok
}

// Capabilities returns the granted capabilities in the token's order.
func (g *GrantSet) Capabilities() []agentharnessv1.Capability {
	if g == nil {
		return nil
	}
	// Preserve the order the token listed them in.
	out := make([]agentharnessv1.Capability, 0, len(g.caps))
	for _, c := range g.ordered {
		out = append(out, c)
	}
	return out
}

// RunID returns the run the token is bound to.
func (g *GrantSet) RunID() string {
	if g == nil {
		return ""
	}
	return g.runID
}

// TenantID returns the tenant the token is bound to.
func (g *GrantSet) TenantID() string {
	if g == nil {
		return ""
	}
	return g.tenantID
}

// GraphDigest returns the exact graph digest the token was minted for.
func (g *GrantSet) GraphDigest() string {
	if g == nil {
		return ""
	}
	return g.graphDigest
}

// ApprovalMode returns the token's approval mode ("auto" | "ask" | "never").
func (g *GrantSet) ApprovalMode() string {
	if g == nil {
		return ModeAsk
	}
	return g.approvalMode
}

// ExpiresUnixMs returns the token's expiry in Unix milliseconds (0 = unset,
// which the verifier treats as already expired — tokens must be short-lived).
func (g *GrantSet) ExpiresUnixMs() int64 {
	if g == nil {
		return 0
	}
	return g.expiresUnixMs
}
