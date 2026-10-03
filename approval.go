package policy

import (
	"fmt"

	"github.com/agent-harness/contracts/gen/agentharness/v1"
	"github.com/agent-harness/taint"
)

// Decision is the outcome of an approval-policy evaluation.
type Decision int

const (
	DecisionDeny Decision = iota
	DecisionNeedsApproval
	DecisionAllow
)

func (d Decision) String() string {
	switch d {
	case DecisionAllow:
		return "allow"
	case DecisionNeedsApproval:
		return "needs_approval"
	default:
		return "deny"
	}
}

// Decide evaluates the approval policy for one capability invocation.
//
// Rules (in order):
//
//  1. Unknown capability → Deny. Nothing unregistered ever executes.
//  2. Read-only capabilities → Allow unconditionally. Reading is how
//     untrusted content enters the system; the taint system quarantines the
//     result, and no mutating capability will accept it downstream.
//     (ResultTaint carries input taint — including Hostile — forward, so a
//     hostile read can never feed a shell, a write, or a commit.)
//  3. Mutating and remote capabilities:
//     a. input taint above the capability's ceiling → Deny. **Ceilings are
//     never approvable upward.** An approval dialog is for decisions the
//     user can reasonably make under time pressure; "run this shell command
//     whose arguments came from a hostile web page" is not one. This is a
//     deliberate tightening of docs/01 step 19 and docs/05 step 8 (which say
//     "PAUSE for approval" on taint excess); docs/03's "shell.run refuses
//     anything that has touched a web page" and the type-system framing are
//     the authoritative intent, and the device must not let a fast-clicking
//     user become the injection's last mile.
//     b. effective mode "never" → Deny (the run declined approval entirely).
//     c. effective mode "auto" → Allow.
//     d. effective mode "ask" → NeedsApproval (PAUSE; resolved by the
//     approval queue with a TTL; TTL expiry default-denies).
//
// The returned reason is rendered verbatim in UI prompts and audit records.
func Decide(cap agentharnessv1.Capability, input taint.Level, mode string) (Decision, string) {
	ceiling, ok := Ceiling(cap)
	if !ok {
		return DecisionDeny, fmt.Sprintf(
			"capability %s is not a known device capability; denied by default",
			capDisplay(cap))
	}
	cls, _ := CapabilityClass(cap)

	if cls == ClassReadOnly {
		return DecisionAllow, fmt.Sprintf(
			"read-only capability %s: no persistent effect; result carries input taint %s forward",
			capDisplay(cap), input)
	}

	// Mutating / remote from here on.
	if input.Above(ceiling) {
		return DecisionDeny, fmt.Sprintf(
			"input taint %s exceeds the %s ceiling (%s) for %s; taint above a ceiling is never approvable upward — narrow the capability or reduce the taint of the inputs",
			input, ceiling, capDisplay(cap), capDisplay(cap))
	}

	switch EffectiveMode(mode) {
	case ModeNever:
		return DecisionDeny, fmt.Sprintf(
			"capability %s requires approval and this run's approval mode is \"never\"; the call was denied rather than paused",
			capDisplay(cap))
	case ModeAuto:
		return DecisionAllow, fmt.Sprintf(
			"capability %s auto-approved: input taint %s within ceiling %s and approval mode is \"auto\"",
			capDisplay(cap), input, ceiling)
	default: // ask
		return DecisionNeedsApproval, fmt.Sprintf(
			"capability %s is mutating with input taint %s (ceiling %s) and approval mode is \"ask\"; waiting for the user",
			capDisplay(cap), input, ceiling)
	}
}

func capDisplay(cap agentharnessv1.Capability) string {
	name := CapName(cap)
	if name == "" {
		return fmt.Sprintf("capability(%d)", int32(cap))
	}
	return name
}
