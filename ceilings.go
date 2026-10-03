// Package policy is the device-side authorization library for agent-harness.
//
// It owns four independent controls, all of which fail closed:
//
//   - Capability ceilings: every proto Capability maps to a maximum taint
//     level (Ceiling). The ceiling is the maximum *input* taint a capability
//     will accept. Read-only capabilities accept up to Untrusted input
//     (reading untrusted content is how it enters the system); mutating
//     capabilities accept at most Semi (model output / local files); remote
//     capabilities (net.fetch, mcp.invoke) accept at most Untrusted.
//   - Grant sets: a verified RunTokenClaims is folded into a GrantSet that
//     answers "is this capability granted for this run?".
//   - Workspace scoping: ScopeCheck resolves symlinks to their final target
//     and requires the resolved path to live inside an allowed root.
//   - Argv allowlist: shell.run/shell.test accept argv arrays only, checked
//     against a closed allowlist of binaries and shapes. There is no code
//     path in this library — or anywhere in the harness — that interprets
//     model text as shell syntax.
//
// Every denial path returns a human-readable reason; denial_reason strings
// are rendered in UI prompts and the audit chain verbatim.
package policy

import (
	"fmt"

	"github.com/agent-harness/contracts/gen/agentharness/v1"
	"github.com/agent-harness/taint"
)

// Class is the effect class of a capability, from the device's point of view.
type Class int

const (
	// ClassReadOnly has no persistent effect on the machine. Reading
	// untrusted content is safe and is how untrusted content is *supposed*
	// to enter the system; the danger is only in what we do with it after.
	ClassReadOnly Class = iota
	// ClassMutating changes device state (filesystem, git history, process
	// execution, accessibility actuation).
	ClassMutating
	// ClassRemote executes off-device (egress proxy, MCP gateway, sandbox).
	// The device never runs it, but it still bounds input taint: a hostile
	// (blocklisted) input must not drive even an off-device call.
	ClassRemote
)

// CapabilityClass classifies a capability. Unknown capabilities are
// ClassMutating's worst-case is not assumed — instead Ceiling reports !ok and
// every check denies them: an unknown capability is never executed.
func CapabilityClass(cap agentharnessv1.Capability) (Class, bool) {
	switch cap {
	case agentharnessv1.Capability_CAPABILITY_FS_READ,
		agentharnessv1.Capability_CAPABILITY_FS_LIST,
		agentharnessv1.Capability_CAPABILITY_FS_SEARCH,
		agentharnessv1.Capability_CAPABILITY_GIT_STATUS,
		agentharnessv1.Capability_CAPABILITY_GIT_LOG,
		agentharnessv1.Capability_CAPABILITY_GIT_DIFF,
		agentharnessv1.Capability_CAPABILITY_DEVICE_STATE:
		return ClassReadOnly, true

	case agentharnessv1.Capability_CAPABILITY_FS_WRITE,
		agentharnessv1.Capability_CAPABILITY_FS_DELETE,
		agentharnessv1.Capability_CAPABILITY_GIT_COMMIT,
		agentharnessv1.Capability_CAPABILITY_GIT_PUSH,
		agentharnessv1.Capability_CAPABILITY_SHELL_RUN,
		agentharnessv1.Capability_CAPABILITY_SHELL_TEST,
		agentharnessv1.Capability_CAPABILITY_AX_CLICK,
		agentharnessv1.Capability_CAPABILITY_AX_TYPE,
		agentharnessv1.Capability_CAPABILITY_AX_FOCUS:
		return ClassMutating, true

	case agentharnessv1.Capability_CAPABILITY_NET_FETCH,
		agentharnessv1.Capability_CAPABILITY_MCP_INVOKE,
		agentharnessv1.Capability_CAPABILITY_SANDBOX_EXECUTE:
		return ClassRemote, true

	case agentharnessv1.Capability_CAPABILITY_SCREEN_CAPTURE,
		agentharnessv1.Capability_CAPABILITY_AX_TREE:
		return ClassReadOnly, true

	default:
		return 0, false
	}
}

// Ceiling returns the maximum input taint the capability accepts.
//
// Choices, and why:
//
//   - Read-only caps (fs.read/list/search, git.status/log/diff, device.state,
//     screen.capture, ax.tree): taint.Untrusted. Reading web-fetched or
//     unknown-origin content must be possible — that is how it gets labelled
//     and quarantined. Reading is not the escalation risk; acting is. Hostile
//     input is still accepted by reads (per "read-only caps always allow")
//     but the *result* taint carries hostile forward, and no mutating
//     capability will ever accept it.
//   - Mutating caps (fs.write, fs.delete, git.commit/push, shell.run/test,
//     ax.click/type): taint.Semi. These may run on model output and
//     user-typed input (both semi), but never on anything that touched a web
//     page, an unknown repo, or a third-party MCP server. This is the
//     mechanism that converts "the model was tricked" into "the operation was
//     blocked by a type system" (docs/03).
//   - Remote caps (net.fetch, mcp.invoke) and sandbox.execute:
//     taint.Untrusted *for input-check purposes only*. These execute off the
//     device (T3 / egress proxy), so the ceiling here bounds what inputs may
//     drive them; untrusted URLs are fetchable, hostile inputs are not. Their
//     output taint is Untrusted by definition regardless of the ceiling —
//     see ResultTaint.
//   - Unknown capabilities: Ceiling reports ok=false and every authorization
//     path denies them. Fail closed.
//
// ax.focus is classified Mutating (Semi): it actuates the user's machine
// (steals focus in any app) even though the capability table does not list it
// as an approval point. Stricter is the safe default for actuation.
func Ceiling(cap agentharnessv1.Capability) (taint.Level, bool) {
	cls, ok := CapabilityClass(cap)
	if !ok {
		return taint.Hostile, false
	}
	switch cls {
	case ClassReadOnly:
		return taint.Untrusted, true
	case ClassMutating:
		return taint.Semi, true
	case ClassRemote:
		return taint.Untrusted, true
	default:
		return taint.Hostile, false
	}
}

// ResultFloor is the minimum result taint a capability's output carries,
// independent of its input, for capabilities the device itself executes.
//
// Rationale (trust ladder in docs/03): local repo files are semi; the device
// cannot verify a local file's provenance, so anything read from disk is at
// least semi. Screen contents and accessibility trees can display hostile web
// content, so they are at least untrusted. device.state reports machine facts
// (uptime, pid) that the device itself computed, so they can be trusted.
// Mutating capabilities return "applied" acknowledgements driven by model
// input, so they are at least semi. Remote capabilities are not executed by
// the device; if one is ever proxied here, its output is untrusted by
// definition.
func ResultFloor(cap agentharnessv1.Capability) (taint.Level, bool) {
	switch cap {
	case agentharnessv1.Capability_CAPABILITY_FS_READ,
		agentharnessv1.Capability_CAPABILITY_FS_LIST,
		agentharnessv1.Capability_CAPABILITY_FS_SEARCH,
		agentharnessv1.Capability_CAPABILITY_GIT_STATUS,
		agentharnessv1.Capability_CAPABILITY_GIT_LOG,
		agentharnessv1.Capability_CAPABILITY_GIT_DIFF:
		// "existing local files" sit at semi on the ladder; the device
		// cannot prove a local file's origin, so never label below semi.
		return taint.Semi, true

	case agentharnessv1.Capability_CAPABILITY_DEVICE_STATE:
		// Machine facts computed by the device itself (uptime, pid, roots).
		return taint.Trusted, true

	case agentharnessv1.Capability_CAPABILITY_SCREEN_CAPTURE,
		agentharnessv1.Capability_CAPABILITY_AX_TREE:
		// The screen can be showing a hostile web page right now.
		return taint.Untrusted, true

	case agentharnessv1.Capability_CAPABILITY_FS_WRITE,
		agentharnessv1.Capability_CAPABILITY_FS_DELETE,
		agentharnessv1.Capability_CAPABILITY_GIT_COMMIT,
		agentharnessv1.Capability_CAPABILITY_GIT_PUSH,
		agentharnessv1.Capability_CAPABILITY_SHELL_RUN,
		agentharnessv1.Capability_CAPABILITY_SHELL_TEST,
		agentharnessv1.Capability_CAPABILITY_AX_CLICK,
		agentharnessv1.Capability_CAPABILITY_AX_TYPE,
		agentharnessv1.Capability_CAPABILITY_AX_FOCUS:
		// Effect acknowledgements were driven by (at best) model output.
		return taint.Semi, true

	case agentharnessv1.Capability_CAPABILITY_NET_FETCH,
		agentharnessv1.Capability_CAPABILITY_MCP_INVOKE:
		// Off-device output is untrusted by definition, whatever its ceiling.
		return taint.Untrusted, true

	case agentharnessv1.Capability_CAPABILITY_SANDBOX_EXECUTE:
		// Sandbox execution exists to run untrusted code; its output is
		// untrusted by definition.
		return taint.Untrusted, true

	default:
		return taint.Hostile, false
	}
}

// ResultTaint is the taint label stamped on a capability result: the join of
// the request's input taint and the capability's result floor. A replayed
// journalled result keeps its original label — replay cannot launder taint.
func ResultTaint(cap agentharnessv1.Capability, input taint.Level) (taint.Level, error) {
	floor, ok := ResultFloor(cap)
	if !ok {
		return taint.Hostile, fmt.Errorf("policy: unknown capability %s", cap)
	}
	if !input.Valid() {
		return taint.Hostile, nil
	}
	return taint.Join(input, floor), nil
}
