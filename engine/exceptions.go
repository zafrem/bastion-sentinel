package engine

import (
	"sync/atomic"

	"github.com/zafrem/bastion-sentinel/exceptions"
)

// The exceptions store is process-wide so it survives config reloads, which
// rebuild the engines. nil (the default) means no exceptions: every rule is
// enforced.
var excClient atomic.Pointer[exceptions.Client]

// SetExceptions installs the exception store the engines consult.
func SetExceptions(c *exceptions.Client) { excClient.Store(c) }

// Allowed reports whether an active exception exempts rule for this caller,
// for callers outside the engine package (for example the industry filters).
func Allowed(rule, tenant, user string) (exceptionID string, ok bool) {
	return allowed(rule, tenant, user)
}

// allowed reports whether an active exception exempts rule for this caller.
func allowed(rule, tenant, user string) (string, bool) {
	c := excClient.Load()
	if c == nil {
		return "", false
	}
	return c.Allowed(rule, tenant, user)
}

// allExempt reports whether every rule ID has an active exception, returning
// the exception IDs used. An empty list is never exempt.
func allExempt(ruleIDs []string, tenant, user string) ([]string, bool) {
	if len(ruleIDs) == 0 {
		return nil, false
	}
	var used []string
	for _, rid := range ruleIDs {
		id, ok := allowed("sentinel.out.pii:"+rid, tenant, user)
		if !ok {
			return nil, false
		}
		used = append(used, id)
	}
	return used, true
}

func addUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}
