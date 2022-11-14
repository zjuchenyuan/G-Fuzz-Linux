// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"github.com/google/syzkaller/gfuzz"
	"github.com/google/syzkaller/pkg/hash"
	"math/rand"
)

// Generate generates a random program with ncalls calls.
// ct contains a set of allowed syscalls, if nil all syscalls are used.
func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, ct, nil)
	for len(p.Calls) < ncalls {
		calls := r.generateCall(s, p, len(p.Calls))
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}
	// For the last generated call we could get additional calls that create
	// resources and overflow ncalls. Remove some of these calls.
	// The resources in the last call will be replaced with the default values,
	// which is exactly what we want.
	for len(p.Calls) > ncalls {
		p.RemoveCall(ncalls - 1)
	}
	p.sanitizeFix()
	p.debugValidate()
	sig := hash.Hash(p.Serialize())
	p.Idx = sig.String()
	return p
}

// GeneratebySyscall generates a random program with ncalls calls and containing syscallIds
// ct contains a set of allowed syscalls, if nil all syscalls are used.
// syscallIds is a list of syscall ids, which must be included in the p
func (target *Target) GeneratebySyscall(rs rand.Source, ncalls int, ct *ChoiceTable, syscallIds []int) *Prog {
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, ct, nil)
	idx := 0
	for idx < len(syscallIds) {
		var calls []*Call
		if idx < len(syscallIds) {
			sid := syscallIds[idx]
			syscallid := sid
			if sid <0 {
				ruleid := -sid-1 // -1 -> 0, -2 -> 1
				syscallid = gfuzz.RuleCalls[ruleid].Id
				gfuzz.UseRuleCall = gfuzz.RuleCalls[ruleid].Rules
			}
			calls = r.generateParticularCall(s, r.target.Syscalls[syscallid])
			if sid <0 {
				gfuzz.UseRuleCall = nil
			}
			idx += 1
		} else {
			calls = r.generateCall(s, p, len(p.Calls))
		}
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}
	// For the last generated call we could get additional calls that create
	// resources and overflow ncalls. Remove some of these calls.
	// The resources in the last call will be replaced with the default values,
	// which is exactly what we want.
	for len(p.Calls) > ncalls {
		p.RemoveCall(ncalls - 1)
	}
	p.sanitizeFix()
	p.debugValidate()
	sig := hash.Hash(p.Serialize())
	p.Idx = sig.String()
	return p
}
