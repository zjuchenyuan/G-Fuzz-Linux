// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"github.com/google/syzkaller/gfuzz"
	"math"
	"math/rand"
	"os"
	"runtime/debug"
	"sort"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

// Proc represents a single fuzzing process (executor).
type Proc struct {
	fuzzer          *Fuzzer
	pid             int
	env             *ipc.Env
	rnd             *rand.Rand
	execOpts        *ipc.ExecOpts
	execOptsCollide *ipc.ExecOpts
	execOptsCover   *ipc.ExecOpts
	execOptsComps   *ipc.ExecOpts
	exectimes         uint32
	newseeds          uint32
	startTime         time.Time
}

func newProc(fuzzer *Fuzzer, pid int) (*Proc, error) {
	env, err := ipc.MakeEnv(fuzzer.config, pid)
	if err != nil {
		return nil, err
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12))
	execOptsCollide := *fuzzer.execOpts
	execOptsCollide.Flags &= ^ipc.FlagCollectSignal
	execOptsCover := *fuzzer.execOpts
	execOptsCover.Flags |= ipc.FlagCollectCover
	execOptsComps := *fuzzer.execOpts
	execOptsComps.Flags |= ipc.FlagCollectComps
	gfuzz.GFUZZlog("proc execOpts: %v, execOptsCover: %v", fuzzer.execOpts, execOptsCover)
	proc := &Proc{
		fuzzer:          fuzzer,
		pid:             pid,
		env:             env,
		rnd:             rnd,
		execOpts:        fuzzer.execOpts,
		execOptsCollide: &execOptsCollide,
		execOptsCover:   &execOptsCover,
		execOptsComps:   &execOptsComps,
		startTime:         fuzzer.startTime,
	}
	return proc, nil
}

func (proc *Proc) loopGenerate() {
	gfuzz.GFUZZlog("GFUZZ:loopGenerate")
	proc.fuzzer.changeMode("generate")
	startTime := proc.fuzzer.startTime // manager start time
	shouldContinue := func() bool {
		if time.Since(proc.fuzzer.LastNewSeedTime).Seconds() < 180 && time.Since(startTime).Seconds() < 1800 {
			// exit generate mode when it stucks over 3 minutes, and at most 30 minutes
			return true
		}
		return false
	}
	defer func() {
		proc.fuzzer.workQueue.mu.Lock()
		proc.fuzzer.workQueue.smash, proc.fuzzer.workQueue.smashSaved = proc.fuzzer.workQueue.smashSaved, proc.fuzzer.workQueue.smash
		proc.fuzzer.workQueue.mu.Unlock()
		proc.fuzzer.StageExit()
	}()
	for round := 0; shouldContinue(); round++ {
		//gfuzz.GFUZZlog("GFUZZ:loopGenerate round:%v", round)

		syscallIds := make([]int, 0)
		trytimes := 0
		if len(proc.fuzzer.SyscallSeedsHead)>0 {
			for len(syscallIds) < 1 || proc.rnd.Intn(5) > 0 {
				trytimes += 1
				if trytimes > 100 {
					gfuzz.GFUZZlog("GFUZZ:ERROR cannot generate enough syscallids within 100 tries HEAD")
					return
				}
				basecall_i := proc.rnd.Intn(len(proc.fuzzer.SyscallSeedsHead))
				if len(proc.fuzzer.SyscallSeedsHead[basecall_i]) == 0 {
					continue
				}
				syscallId := proc.fuzzer.SyscallSeedsHead[basecall_i][proc.rnd.Intn(len(proc.fuzzer.SyscallSeedsHead[basecall_i]))]
				syscallIds = append(syscallIds, syscallId)
			}
		}
		if len(proc.fuzzer.SyscallSeedsTail)>0 {
			for len(syscallIds) < 1 || proc.rnd.Intn(5) > 0 {
				trytimes += 1
				if trytimes > 100 {
					gfuzz.GFUZZlog("GFUZZ:ERROR cannot generate enough syscallids within 100 tries TAIL")
					return
				}
				basecall_i := proc.rnd.Intn(len(proc.fuzzer.SyscallSeedsTail))
				if len(proc.fuzzer.SyscallSeedsTail[basecall_i]) == 0 {
					continue
				}
				syscallId := proc.fuzzer.SyscallSeedsTail[basecall_i][proc.rnd.Intn(len(proc.fuzzer.SyscallSeedsTail[basecall_i]))]
				syscallIds = append(syscallIds, syscallId)
			}
		}
		//gfuzz.GFUZZlog("GFUZZ:GeneratebySyscall syscallIds:%v", syscallIds)

		ct := proc.fuzzer.choiceTable
		p := proc.fuzzer.target.GeneratebySyscall(proc.rnd, prog.RecommendedCalls, ct, syscallIds)

		//gfuzz.GFUZZlog("GFUZZ:loopGenerate_generate %v >>>\n%v<<<", syscallIds, string(p.Serialize()))
		gfuzz.Status = "Ggenerate"
		proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)

		item := proc.fuzzer.workQueue.dequeue()
		for item != nil {
			switch item := item.(type) {
			case *WorkTriage:
				gfuzz.Status = "Gtriage+" + item.status
				proc.triageInput(item)
			case *WorkCandidate:
				gfuzz.Status = "Gcandidate"
				proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
			case *WorkSmash:
				gfuzz.Status = "Gsmash"
				shouldSmashNow := false
				for pc := range item.newSignal {
					if dis, ok := proc.fuzzer.pc2distance[uint64(pc)]; ok && dis < 10 {
						shouldSmashNow = true
						break
					}
				}
				if shouldSmashNow {
					proc.smashInput(item)
				} else {
					item.times = 10 // do less repeat times for unrelated ones
					proc.fuzzer.workQueue.mu.Lock()
					proc.fuzzer.workQueue.smashSaved = append(proc.fuzzer.workQueue.smashSaved, item)
					proc.fuzzer.workQueue.mu.Unlock()
					//gfuzz.GFUZZlog("GFUZZ:skip_smash %v len(saved):%v", item.p.Idx, len(proc.fuzzer.workQueue.smashSaved))
				}
			default:
				log.Fatalf("unknown work type: %#v", item)
			}
			item = proc.fuzzer.workQueue.dequeue()
		}
	}

}

func (proc *Proc) loopDirected() {
	proc.fuzzer.changeMode("directed")
	savedLen, newLen := proc.fuzzer.workQueue.Stash()
	gfuzz.GFUZZlog("GFUZZ:loopDirected savedLen:%v newLen:%v LastNewSeedTime:%v StageStartTime:%v corpusLen:%v", savedLen, newLen, proc.fuzzer.LastNewSeedTime, proc.fuzzer.StageStartTime, len(proc.fuzzer.corpus))
	defer func() {
		gfuzz.GFUZZlog("GFUZZ:loopDirected_exit recovered:%v", proc.fuzzer.workQueue.StashPop())
		proc.fuzzer.StageExit()
	}()
	shouldContinue := func() bool {
		//gfuzz.GFUZZlog("GFUZZ:shouldContinue1 %v %v %v", proc.fuzzer.StageStartTime, time.Since(proc.fuzzer.StageStartTime).Seconds(), float64(proc.fuzzer.directchooseForceExittime))
		//gfuzz.GFUZZlog("GFUZZ:shouldContinue2 %v %v %v", proc.fuzzer.LastNewSeedTime, time.Since(proc.fuzzer.LastNewSeedTime).Seconds(), float64(proc.fuzzer.directchooseExittime))
		return time.Since(proc.fuzzer.StageStartTime).Seconds() <= float64(proc.fuzzer.directchooseForceExittime) &&
			time.Since(proc.fuzzer.LastNewSeedTime).Seconds() <= float64(proc.fuzzer.directchooseExittime)
	}
	for round := 0; shouldContinue(); round++ {
		gfuzz.GFUZZlog("GFUZZ:loopDirected round:%v", round)
		fuzzerSnapshot := proc.fuzzer.snapshot()
		chooseidx := make([]int, 0)
		for i := 0; i < 100; i++ {
			idx := proc.rnd.Intn(len(fuzzerSnapshot.corpus))
			if idx >= len(fuzzerSnapshot.corpus) {
				continue
			}
			chooseidx = append(chooseidx, idx)
		}
		sort.SliceStable(chooseidx, func(_i int, _j int) bool {
			i := chooseidx[_i]
			j := chooseidx[_j]
			if proc.fuzzer.corpusClosetDistance[i] == proc.fuzzer.corpusClosetDistance[j] {
				return proc.fuzzer.corpusDistance[i] < proc.fuzzer.corpusDistance[j]
			}
			return proc.fuzzer.corpusClosetDistance[i] < proc.fuzzer.corpusClosetDistance[j]
		})
		//gfuzz.GFUZZlog("GFUZZ:loopDirected chooseidx:%v", chooseidx)

		for i := 0; i < 30; i++ {
			//gfuzz.GFUZZlog("GFUZZ:loopDirected_loop30 round:%v i:%v len_triage:%v s:%v len_smash:%v ss:%v",
			//	round, i, len(proc.fuzzer.workQueue.triage), len(proc.fuzzer.workQueue.triageSaved), len(proc.fuzzer.workQueue.smash), len(proc.fuzzer.workQueue.smashSaved))

			ct := proc.fuzzer.choiceTable

			// Mutate an existing prog.
			idx := chooseidx[i]
			p := fuzzerSnapshot.corpus[idx].Clone()
			//gfuzz.GFUZZlog("GFUZZ:loopDirected execute i:%v idx:%v p.Idx:%v avg:%v closetdistance:%v",
			//	i, idx, p.Idx, proc.fuzzer.corpusDistance[idx], proc.fuzzer.corpusClosetDistance[idx])
			gfuzz.Status = fmt.Sprintf("loop_directed %v", idx)
			elapsed_time := time.Since(proc.fuzzer.startTime).Seconds()
			chance := proc.fuzzer.MutateDirectChance
			chance -= int(elapsed_time/3600*10)
			if chance < 20 {
				chance = 20
			}
			p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus,
				proc.fuzzer.SyscallSeedsHead, proc.fuzzer.SyscallSeedsTail, chance)
			log.Logf(1, "#%v: mutated", proc.pid)
			proc.execute(proc.execOpts, p, ProgNormal, StatFuzz)
		}
		//gfuzz.GFUZZlog("GFUZZ:loopDirected_after30 round:%v len_triage:%v", round, len(proc.fuzzer.workQueue.triage))

		item := proc.fuzzer.workQueue.dequeue()
		for item != nil {
			switch item := item.(type) {
			case *WorkTriage:
				gfuzz.Status = "Dtriage+" + item.status
				proc.triageInput(item)
			case *WorkCandidate:
				gfuzz.Status = "Dcandidate"
				proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
			case *WorkSmash:
				gfuzz.Status = "Dsmash"
				proc.smashInput(item)
			default:
				log.Fatalf("unknown work type: %#v", item)
			}
			item = proc.fuzzer.workQueue.dequeue()
		}
	}
}


func (proc *Proc) loop() {
	// recover last mode, do not change timestamp in enter mode, only do that after a mode exit
	logprefix := "recover"
	switch proc.fuzzer.mode{
	case "init":
		logprefix = "init"
		fallthrough
	case "generate":
		if len(proc.fuzzer.SyscallSeedsHead) > 0 || len(proc.fuzzer.SyscallSeedsTail) > 0 {
			gfuzz.GFUZZlog("GFUZZ:%v loopGenerate start", logprefix)
			proc.loopGenerate()
			gfuzz.GFUZZlog("GFUZZ:%v loopGenerate finished", logprefix)
		}
		fallthrough
	case "directed":
		if len(proc.fuzzer.corpus) > 100 && proc.fuzzer.directchooseEntertime > 0 {
			gfuzz.GFUZZlog("GFUZZ:%v loopDirected start", logprefix)
			proc.loopDirected()
			gfuzz.GFUZZlog("GFUZZ:%v loopDirected finished", logprefix)
		}
	case "coverage":
		gfuzz.GFUZZlog("GFUZZ:recover coverage start")
	default:
		gfuzz.GFUZZlog("GFUZZ:error unknown Mode: %v", proc.fuzzer.mode)
	}
	proc.fuzzer.changeMode("coverage")

	generatePeriod := 100
	userandom := proc.execOpts.Flags&ipc.FlagEnableRandomChoose != 0
	useglobaldistance := proc.execOpts.Flags&ipc.FlagEnableGlobalDistance != 0
	useseedlimit := proc.execOpts.Flags&ipc.FlagEnableSeedExecLimit != 0
	usecooling := proc.fuzzer.cooling_tx > 0
	t_x := proc.fuzzer.cooling_tx //time to exploit for cooling schedule
	gfuzz.GFUZZlog("GFUZZ:procloop userandom:%v useglobaldistance:%v useseedlimit:%v cooling_t_x:%v starttime:%v useclosetdistance:%v", userandom, useglobaldistance, useseedlimit, t_x, proc.startTime, proc.fuzzer.useClosetDistance)
	if proc.fuzzer.config.Flags&ipc.FlagSignal == 0 {
		// If we don't have real coverage signal, generate programs more frequently
		// because fallback signal is weak.
		generatePeriod = 2
	}
	var oldp *prog.Prog
	var energy int
	var idx int
	for i := 0; ; i++ {
		item := proc.fuzzer.workQueue.dequeue()
		if item != nil {
			switch item := item.(type) {
			case *WorkTriage:
				//gfuzz.GFUZZlog("GFUZZ:task Triage")
				gfuzz.Status = "triage+" + item.status
				proc.triageInput(item)
			case *WorkCandidate:
				//gfuzz.GFUZZlog("GFUZZ:task Candidate")
				gfuzz.Status = "candidate"
				proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
			case *WorkSmash:
				//gfuzz.GFUZZlog("GFUZZ:task Smash")
				gfuzz.Status = "smash"
				proc.smashInput(item)
			default:
				log.Fatalf("unknown work type: %#v", item)
			}
			if proc.rnd.Int63n(5) > 1 {
				continue
			}
		}

		ct := proc.fuzzer.choiceTable
		fuzzerSnapshot := proc.fuzzer.snapshot()
		var usedTime time.Duration
		if len(fuzzerSnapshot.corpus) < 10 || i%generatePeriod == 0 {
			// Generate a new prog.
			p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
			//log.Logf(1, "#%v: generated", proc.pid)
			//gfuzz.GFUZZlog("GFUZZ:generated %v", p)
			gfuzz.Status = "generate"
			proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatGenerate)
		} else {
			if len(fuzzerSnapshot.corpus) > 100 && proc.fuzzer.directchooseEntertime > 0 &&
				(time.Since(proc.fuzzer.StageStartTime).Seconds() > float64(proc.fuzzer.directchooseForceEntertime) ||
					time.Since(proc.fuzzer.LastNewSeedTime).Seconds() > float64(proc.fuzzer.directchooseEntertime)) {
				proc.fuzzer.StageExit() // exit from coverage, change to directed mode
				proc.loopDirected()
				gfuzz.GFUZZlog("GFUZZ:after_loopDirected")
				proc.fuzzer.changeMode("coverage")
			}
			// Mutate an existing prog.
			var p *prog.Prog
			if energy > 0 && usedTime < 60*time.Second {
				energy--
				p = oldp.Clone()
				//gfuzz.GFUZZlog("GFUZZ:oldprog %v %v %v", idx, p.Idx, energy)
				gfuzz.Status = fmt.Sprintf("use_energy %v %v", idx, energy)
			} else {
				if usedTime >= 60*time.Second {
					gfuzz.GFUZZlog("GFUZZ:energy_timeout %v energy:%v", oldp.Idx, energy)
				}
				if userandom {
					idx = proc.rnd.Intn(len(fuzzerSnapshot.corpus))
					gfuzz.Status = fmt.Sprintf("choose_random %v", idx)
				} else {
					idx = fuzzerSnapshot.chooseProgram_idx(proc.rnd)
					gfuzz.Status = fmt.Sprintf("choose_signal %v", idx)
				}
				if idx >= len(fuzzerSnapshot.corpus) {
					continue
				}

				p = fuzzerSnapshot.corpus[idx].Clone()
				usedTime = 0 * time.Second
				var seedcost, avgcost float64
				if (proc.execOpts.Flags&ipc.FlagEnableSeedExecLimit != 0) && proc.newseeds > 10 {
					avgcost = float64(proc.exectimes) / float64(proc.newseeds)
					if proc.fuzzer.seedProfit[p.Idx] > 0 {
						seedcost = float64(proc.fuzzer.seedExectimes[p.Idx]) / float64(proc.fuzzer.seedProfit[p.Idx])
					} else {
						seedcost = float64(proc.fuzzer.seedExectimes[p.Idx])
					}
					if seedcost > 2*avgcost && seedcost > 20 {
						gfuzz.GFUZZlog("GFUZZ:skipexecute %v status:%v seedcost:%v avgcost:%v exectimes:%v", p.Idx, gfuzz.Status, seedcost, avgcost, proc.exectimes)
						continue
					}
				}

				if !proc.fuzzer.mimicBaseline && proc.fuzzer.enableDistance {
					//we only use energy when enabled distance and not moreSmash mode
					var T float64
					seedDistantce := (fuzzerSnapshot.corpusDistance[idx] - fuzzerSnapshot.corpusDistance_min) / (fuzzerSnapshot.corpusDistance_max - fuzzerSnapshot.corpusDistance_min)
					//energy = int((1 - seedDistantce) * 32)
					if usecooling {
						progress_to_tx := time.Now().Sub(proc.startTime).Seconds() / float64(t_x)
						if progress_to_tx > 2 {
							T = 0
						} else {
							T = math.Pow(20.0, -progress_to_tx)
						}
						p := (1.0-float64(seedDistantce))*(1.0-T) + 0.5*T
						energy = int(math.Pow(2.0, 7*(p))) - 1
					} else if useglobaldistance {
						maxweight := 7 * float64(1-fuzzerSnapshot.corpusDistance_min/fuzzerSnapshot.corpusDistance_max)
						energy = int(math.Pow(2, maxweight*float64(1-seedDistantce)))
					} else {
						energy = int(math.Pow(2, 7*float64(1-seedDistantce)))
					}
					if fuzzerSnapshot.corpusClosetDistance[idx] < 20 {
						energy *= 2
					}
					if fuzzerSnapshot.corpusClosetDistance[idx] < 10 {
						energy *= 2
					}
					oldp = p.Clone()
					pcinboundary := make([]uint32, 0)
					if proc.fuzzer.enablePCCFG {
						seedsignal := proc.fuzzer.corpusSignals[idx]
						for seedpc := range seedsignal {
							if _, ok := proc.fuzzer.boundary[seedpc]; ok {
								if len(proc.fuzzer.boundary[seedpc]) < 50 { // if a boundary has more than 50 seeds, we treat it as a really hard boundary and skip it
									pcinboundary = append(pcinboundary, seedpc)
								}
							}
						}
						energy *= int(math.Min(float64(len(pcinboundary)+1), 5))
					}
					//gfuzz.GFUZZlog("GFUZZ:choose idx:%v %v distance:%v closet:%v relative:%v energy:%v, len(boundary):%v pcinboundary:%v T:%v",
					//	idx, p.Idx, fuzzerSnapshot.corpusDistance[idx], fuzzerSnapshot.corpusClosetDistance[idx], seedDistantce, energy, len(proc.fuzzer.boundary), len(pcinboundary), T)
				} else if !proc.fuzzer.mimicBaseline && proc.fuzzer.enablePCCFG { //no target, only boundary
					oldp = p.Clone()
					pcinboundary := make([]uint32, 0)
					seedsignal := proc.fuzzer.corpusSignals[idx]
					for seedpc := range seedsignal {
						if _, ok := proc.fuzzer.boundary[seedpc]; ok {
							if len(proc.fuzzer.boundary[seedpc]) < 50 { // if a boundary has more than 50 seeds, we treat it as a really hard boundary and skip it
								pcinboundary = append(pcinboundary, seedpc)
							}
						}
					}
					energy = int(math.Min(float64(len(pcinboundary)), 5))
					//gfuzz.GFUZZlog("GFUZZ:onlycfg_choose idx:%v %v energy:%v len(boundary):%v pcinboundary:%v",
					//	idx, p.Idx, energy, len(proc.fuzzer.boundary), len(pcinboundary))
				}
				if energy > 128 {
					//gfuzz.GFUZZlog("GFUZZ:energy_too_big idx:%v %v energy:%v", idx, p.Idx, energy)
					energy = 128
				}
			}
			//gfuzz.GFUZZlog("GFUZZ:chooseMutate %v", p.Idx)
			elapsed_time := time.Since(proc.fuzzer.startTime).Seconds()
			chance := proc.fuzzer.MutateDirectChance
			chance -= int(elapsed_time/3600*10)
			if chance < 0 {
				chance = 0
			}
			p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus,
				proc.fuzzer.SyscallSeedsHead, proc.fuzzer.SyscallSeedsTail, chance)
			log.Logf(1, "#%v: mutated", proc.pid)
			stime := time.Now()
			proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatFuzz)
			usedTime += time.Since(stime)
		}
	}
}

func (proc *Proc) triageInput(item *WorkTriage) {
	log.Logf(1, "#%v: triaging type=%x", proc.pid, item.flags)
	len_calls := len(item.p.Calls)

	prio := signalPrio(item.p, &item.info, item.call)
	tmpsig := item.info.Signal
	if proc.fuzzer.mode == "directed" && len(proc.fuzzer.gfuzzfilter)>0{
		// apply gfuzzfilter only in directed mode
		beforelen := len(tmpsig)
		tmpsig = make([]uint32, 0)
		for _,pc := range item.info.Signal{
			if ok := proc.fuzzer.gfuzzfilter[pc]; ok {
				tmpsig = append(tmpsig, pc)
			}
		}
		afterlen := len(tmpsig)
		gfuzz.GFUZZlog("GFUZZ:gfuzzfilter before:%v after:%v", beforelen, afterlen)
	}
	inputSignal := signal.FromRaw(tmpsig, prio)
	newSignal := proc.fuzzer.corpusSignalDiff(inputSignal)
	if newSignal.Empty() {
		return
	}
	callName := ".extra"
	logCallName := "extra"
	if item.call != -1 {
		callName = item.p.Calls[item.call].Meta.Name
		logCallName = fmt.Sprintf("call #%v %v", item.call, callName)
	}
	log.Logf(3, "triaging input for %v (new signal=%v)", logCallName, newSignal.Len())
	var inputCover cover.Cover
	const (
		signalRuns       = 3
		minimizeAttempts = 3
	)
	// Compute input coverage and non-flaky signal for minimization.
	notexecuted := 0
	var progSig signal.Signal
	for i := 0; i < signalRuns; i++ {
		info := proc.executeRaw(proc.execOptsCover, item.p, StatTriage)
		if !reexecutionSuccess(info, &item.info, item.call) {
			// The call was not executed or failed.
			notexecuted++
			if notexecuted > signalRuns/2+1 {
				return // if happens too often, give up
			}
			continue
		}
		thisSignal, thisCover := getSignalAndCover(item.p, info, item.call)
		newSignal = newSignal.Intersection(thisSignal)
		// Without !minimized check manager starts losing some considerable amount
		// of coverage after each restart. Mechanics of this are not completely clear.
		if newSignal.Empty() && item.flags&ProgMinimized == 0 {
			return
		}
		inputCover.Merge(thisCover)
	}
	if item.flags&ProgMinimized == 0 {
		gfuzz.Status += "_m"
		item.p, item.call = prog.Minimize(item.p, item.call, false,
			func(p1 *prog.Prog, call1 int) bool {
				for i := 0; i < minimizeAttempts; i++ {
					info := proc.execute(proc.execOpts, p1, ProgNormal, StatMinimize)
					if !reexecutionSuccess(info, &item.info, call1) {
						// The call was not executed or failed.
						continue
					}
					thisSignal, _ := getSignalAndCover(p1, info, call1)
					if newSignal.Intersection(thisSignal).Len() == newSignal.Len() {
						return true
					}
				}
				return false
			}, 60) //only allow minimize in 60s
	}

	if proc.fuzzer.useprogdis && len_calls > 1 {
		oldlen := len(inputSignal)
		info := proc.executeRaw(proc.execOpts, item.p, StatHint)
		progSig = getProgSignal(item.p, info)
		//gfuzz.GFUZZlog("GFUZZ:progSig1 len(inputSignal):%v len(progSig):%v not_minimized:%v len(Calls):%v len_calls:%v", len(inputSignal), len(progSig), item.flags&ProgMinimized == 0, len(info.Calls), len_calls)
		if oldlen != len(progSig) {
			oldlen = len(progSig)
			info = proc.executeRaw(proc.execOpts, item.p, StatHint)
			progSig = progSig.Intersection(getProgSignal(item.p, info))
			//gfuzz.GFUZZlog("GFUZZ:progSig2 len(inputSignal):%v len(progSig):%v not_minimized:%v len(Calls):%v len_calls:%v", len(inputSignal), len(progSig), item.flags&ProgMinimized == 0, len(info.Calls), len_calls)
			if oldlen != len(progSig) {
				info = proc.executeRaw(proc.execOpts, item.p, StatHint)
				progSig = progSig.Intersection(getProgSignal(item.p, info))
				//gfuzz.GFUZZlog("GFUZZ:progSig3 len(inputSignal):%v len(progSig):%v not_minimized:%v len(Calls):%v len_calls:%v", len(inputSignal), len(progSig), item.flags&ProgMinimized == 0, len(info.Calls), len_calls)
			}
		}
	} else {
		progSig = inputSignal
		//gfuzz.GFUZZlog("GFUZZ:progSig4 direct_use len(inputSignal):%v", len(inputSignal))
	}

	data := item.p.Serialize()
	sig := hash.Hash(data)

	log.Logf(2, "added new input for %v to corpus:\n%s", logCallName, data)

	proc.fuzzer.sendInputToManager(rpctype.Input{
		Call:    callName,
		Prog:    data,
		Signal:  inputSignal.Serialize(),
		ProgSig: progSig.Serialize(),
		Cover:   inputCover.Serialize(),
	})

	proc.fuzzer.addInputToCorpus(item.p, inputSignal, progSig, sig, inputCover)
	proc.newseeds++
	proc.fuzzer.LastNewSeedTime = time.Now()

	if item.flags&ProgSmashed == 0 {
		times := 100
		seedClosestdistance := int64(1000)
		if proc.fuzzer.enablemoreSmash > 0 {
			for i := range progSig {
				d, ok := proc.fuzzer.pc2distance[uint64(i)]
				if ok {
					if d < seedClosestdistance {
						seedClosestdistance = d
					}
				}
			}
			times = int(float64(proc.fuzzer.enablemoreSmash) * (1- float64(seedClosestdistance)/float64(proc.fuzzer.maxStaticDis)))
			if times<10{
				times = 10
			}
			//gfuzz.GFUZZlog("GFUZZ:before_enqueue_smash %v shouldsmash:%v times:%v closestdistance:%v queue_len:%v high_queue_len:%v",
			//	item.p.Idx, item.flags&ProgSmashed == 0, times, seedClosestdistance, len(proc.fuzzer.workQueue.smash), len(proc.fuzzer.workQueue.smashHighPriority))
		}
		if seedClosestdistance<10 {
			proc.fuzzer.workQueue.enqueueHighPriorityWorkSmashQueue(&WorkSmash{item.p, item.call, times, newSignal})
			//gfuzz.GFUZZlog("GFUZZ:high_priority_queue %v closetdistance:%v", item.p.Idx, seedClosestdistance)
		} else {
			proc.fuzzer.workQueue.enqueue(&WorkSmash{item.p, item.call, times, newSignal})
		}
	}
}

func reexecutionSuccess(info *ipc.ProgInfo, oldInfo *ipc.CallInfo, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldInfo.Errno == 0 && info.Calls[call].Errno != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *ipc.ProgInfo, call int) (signal.Signal, []uint32) {
	inf := &info.Extra
	if call != -1 {
		inf = &info.Calls[call]
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call)), inf.Cover
}

func getProgSignal(p *prog.Prog, info *ipc.ProgInfo) (sig signal.Signal) {
	inf := &info.Extra
	sig = signal.FromRaw(inf.Signal, signalPrio(p, inf, -1))
	for i, inf := range info.Calls {
		sig.Merge(signal.FromRaw(inf.Signal, signalPrio(p, &inf, i)))
	}
	return sig
}

func (proc *Proc) smashInput(item *WorkSmash) {
	startTime := time.Now()
	if proc.fuzzer.faultInjectionEnabled && item.call != -1 {
		proc.failCall(item.p, item.call)
	}
	if proc.fuzzer.comparisonTracingEnabled && item.call != -1 {
		proc.executeHintSeed(item.p, item.call)
	}
	gfuzz.GFUZZlog("GFUZZ:smashInput %v call:%v times:%v", item.p.Idx, item.call, item.times)
	fuzzerSnapshot := proc.fuzzer.snapshot()
	for i := 0; i < item.times; i++ {
		if time.Since(startTime).Seconds() > 60 {
			gfuzz.GFUZZlog("GFUZZ:timeout_smash %v i:%v times:%v", item.p.Idx, i, item.times)
			break
		}
		// GFUZZ: we think we should use less time in smash
		p := item.p.Clone()
		//gfuzz.GFUZZlog("GFUZZ:smashMutate")
		elapsed_time := time.Since(proc.fuzzer.startTime).Seconds()
		chance := proc.fuzzer.MutateDirectChance
		chance -= int(elapsed_time/3600*10)
		if proc.fuzzer.mode=="directed" && chance < 20 {
			chance = 20
		}
		if chance < 0{
			chance = 0
		}
		p.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, fuzzerSnapshot.corpus,
			proc.fuzzer.SyscallSeedsHead, proc.fuzzer.SyscallSeedsTail, chance)
		log.Logf(1, "#%v: smash mutated", proc.pid)
		proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatSmash)
	}
	gfuzz.Status = "unknown_aftersmash"
}

func (proc *Proc) failCall(p *prog.Prog, call int) {
	for nth := 1; nth <= 100; nth++ {
		log.Logf(1, "#%v: injecting fault into call %v/%v", proc.pid, call, nth)
		newProg := p.Clone()
		newProg.Calls[call].Props.FailNth = nth
		info := proc.executeRaw(proc.execOpts, newProg, StatSmash)
		if info != nil && len(info.Calls) > call && info.Calls[call].Flags&ipc.CallFaultInjected == 0 {
			break
		}
	}
}

func (proc *Proc) executeHintSeed(p *prog.Prog, call int) {
	log.Logf(1, "#%v: collecting comparisons", proc.pid)
	// First execute the original program to dump comparisons from KCOV.
	info := proc.execute(proc.execOptsComps, p, ProgNormal, StatSeed)
	if info == nil {
		return
	}

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(call, info.Calls[call].Comps, func(p *prog.Prog) {
		log.Logf(1, "#%v: executing comparison hint", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatHint)
	})
}

func (proc *Proc) execute(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) *ipc.ProgInfo {
	//gfuzz.GFUZZlog("GFUZZ:execute %v status:%v", p.Idx, gfuzz.Status)
	if p.Idx != "" {
		proc.fuzzer.seedExectimes[p.Idx]++
	}
	proc.exectimes++
	info := proc.executeRaw(execOpts, p, stat)
	if info == nil {
		return nil
	}
	calls, extra := proc.fuzzer.checkNewSignal(p, info)
	for _, callIndex := range calls {
		proc.enqueueCallTriage(p, flags, callIndex, info.Calls[callIndex])
	}
	if extra {
		proc.enqueueCallTriage(p, flags, -1, info.Extra)
	}
	return info
}

func (proc *Proc) enqueueCallTriage(p *prog.Prog, flags ProgTypes, callIndex int, info ipc.CallInfo) {
	// info.Signal points to the output shmem region, detach it before queueing.
	info.Signal = append([]uint32{}, info.Signal...)
	// None of the caller use Cover, so just nil it instead of detaching.
	// Note: triage input uses executeRaw to get coverage.
	info.Cover = nil
	//proc.triageInput(&WorkTriage{
	//	p:     p.Clone(),
	//	call:  callIndex,
	//	info:  info,
	//	flags: flags,
	//})
	proc.fuzzer.workQueue.enqueue(&WorkTriage{
		p:      p.Clone(),
		call:   callIndex,
		info:   info,
		flags:  flags,
		status: gfuzz.Status,
	})
}

func (proc *Proc) executeAndCollide(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) {
	proc.execute(execOpts, p, flags, stat)

	if proc.execOptsCollide.Flags&ipc.FlagThreaded == 0 {
		// We cannot collide syscalls without being in the threaded mode.
		return
	}
	const collideIterations = 2
	for i := 0; i < collideIterations; i++ {
		proc.executeRaw(proc.execOptsCollide, proc.randomCollide(p), StatCollide)
	}
}

func (proc *Proc) randomCollide(origP *prog.Prog) *prog.Prog {
	// Old-styl collide with a 33% probability.
	if proc.rnd.Intn(3) == 0 {
		p, err := prog.DoubleExecCollide(origP, proc.rnd)
		if err == nil {
			return p
		}
	}
	p := prog.AssignRandomAsync(origP, proc.rnd)
	if proc.rnd.Intn(2) != 0 {
		prog.AssignRandomRerun(p, proc.rnd)
	}
	return p
}

func (proc *Proc) executeRaw(opts *ipc.ExecOpts, p *prog.Prog, stat Stat) *ipc.ProgInfo {
	if opts.Flags&ipc.FlagDedupCover == 0 {
		log.Fatalf("dedup cover is not enabled")
	}
	proc.fuzzer.checkDisabledCalls(p)

	// Limit concurrency window and do leak checking once in a while.
	ticket := proc.fuzzer.gate.Enter()
	defer proc.fuzzer.gate.Leave(ticket)

	proc.logProgram(opts, p)
	for try := 0; ; try++ {
		atomic.AddUint64(&proc.fuzzer.stats[stat], 1)
		output, info, hanged, err := proc.env.Exec(opts, p)
		if err != nil {
			if err == prog.ErrExecBufferTooSmall {
				// It's bad if we systematically fail to serialize programs,
				// but so far we don't have a better handling than ignoring this.
				// This error is observed a lot on the seeded syz_mount_image calls.
				return nil
			}
			if try > 10 {
				log.Fatalf("executor %v failed %v times:\n%v", proc.pid, try, err)
			}
			log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
			debug.FreeOSMemory()
			time.Sleep(time.Second)
			continue
		}
		log.Logf(2, "result hanged=%v: %s", hanged, output)
		return info
	}
}

func (proc *Proc) logProgram(opts *ipc.ExecOpts, p *prog.Prog) {
	if proc.fuzzer.outputType == OutputNone {
		return
	}

	data := p.Serialize()

	// The following output helps to understand what program crashed kernel.
	// It must not be intermixed.
	switch proc.fuzzer.outputType {
	case OutputStdout:
		now := time.Now()
		proc.fuzzer.logMu.Lock()
		fmt.Printf("%02v:%02v:%02v executing program %v:\n%s\n",
			now.Hour(), now.Minute(), now.Second(),
			proc.pid, data)
		proc.fuzzer.logMu.Unlock()
	case OutputDmesg:
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "syzkaller: executing program %v:\n%s\n",
				proc.pid, data)
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case OutputFile:
		f, err := os.Create(fmt.Sprintf("%v-%v.prog", proc.fuzzer.name, proc.pid))
		if err == nil {
			f.Write(data)
			f.Close()
		}
	default:
		log.Fatalf("unknown output type: %v", proc.fuzzer.outputType)
	}
}
