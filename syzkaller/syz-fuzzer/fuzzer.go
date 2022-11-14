// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/gfuzz"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

type Fuzzer struct {
	name              string
	outputType        OutputType
	config            *ipc.Config
	execOpts          *ipc.ExecOpts
	procs             []*Proc
	gate              *ipc.Gate
	workQueue         *WorkQueue
	needPoll          chan struct{}
	choiceTable       *prog.ChoiceTable
	stats             [StatCount]uint64
	manager           *rpctype.RPCClient
	target            *prog.Target
	triagedCandidates uint32
	timeouts          targets.Timeouts

	faultInjectionEnabled    bool
	comparisonTracingEnabled bool

	corpusMu      sync.RWMutex
	corpus        []*prog.Prog
	corpusHashes  map[hash.Sig]uint
	corpusPrios   []int64
	corpusSignals []signal.Signal

	enableDistance       bool
	corpusDistance       []float32
	corpusClosetDistance []int64
	corpusClosetDistanceMap map[string]int64
	corpusDistance_min   float32
	corpusDistance_max   float32
	useClosetDistance    bool

	enablePCCFG bool
	pccfg       map[uint32][]uint32 //pc to descendant pcs
	boundary    map[uint32][]int    //pc to seed idxs

	sumPrios int64

	signalMu     sync.RWMutex
	corpusSignal signal.Signal // signal of inputs in corpus
	maxSignal    signal.Signal // max signal ever observed including flakes
	newSignal    signal.Signal // diff of maxSignal since last sync with master

	checkResult *rpctype.CheckArgs
	logMu                      sync.Mutex
	pc2distance                map[uint64]int64
	maxStaticDis               int64
	seedExectimes              map[string]uint32
	seedProfit                 map[string]uint32
	cooling_tx                 int
	startTime                  time.Time
	StageStartTime             time.Time
	LastNewSeedTime            time.Time
	enablemoreSmash            int
	directchooseEntertime      int
	directchooseForceEntertime int
	directchooseExittime       int
	directchooseForceExittime  int
	mimicBaseline              bool
	useprogdis                 bool
	SyscallSeedsHead           [][]int
	SyscallSeedsTail           [][]int
	MutateDirectChance         int
	targetpc                   []uint32
	mode                       string //"coverage", "directed", "generate"
	gfuzzfilter                map[uint32]bool
}

type FuzzerSnapshot struct {
	corpus               []*prog.Prog
	corpusPrios          []int64
	sumPrios             int64
	corpusDistance       []float32
	corpusClosetDistance []int64
	corpusDistance_min   float32
	corpusDistance_max   float32
}

type Stat int

const (
	StatGenerate Stat = iota
	StatFuzz
	StatCandidate
	StatTriage
	StatMinimize
	StatSmash
	StatHint
	StatSeed
	StatCollide
	StatCount
)

var statNames = [StatCount]string{
	StatGenerate:  "exec gen",
	StatFuzz:      "exec fuzz",
	StatCandidate: "exec candidate",
	StatTriage:    "exec triage",
	StatMinimize:  "exec minimize",
	StatSmash:     "exec smash",
	StatHint:      "exec hints",
	StatSeed:      "exec seeds",
	StatCollide:   "exec collide",
}

type OutputType int

const (
	OutputNone OutputType = iota
	OutputStdout
	OutputDmesg
	OutputFile
)

func createIPCConfig(features *host.Features, config *ipc.Config) {
	if features[host.FeatureExtraCoverage].Enabled {
		config.Flags |= ipc.FlagExtraCover
	}
	if features[host.FeatureDelayKcovMmap].Enabled {
		config.Flags |= ipc.FlagDelayKcovMmap
	}
	if features[host.FeatureNetInjection].Enabled {
		config.Flags |= ipc.FlagEnableTun
	}
	if features[host.FeatureNetDevices].Enabled {
		config.Flags |= ipc.FlagEnableNetDev
	}
	config.Flags |= ipc.FlagEnableNetReset
	config.Flags |= ipc.FlagEnableCgroups
	config.Flags |= ipc.FlagEnableCloseFds
	if features[host.FeatureDevlinkPCI].Enabled {
		config.Flags |= ipc.FlagEnableDevlinkPCI
	}
	if features[host.FeatureVhciInjection].Enabled {
		config.Flags |= ipc.FlagEnableVhciInjection
	}
	if features[host.FeatureWifiEmulation].Enabled {
		config.Flags |= ipc.FlagEnableWifi
	}
}

func syscallIsGenerator(syscall *prog.Syscall) bool{
	hasResource := false
	for _, arg := range syscall.Args {
		if _, ok := arg.Type.(*prog.ResourceType); ok {
			hasResource = true
		}
		if ptr, ok := arg.Type.(*prog.PtrType); ok {
			if _, ok2 := ptr.Elem.(*prog.ResourceType); ok2 {
				hasResource = true
			}
		}
	}
	_, isReturnResource :=syscall.Ret.(*prog.ResourceType)
	return !hasResource||isReturnResource
}

func SyscallExpand(basesyscalls []string, calls map[*prog.Syscall]bool, rulecalls []gfuzz.RuleInferredSyscalls, enableOrderInfer bool) (outHeadres, outTailres[][]int) {
	basename2ids := make(map[string][][]int)

	addcall := func(syscall *prog.Syscall, id int){
		basecall := syscall.Name
		if basename2ids[basecall] == nil{
			basename2ids[basecall] = make([][]int, 2)
			basename2ids[basecall][0] = make([]int, 0)
			basename2ids[basecall][1] = make([]int, 0)
		}
		if enableOrderInfer && syscallIsGenerator(syscall){
			basename2ids[basecall][0] = append(basename2ids[basecall][0], id)
		}else{
			basename2ids[basecall][1] = append(basename2ids[basecall][1], id)
		}
	}

	for _, basecall := range basesyscalls {
		for syscall := range calls {
			if syscall.CallName == basecall || syscall.Name == basecall || syscall.Name==basecall[:len(basecall)-1] {
				addcall(syscall, syscall.ID)
			}
		}
	}
	for i, item := range rulecalls{
		for syscall := range calls{
			if syscall.Name == item.Name{
				addcall(syscall, -(i+1))
			}
		}
	}
	outHeadres = make([][]int, 0)
	outTailres = make([][]int, 0)
	for _, item := range basename2ids{
		if len(item[0])>0{
			outHeadres = append(outHeadres, item[0])
		}
		if len(item[1])>0{
			outTailres = append(outTailres, item[1])
		}
	}

	gfuzz.GFUZZlog("GFUZZ:SyscallExpand_Head %v", outHeadres)
	gfuzz.GFUZZlog("GFUZZ:SyscallExpand_Tail %v", outTailres)
	if fp, err := os.OpenFile("/workdir/syscalls_dynamic.txt", os.O_RDONLY, 0644); err == nil {
		scanner := bufio.NewScanner(fp)
		for scanner.Scan() {
			lineStr := scanner.Text()
			num, _ := strconv.Atoi(lineStr)
			tmp := make([]int, 1)
			tmp[0] = num
			outTailres = append(outTailres, tmp)
		}
		gfuzz.GFUZZlog("GFUZZ:SyscallExpand_dynamic %v", outTailres)
	}
	return
}

func SyscallExpandv1(basesyscalls []string, calls map[*prog.Syscall]bool, rulecalls []gfuzz.RuleInferredSyscalls, enableOrderInfer bool) (outHeadres, outTailres[][]int) {
	maxlength := len(basesyscalls)+len(rulecalls)
	outHead := make([][]int, maxlength)
	outTail := make([][]int, maxlength)
	for i, basecall := range basesyscalls {
		outHead[i] = make([]int, 0)
		outTail[i] = make([]int, 0)
		for syscall := range calls {
			if syscall.CallName == basecall || syscall.Name == basecall || syscall.Name==basecall[:len(basecall)-1] {
				if enableOrderInfer && syscallIsGenerator(syscall){
					outHead[i] = append(outHead[i], syscall.ID)
				}else{
					outTail[i] = append(outTail[i], syscall.ID)
				}
			}
		}
	}
	for i, item := range rulecalls{
		outi := len(basesyscalls) + i
		outHead[outi] = make([]int, 0)
		outTail[outi] = make([]int, 0)
		for syscall := range calls{
			if syscall.Name == item.Name{
				if enableOrderInfer && syscallIsGenerator(syscall){
					outHead[outi] = append(outHead[outi], -(i+1))// gfuzz: we use negative syscall id as rulecalls' id
				}else{
					outTail[outi] = append(outTail[outi], -(i+1))
				}
			}
		}
	}
	outHeadres = make([][]int, 0)
	for _, item := range outHead{
		if len(item)>0{
			outHeadres = append(outHeadres, item)
		}
	}
	outTailres = make([][]int, 0)
	for _, item := range outTail{
		if len(item)>0{
			outTailres = append(outTailres, item)
		}
	}
	gfuzz.GFUZZlog("GFUZZ:SyscallExpand_Head %v", outHeadres)
	gfuzz.GFUZZlog("GFUZZ:SyscallExpand_Tail %v", outTailres)
	if fp, err := os.OpenFile("/workdir/syscalls_dynamic.txt", os.O_RDONLY, 0644); err == nil {
		scanner := bufio.NewScanner(fp)
		for scanner.Scan() {
			lineStr := scanner.Text()
			num, _ := strconv.Atoi(lineStr)
			tmp := make([]int, 1)
			tmp[0] = num
			outTailres = append(outTailres, tmp)
		}
		gfuzz.GFUZZlog("GFUZZ:SyscallExpand_dynamic %v", outTailres)
	}
	return
}

// nolint: funlen
func main() {
	debug.SetGCPercent(50)
	gfuzz.GFUZZlog("GFUZZ:fuzzer_started")

	var (
		flagName    = flag.String("name", "test", "unique name for manager")
		flagOS      = flag.String("os", runtime.GOOS, "target OS")
		flagArch    = flag.String("arch", runtime.GOARCH, "target arch")
		flagManager = flag.String("manager", "", "manager rpc address")
		flagProcs   = flag.Int("procs", 1, "number of parallel test processes")
		flagOutput  = flag.String("output", "stdout", "write programs to none/stdout/dmesg/file")
		flagTest    = flag.Bool("test", false, "enable image testing mode")      // used by syz-ci
		flagRunTest = flag.Bool("runtest", false, "enable program testing mode") // used by pkg/runtest
	)
	defer tool.Init()()
	outputType := parseOutputType(*flagOutput)
	log.Logf(0, "fuzzer started")

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("%v", err)
	}

	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		log.Fatalf("failed to create default ipc config: %v", err)
	}
	timeouts := config.Timeouts
	sandbox := ipc.FlagsToSandbox(config.Flags)
	shutdown := make(chan struct{})
	osutil.HandleInterrupts(shutdown)
	go func() {
		// Handles graceful preemption on GCE.
		<-shutdown
		log.Logf(0, "SYZ-FUZZER: PREEMPTED")
		os.Exit(1)
	}()

	checkArgs := &checkArgs{
		target:         target,
		sandbox:        sandbox,
		ipcConfig:      config,
		ipcExecOpts:    execOpts,
		gitRevision:    prog.GitRevision,
		targetRevision: target.Revision,
	}
	if *flagTest {
		testImage(*flagManager, checkArgs)
		return
	}

	machineInfo, modules := collectMachineInfos(target)

	log.Logf(0, "dialing manager at %v", *flagManager)
	manager, err := rpctype.NewRPCClient(*flagManager, timeouts.Scale)
	if err != nil {
		log.Fatalf("failed to connect to manager: %v ", err)
	}

	log.Logf(1, "connecting to manager...")
	a := &rpctype.ConnectArgs{
		Name:        *flagName,
		MachineInfo: machineInfo,
		Modules:     modules,
	}
	r := &rpctype.ConnectRes{}
	if err := manager.Call("Manager.Connect", a, r); err != nil {
		log.Fatalf("failed to connect to manager: %v ", err)
	}
	featureFlags, err := csource.ParseFeaturesFlags("none", "none", true)
	if err != nil {
		log.Fatal(err)
	}
	if r.CoverFilterBitmap != nil {
		if err := osutil.WriteFile("syz-cover-bitmap", r.CoverFilterBitmap); err != nil {
			log.Fatalf("failed to write syz-cover-bitmap: %v", err)
		}
	}
	if r.CheckResult == nil {
		checkArgs.gitRevision = r.GitRevision
		checkArgs.targetRevision = r.TargetRevision
		checkArgs.enabledCalls = r.EnabledCalls
		checkArgs.allSandboxes = r.AllSandboxes
		checkArgs.featureFlags = featureFlags
		r.CheckResult, err = checkMachine(checkArgs)
		if err != nil {
			if r.CheckResult == nil {
				r.CheckResult = new(rpctype.CheckArgs)
			}
			r.CheckResult.Error = err.Error()
		}
		r.CheckResult.Name = *flagName
		if err := manager.Call("Manager.Check", r.CheckResult, nil); err != nil {
			log.Fatalf("Manager.Check call failed: %v", err)
		}
		if r.CheckResult.Error != "" {
			log.Fatalf("%v", r.CheckResult.Error)
		}
		r.StartTime = time.Now()
	} else {
		target.UpdateGlobs(r.CheckResult.GlobFiles)
		if err = host.Setup(target, r.CheckResult.Features, featureFlags, config.Executor); err != nil {
			log.Fatal(err)
		}
	}
	log.Logf(0, "syscalls: %v", len(r.CheckResult.EnabledCalls[sandbox]))
	for _, feat := range r.CheckResult.Features.Supported() {
		log.Logf(0, "%v: %v", feat.Name, feat.Reason)
	}
	createIPCConfig(r.CheckResult.Features, config)

	if *flagRunTest {
		runTest(target, manager, *flagName, config.Executor)
		return
	}

	needPoll := make(chan struct{}, 1)
	needPoll <- struct{}{}

	var pc2dis map[uint64]int64 = make(map[uint64]int64)
	enableDistance := true

	hextoint := func(s string) uint32 {
		kk := strings.Replace(s, "0x", "", -1)
		kint, err := strconv.ParseUint(kk, 16, 32)
		if err != nil {
			panic(err)
		}
		return uint32(kint)
	}

	fdistance, err := os.Open("/distance.json")
	maxStaticDis := int64(-1) // max distance inferred from static analysis, used in Smart Smash
	if err == nil {
		defer fdistance.Close()
		byteValue, _ := ioutil.ReadAll(fdistance)
		var tmp map[string]interface{}
		err = json.Unmarshal([]byte(byteValue), &tmp)
		if err != nil {
			log.Fatalf("json.Unmarshal distance.json failed: %v", err)
		}
		for k, v := range tmp {
			//fmt.Printf("%v : %v %T\n", k, v, v)
			v2 := int64(v.(float64))
			pc2dis[uint64(hextoint(k))] = v2
			if v2>maxStaticDis{
				maxStaticDis = v2
			}
		}
	} else {
		enableDistance = false
	}

	var pccfg map[uint32][]uint32 = make(map[uint32][]uint32)
	enablePCCFG := true
	fcfg, err := os.Open("/cfg.json")
	if err == nil {
		defer fcfg.Close()
		byteValue, _ := ioutil.ReadAll(fcfg)
		var tmp map[string]interface{}
		err = json.Unmarshal([]byte(byteValue), &tmp)
		if err != nil {
			log.Fatalf("json.Unmarshal cfg.json failed: %v", err)
		}
		for k, v := range tmp {
			//fmt.Printf("pccfg %v : %v %T\n", k, v, v)
			vv := v.([]interface{})
			pccfg[hextoint(k)] = make([]uint32, 0)
			for _, i := range vv {
				pccfg[hextoint(k)] = append(pccfg[hextoint(k)], hextoint(i.(string)))
			}
		}
	} else {
		enablePCCFG = false
	}
	//fmt.Printf("pccfg: %v", pccfg)
	GFuzzFilter := make(map[uint32]bool)
	fgfuzzfilter, err := os.Open("/gfuzzfilter.json")
	defer fgfuzzfilter.Close()
	if err == nil{
		s := bufio.NewScanner(fgfuzzfilter)
		for s.Scan() {
			pc := hextoint(s.Text())
			GFuzzFilter[pc] = true
		}
	}


	fuzzer := &Fuzzer{
		name:                     *flagName,
		outputType:               outputType,
		config:                   config,
		execOpts:                 execOpts,
		workQueue:                newWorkQueue(*flagProcs, needPoll),
		needPoll:                 needPoll,
		manager:                  manager,
		target:                   target,
		timeouts:                 timeouts,
		faultInjectionEnabled:    r.CheckResult.Features[host.FeatureFault].Enabled,
		comparisonTracingEnabled: r.CheckResult.Features[host.FeatureComparisons].Enabled,
		checkResult:              r.CheckResult,
		corpusHashes:             make(map[hash.Sig]uint),
		pc2distance:              pc2dis,
		maxStaticDis:             maxStaticDis,
		enableDistance:           enableDistance,
		pccfg:                    pccfg,
		enablePCCFG:              enablePCCFG,
		corpusDistance_min:       1000,
		boundary:                 make(map[uint32][]int),
		seedExectimes:            make(map[string]uint32),
		seedProfit:               make(map[string]uint32),
		corpusClosetDistanceMap:  make(map[string]int64),
		gfuzzfilter:              GFuzzFilter,
	}
	gateCallback := fuzzer.useBugFrames(r, *flagProcs)
	fuzzer.gate = ipc.NewGate(2**flagProcs, gateCallback)

	for needCandidates, more := true, true; more; needCandidates = false {
		more = fuzzer.poll(needCandidates, nil)
		// This loop lead to "no output" in qemu emulation, tell manager we are not dead.
		log.Logf(0, "fetching corpus: %v, signal %v/%v (executing program)",
			len(fuzzer.corpus), len(fuzzer.corpusSignal), len(fuzzer.maxSignal))
	}
	calls := make(map[*prog.Syscall]bool)
	for _, id := range r.CheckResult.EnabledCalls[sandbox] {
		calls[target.Syscalls[id]] = true
	}

	gfuzz.RuleCalls = make([]gfuzz.RuleInferredSyscalls, 0)
	rc := make([]gfuzz.RuleInferredSyscalls, 0)
	if err = json.Unmarshal([]byte(r.RuleCallsStr), &rc); err != nil{
		log.Fatalf("unmarshal rulecalls failed: %v", err)
	}
	for _, item := range rc {
		for syscall := range calls {
			if item.Name == syscall.Name { //only add allowed syscalls to gfuzz.RuleCalls
				item.Id = syscall.ID
				gfuzz.RuleCalls = append(gfuzz.RuleCalls, item)
				break
			}
		}
	}

	fuzzer.choiceTable = target.BuildChoiceTable(fuzzer.corpus, calls)
	fuzzer.SyscallSeedsHead, fuzzer.SyscallSeedsTail = SyscallExpand(r.SyscallSeeds, calls, gfuzz.RuleCalls, r.EnableOrderInfer)
	fuzzer.MutateDirectChance = r.MutateDirectChance

	if r.CoverFilterBitmap != nil {
		fuzzer.execOpts.Flags |= ipc.FlagEnableCoverageFilter
	}
	if r.EnableRandomChoose {
		fuzzer.execOpts.Flags |= ipc.FlagEnableRandomChoose
	}
	if r.EnableGlobalDistance {
		fuzzer.execOpts.Flags |= ipc.FlagEnableGlobalDistance
	}
	if r.EnableSeedExecLimit {
		fuzzer.execOpts.Flags |= ipc.FlagEnableSeedExecLimit
	}
	if r.CoolingTx > 0 {
		fuzzer.cooling_tx = r.CoolingTx
	}
	fuzzer.startTime = r.StartTime
	fuzzer.StageStartTime = r.StageStartTime
	fuzzer.LastNewSeedTime = r.LastNewSeedTime
	fuzzer.mode = r.Mode
	if r.EnablemoreSmash > 0 {
		fuzzer.enablemoreSmash = r.EnablemoreSmash
	}
	if r.UseClosetDistance {
		fuzzer.useClosetDistance = true
	}
	if r.NoLog {
		gfuzz.NoLog = true
	}
	fuzzer.directchooseEntertime = r.DirectchooseEntertime
	fuzzer.directchooseForceEntertime = r.DirectchooseForceEntertime
	fuzzer.directchooseExittime = r.DirectchooseExittime
	fuzzer.directchooseForceExittime = r.DirectchooseForceExittime
	fuzzer.mimicBaseline = r.MimicBaseline
	fuzzer.useprogdis = r.UseProgDis
	fuzzer.targetpc = r.TargetPC

	log.Logf(0, "starting %v fuzzer processes", *flagProcs)
	for pid := 0; pid < *flagProcs; pid++ {
		proc, err := newProc(fuzzer, pid)
		if err != nil {
			log.Fatalf("failed to create proc: %v", err)
		}
		fuzzer.procs = append(fuzzer.procs, proc)
		go proc.loop()
	}
	if fuzzer.enablePCCFG {
		go fuzzer.boundaryDeleteRoutine()
	}
	go fuzzer.showQueueRoutine()

	fuzzer.pollLoop()
}

func collectMachineInfos(target *prog.Target) ([]byte, []host.KernelModule) {
	machineInfo, err := host.CollectMachineInfo()
	if err != nil {
		log.Fatalf("failed to collect machine information: %v", err)
	}
	modules, err := host.CollectModulesInfo()
	if err != nil {
		log.Fatalf("failed to collect modules info: %v", err)
	}
	return machineInfo, modules
}

// Returns gateCallback for leak checking if enabled.
func (fuzzer *Fuzzer) useBugFrames(r *rpctype.ConnectRes, flagProcs int) func() {
	var gateCallback func()

	if r.CheckResult.Features[host.FeatureLeak].Enabled {
		gateCallback = func() { fuzzer.gateCallback(r.MemoryLeakFrames) }
	}

	if r.CheckResult.Features[host.FeatureKCSAN].Enabled && len(r.DataRaceFrames) != 0 {
		fuzzer.filterDataRaceFrames(r.DataRaceFrames)
	}

	return gateCallback
}

func (fuzzer *Fuzzer) gateCallback(leakFrames []string) {
	// Leak checking is very slow so we don't do it while triaging the corpus
	// (otherwise it takes infinity). When we have presumably triaged the corpus
	// (triagedCandidates == 1), we run leak checking bug ignore the result
	// to flush any previous leaks. After that (triagedCandidates == 2)
	// we do actual leak checking and report leaks.
	triagedCandidates := atomic.LoadUint32(&fuzzer.triagedCandidates)
	if triagedCandidates == 0 {
		return
	}
	args := append([]string{"leak"}, leakFrames...)
	timeout := fuzzer.timeouts.NoOutput * 9 / 10
	output, err := osutil.RunCmd(timeout, "", fuzzer.config.Executor, args...)
	if err != nil && triagedCandidates == 2 {
		// If we exit right away, dying executors will dump lots of garbage to console.
		os.Stdout.Write(output)
		fmt.Printf("BUG: leak checking failed\n")
		time.Sleep(time.Hour)
		os.Exit(1)
	}
	if triagedCandidates == 1 {
		atomic.StoreUint32(&fuzzer.triagedCandidates, 2)
	}
}

func (fuzzer *Fuzzer) filterDataRaceFrames(frames []string) {
	args := append([]string{"setup_kcsan_filterlist"}, frames...)
	timeout := time.Minute * fuzzer.timeouts.Scale
	output, err := osutil.RunCmd(timeout, "", fuzzer.config.Executor, args...)
	if err != nil {
		log.Fatalf("failed to set KCSAN filterlist: %v", err)
	}
	log.Logf(0, "%s", output)
}

func (fuzzer *Fuzzer) pollLoop() {
	var execTotal uint64
	var lastPoll time.Time
	var lastPrint time.Time
	ticker := time.NewTicker(3 * time.Second * fuzzer.timeouts.Scale).C
	for {
		poll := false
		select {
		case <-ticker:
		case <-fuzzer.needPoll:
			poll = true
		}
		if fuzzer.outputType != OutputStdout && time.Since(lastPrint) > 10*time.Second*fuzzer.timeouts.Scale {
			// Keep-alive for manager.
			log.Logf(0, "alive, executed %v", execTotal)
			lastPrint = time.Now()
		}
		if poll || time.Since(lastPoll) > 10*time.Second*fuzzer.timeouts.Scale {
			needCandidates := fuzzer.workQueue.wantCandidates()
			if poll && !needCandidates {
				continue
			}
			stats := make(map[string]uint64)
			for _, proc := range fuzzer.procs {
				stats["exec total"] += atomic.SwapUint64(&proc.env.StatExecs, 0)
				stats["executor restarts"] += atomic.SwapUint64(&proc.env.StatRestarts, 0)
			}
			for stat := Stat(0); stat < StatCount; stat++ {
				v := atomic.SwapUint64(&fuzzer.stats[stat], 0)
				stats[statNames[stat]] = v
				execTotal += v
			}
			if !fuzzer.poll(needCandidates, stats) {
				lastPoll = time.Now()
			}
		}
	}
}

func (fuzzer *Fuzzer) poll(needCandidates bool, stats map[string]uint64) bool {
	a := &rpctype.PollArgs{
		Name:           fuzzer.name,
		NeedCandidates: needCandidates,
		MaxSignal:      fuzzer.grabNewSignal().Serialize(),
		Stats:          stats,
	}
	r := &rpctype.PollRes{}
	if err := fuzzer.manager.Call("Manager.Poll", a, r); err != nil {
		log.Fatalf("Manager.Poll call failed: %v", err)
	}
	maxSignal := r.MaxSignal.Deserialize()
	log.Logf(1, "poll: candidates=%v inputs=%v signal=%v",
		len(r.Candidates), len(r.NewInputs), maxSignal.Len())
	fuzzer.addMaxSignal(maxSignal)
	for _, inp := range r.NewInputs {
		fuzzer.addInputFromAnotherFuzzer(inp)
	}
	for _, candidate := range r.Candidates {
		fuzzer.addCandidateInput(candidate)
	}
	if needCandidates && len(r.Candidates) == 0 && atomic.LoadUint32(&fuzzer.triagedCandidates) == 0 {
		atomic.StoreUint32(&fuzzer.triagedCandidates, 1)
	}
	return len(r.NewInputs) != 0 || len(r.Candidates) != 0 || maxSignal.Len() != 0
}

func (fuzzer *Fuzzer) sendInputToManager(inp rpctype.Input) {
	a := &rpctype.NewInputArgs{
		Name:  fuzzer.name,
		Input: inp,
	}
	if err := fuzzer.manager.Call("Manager.NewInput", a, nil); err != nil {
		log.Fatalf("Manager.NewInput call failed: %v", err)
	}
}

func (fuzzer *Fuzzer) StageExit() {
	fuzzer.StageStartTime = time.Now()
	fuzzer.LastNewSeedTime = time.Now()
	a := fuzzer.name
	if err := fuzzer.manager.Call("Manager.StageExit", a, nil); err != nil {
		log.Logf(0, "Manager.StageExit call failed: %v", err)
	}
}

func (fuzzer *Fuzzer) changeMode(newMode string){
	gfuzz.GFUZZlog("GFUZZ:changeMode %v", newMode)
	fuzzer.mode = newMode
	a := &rpctype.ModeChange{
		Name: fuzzer.name,
		Mode: newMode,
	}
	if err := fuzzer.manager.Call("Manager.ChangeMode", a, nil); err != nil {
		log.Fatalf("Manager.ChangeMode call failed: %v", err)
	}
}


var TargetFound = make(map[uint32]bool)

func (fuzzer *Fuzzer) notifyTargetFound(targetpc uint32) {
	if _, ok := TargetFound[targetpc]; ok {
		return
	}
	a := fmt.Sprintf("%x", targetpc)
	if err := fuzzer.manager.Call("Manager.TargetFound", a, nil); err != nil {
		log.Logf(0, "Manager.TargetFound call failed: %v", err)
	} else {
		TargetFound[targetpc] = true
	}
}

func (fuzzer *Fuzzer) addInputFromAnotherFuzzer(inp rpctype.Input) {
	p := fuzzer.deserializeInput(inp.Prog)
	if p == nil {
		return
	}
	sig := hash.Hash(inp.Prog)
	sign := inp.Signal.Deserialize()
	cover := new(cover.Cover)
	cover.Merge(inp.Cover)
	fuzzer.addInputToCorpus(p, sign, inp.ProgSig.Deserialize(), sig, *cover)
}

func (fuzzer *Fuzzer) addCandidateInput(candidate rpctype.Candidate) {
	p := fuzzer.deserializeInput(candidate.Prog)
	if p == nil {
		return
	}
	flags := ProgCandidate
	if candidate.Minimized {
		flags |= ProgMinimized
	}
	if candidate.Smashed {
		flags |= ProgSmashed
	}
	fuzzer.workQueue.enqueue(&WorkCandidate{
		p:     p,
		flags: flags,
	})
}

func (fuzzer *Fuzzer) deserializeInput(inp []byte) *prog.Prog {
	p, err := fuzzer.target.Deserialize(inp, prog.NonStrict)
	if err != nil {
		log.Fatalf("failed to deserialize prog: %v\n%s", err, inp)
	}
	// We build choice table only after we received the initial corpus,
	// so we don't check the initial corpus here, we check it later in BuildChoiceTable.
	if fuzzer.choiceTable != nil {
		fuzzer.checkDisabledCalls(p)
	}
	if len(p.Calls) > prog.MaxCalls {
		return nil
	}
	sig := hash.Hash(p.Serialize())
	p.Idx = sig.String()
	return p
}

func (fuzzer *Fuzzer) checkDisabledCalls(p *prog.Prog) {
	for _, call := range p.Calls {
		if !fuzzer.choiceTable.Enabled(call.Meta.ID) {
			fmt.Printf("executing disabled syscall %v [%v]\n", call.Meta.Name, call.Meta.ID)
			sandbox := ipc.FlagsToSandbox(fuzzer.config.Flags)
			fmt.Printf("check result for sandbox=%v:\n", sandbox)
			for _, id := range fuzzer.checkResult.EnabledCalls[sandbox] {
				meta := fuzzer.target.Syscalls[id]
				fmt.Printf("  %v [%v]\n", meta.Name, meta.ID)
			}
			fmt.Printf("choice table:\n")
			for i, meta := range fuzzer.target.Syscalls {
				fmt.Printf("  #%v: %v [%v]: enabled=%v\n", i, meta.Name, meta.ID, fuzzer.choiceTable.Enabled(meta.ID))
			}
			panic("disabled syscall")
		}
	}
}

func (fuzzer *FuzzerSnapshot) chooseProgram_idx(r *rand.Rand) int {
	randVal := r.Int63n(fuzzer.sumPrios + 1)
	idx := sort.Search(len(fuzzer.corpusPrios), func(i int) bool {
		return fuzzer.corpusPrios[i] >= randVal
	})
	return idx
}

func (fuzzer *FuzzerSnapshot) chooseProgram(r *rand.Rand) *prog.Prog {
	idx := fuzzer.chooseProgram_idx(r)
	return fuzzer.corpus[idx]
}

func (fuzzer *Fuzzer) showQueueRoutine() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		wq := fuzzer.workQueue
		wq.mu.RLock()
		gfuzz.GFUZZlog("GFUZZ:showqueue hp:%v smash:%v candidate:%v triage:%v triageCandidate:%v len_corpus:%v saved:%v",
			len(wq.smashHighPriority), len(wq.smash), len(wq.candidate), len(wq.triage), len(wq.triageCandidate), len(fuzzer.corpus), len(wq.smashHighPrioritySaved)+len(wq.triageCandidateSaved)+len(wq.candidateSaved)+len(wq.triageSaved)+len(wq.smashSaved))
		wq.mu.RUnlock()
	}
}

func (fuzzer *Fuzzer) boundaryDeleteRoutine() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		//GFUZZlog("boundaryDeleteRoutine: before lock")
		fuzzer.corpusMu.Lock()
		//GFUZZlog("boundaryDeleteRoutine: after lock")
		cnt := 0
		dellist := make([]uint32, 0)
		for pc := range fuzzer.boundary {
			shouldkeep := false
			for _, descendant := range fuzzer.pccfg[pc] {
				//GFUZZlog("boundaryDeleteRoutine: descendant %v %v %v", descendant, fuzzer.boundary[descendant], fuzzer.corpusSignal[descendant])
				if _, ok := fuzzer.boundary[descendant]; !ok {
					if _, ok := fuzzer.corpusSignal[descendant]; !ok {
						shouldkeep = true //descendant not in boundary and corpusSignal
					}
				}
			}
			if !shouldkeep {
				delete(fuzzer.boundary, pc)
				dellist = append(dellist, pc)
				cnt += 1
			}
		}
		seedNoboundary := make([]int, 0)
		for idx, sign := range fuzzer.corpusSignals {
			// if this seed's all signals not in boundary, then we should treat this seed as useless
			notinbounary := true
			for seedpc := range sign {
				if _, ok := fuzzer.boundary[seedpc]; ok {
					if len(fuzzer.boundary[seedpc]) < 50 {
						notinbounary = false
					}
				}
			}
			if notinbounary {
				seedNoboundary = append(seedNoboundary, idx)
			}
		}
		validboundary_cnt := 0
		for _, v := range fuzzer.boundary {
			if len(v) < 50 {
				validboundary_cnt += 1
			}
		}
		gfuzz.GFUZZlog("GFUZZ:boundaryDeleteRoutine seedNoboundary:%v len:%d valid_len:%v delete:%d %v", len(seedNoboundary), len(fuzzer.boundary), validboundary_cnt, cnt, dellist)
		file, err := os.OpenFile("/workdir/boundary.txt", os.O_CREATE|os.O_WRONLY, 0666)
		if err == nil {
			buf := bufio.NewWriter(file)
			for i, j := range fuzzer.boundary {
				fmt.Fprintf(buf, "0x%x %v\n", i, j)
			}
			buf.Flush()
		}
		file.Close()
		fuzzer.corpusMu.Unlock()
	}
}

func (fuzzer *Fuzzer) addInputToCorpus(p *prog.Prog, sign signal.Signal, progSig signal.Signal, sig hash.Sig, cover cover.Cover) {
	fuzzer.corpusMu.Lock()
	var newidx uint
	var isnewseed bool
	if _newidx, ok := fuzzer.corpusHashes[sig]; ok {
		newidx = _newidx
		isnewseed = false
	} else {
		newidx = uint(len(fuzzer.corpus))
		isnewseed = true
	}
	if !fuzzer.enableDistance {
		gfuzz.GFUZZlog("GFUZZ:addInputToCorpus %v idx:%v from:%v status:%v isnew:%v", sig.String(), newidx, p.Idx, gfuzz.Status, isnewseed)
	}
	if p.Idx != "" {
		fuzzer.seedProfit[p.Idx]++
	}
	for _, targetpc := range fuzzer.targetpc {
		if _, ok := cover[targetpc]; ok {
			fuzzer.notifyTargetFound(targetpc)
		}
	}
	if fuzzer.enableDistance {
		var energysum, energycnt int64
		seedClosestdistance := int64(1000)
		for i := range cover {
			d, ok := fuzzer.pc2distance[uint64(i)]
			if ok {
				energysum += d
				energycnt += 1
				if d < seedClosestdistance {
					seedClosestdistance = d
				}
			}
		}
		seed_distance := float32(energysum) / float32(energycnt)
		if fuzzer.useClosetDistance {
			seed_distance = float32(seedClosestdistance)
		}
		if seedClosestdistance == 0 {
			fuzzer.manager.Call("Manager.TargetFound", "closet0", nil)
		}
		if parentClosetDis, ok := fuzzer.corpusClosetDistanceMap[p.Idx]; ok{
			if seedClosestdistance < parentClosetDis{
				// this seed make progress in distance metric, let's add its syscalls to fuzzer.SyscallSeeds
				// only syscalls that already in SyscallSeeds are considered
				// to make it persistent, also write to syscalls_dynamic.txt
				allCalls := make(map[int]bool, 0)
				for _, ids := range fuzzer.SyscallSeedsTail {
					for _, id := range ids {
						allCalls[id] = true
					}
				}
				for _,call := range p.Calls{
					callid := call.Meta.ID
					if _, ok := allCalls[callid]; ok{
						tmp := make([]int, 1)
						tmp[0] = callid
						gfuzz.GFUZZlog("GFUZZ:dynamic_syscall %v %v", callid, call.Meta.Name)
						fuzzer.SyscallSeedsTail = append(fuzzer.SyscallSeedsTail, tmp)
						if fp, err := os.OpenFile("/workdir/syscalls_dynamic.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644); err == nil{
							fmt.Fprintf(fp, "%d\n", callid)
							fp.Close()
						}
					}
				}
			}
		}
		if gfuzz.Status!="" {
			gfuzz.GFUZZlog("GFUZZ:addInputToCorpus_distance %v dis:%v closet:%v idx:%v from:%v status:%v isnew:%v",
				sig.String(), seed_distance, seedClosestdistance, newidx, p.Idx, gfuzz.Status, isnewseed)
		}
		if isnewseed {
			fuzzer.corpusDistance = append(fuzzer.corpusDistance, seed_distance)
			fuzzer.corpusClosetDistance = append(fuzzer.corpusClosetDistance, seedClosestdistance)
			fuzzer.corpusClosetDistanceMap[sig.String()] = seedClosestdistance
		} else {
			if seed_distance < fuzzer.corpusDistance[newidx] {
				fuzzer.corpusDistance[newidx] = seed_distance
			}
			if seedClosestdistance < fuzzer.corpusClosetDistance[newidx] {
				fuzzer.corpusClosetDistance[newidx] = seedClosestdistance
				fuzzer.corpusClosetDistanceMap[sig.String()] = seedClosestdistance
			}
		}
		if seed_distance > fuzzer.corpusDistance_max {
			fuzzer.corpusDistance_max = seed_distance
		}
		if seed_distance < fuzzer.corpusDistance_min {
			fuzzer.corpusDistance_min = seed_distance
		}
	}
	if fuzzer.enablePCCFG {
		for i := range cover {
			pc := uint32(i)
			if _, ok := fuzzer.boundary[pc]; ok {
				fuzzer.boundary[pc] = append(fuzzer.boundary[pc], int(newidx))
				continue // already in boundary
			}
			if _, ok := fuzzer.corpusSignal[pc]; ok {
				continue // already in corpus
			}
			shouldkeep := false
			for descendant := range fuzzer.pccfg[pc] {
				if _, ok := progSig[uint32(descendant)]; !ok {
					if _, ok := fuzzer.corpusSignal[uint32(descendant)]; !ok {
						shouldkeep = true // at least one descendant not found
					}
				}
			}
			if !shouldkeep {
				continue
			}
			fuzzer.boundary[pc] = make([]int, 0)
			fuzzer.boundary[pc] = append(fuzzer.boundary[pc], len(fuzzer.corpus))
		}
	}
	p.Idx = sig.String()
	if isnewseed {
		fuzzer.corpusSignals = append(fuzzer.corpusSignals, progSig)
	} else {
		fuzzer.corpusSignals[newidx].Merge(progSig)
	}
	if _, ok := fuzzer.corpusHashes[sig]; !ok {
		fuzzer.corpus = append(fuzzer.corpus, p)
		fuzzer.corpusHashes[sig] = newidx
		prio := int64(len(sign))
		if sign.Empty() {
			prio = 1
		}
		fuzzer.sumPrios += prio
		fuzzer.corpusPrios = append(fuzzer.corpusPrios, fuzzer.sumPrios)
	}
	fuzzer.corpusMu.Unlock()

	if !sign.Empty() {
		fuzzer.signalMu.Lock()
		fuzzer.corpusSignal.Merge(sign)
		fuzzer.maxSignal.Merge(sign)
		fuzzer.signalMu.Unlock()
	}
}

func (fuzzer *Fuzzer) snapshot() FuzzerSnapshot {
	fuzzer.corpusMu.RLock()
	defer fuzzer.corpusMu.RUnlock()
	return FuzzerSnapshot{
		fuzzer.corpus,
		fuzzer.corpusPrios,
		fuzzer.sumPrios,
		fuzzer.corpusDistance,
		fuzzer.corpusClosetDistance,
		fuzzer.corpusDistance_min,
		fuzzer.corpusDistance_max,
	}
}

func (fuzzer *Fuzzer) addMaxSignal(sign signal.Signal) {
	if sign.Len() == 0 {
		return
	}
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	fuzzer.maxSignal.Merge(sign)
}

func (fuzzer *Fuzzer) grabNewSignal() signal.Signal {
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	sign := fuzzer.newSignal
	if sign.Empty() {
		return nil
	}
	fuzzer.newSignal = nil
	return sign
}

func (fuzzer *Fuzzer) corpusSignalDiff(sign signal.Signal) signal.Signal {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	return fuzzer.corpusSignal.Diff(sign)
}

func (fuzzer *Fuzzer) checkNewSignal(p *prog.Prog, info *ipc.ProgInfo) (calls []int, extra bool) {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	for i, inf := range info.Calls {
		if fuzzer.checkNewCallSignal(p, &inf, i) {
			calls = append(calls, i)
		}
	}
	extra = fuzzer.checkNewCallSignal(p, &info.Extra, -1)
	return
}

func (fuzzer *Fuzzer) checkNewCallSignal(p *prog.Prog, info *ipc.CallInfo, call int) bool {
	diff := fuzzer.maxSignal.DiffRaw(info.Signal, signalPrio(p, info, call))
	if diff.Empty() {
		return false
	}
	fuzzer.signalMu.RUnlock()
	fuzzer.signalMu.Lock()
	fuzzer.maxSignal.Merge(diff)
	fuzzer.newSignal.Merge(diff)
	fuzzer.signalMu.Unlock()
	fuzzer.signalMu.RLock()
	return true
}

func signalPrio(p *prog.Prog, info *ipc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Errno == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

func parseOutputType(str string) OutputType {
	switch str {
	case "none":
		return OutputNone
	case "stdout":
		return OutputStdout
	case "dmesg":
		return OutputDmesg
	case "file":
		return OutputFile
	default:
		log.Fatalf("-output flag must be one of none/stdout/dmesg/file")
		return OutputNone
	}
}
