// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"time"
	"math/rand"
	//"encoding/json"
	"os"
	//"io/ioutil"
	
	"github.com/google/syzkaller/gfuzz"

	. "github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/pkg/mgrconfig"
)

func main() {
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	ct := target.BuildChoiceTable(nil, nil)
	syscallid := -1
	for idx, syscall := range target.Syscalls {
	    if syscall.Name == os.Args[1]{
	    	fmt.Printf("%v %v %v\n", idx, syscall.Name, syscall)
	    	syscallid = syscall.ID
	    }
	}
	gfuzz.UseRuleCall = nil
	if syscallid != -1{
	    for i:=0; i<10000; i++{
	        fmt.Printf("[%d] %s", i, target.GeneratebySyscall(rnd, RecommendedCalls, ct, append(make([]int, 0), syscallid)).Serialize())
	    }
	}

}