package gfuzz

import (
	"fmt"
	"github.com/google/syzkaller/pkg/log"
	"os"
	"time"
)

var fGFUZZlog *os.File
var Status string = ""

func initGFUZZlog() {
	var err error
err=os.MkdirAll("/workdir", os.ModePerm)
	fGFUZZlog, err = os.OpenFile(fmt.Sprintf("/workdir/gfuzz_%v.log", os.Getenv("INDEX")), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("cannot write gfuzz log: %v", err)
		return
	}
}

var oldline string
var oldline_cnt int
var NoLog bool

func GFUZZlog(format string, a ...interface{}) {
	if NoLog {
		return
	}
	if fGFUZZlog == nil {
		initGFUZZlog()
	}
	log.Logf(0, format, a...)
	outstr := fmt.Sprintf(format, a...)
	if outstr == oldline {
		oldline_cnt += 1
		return
	}
	if oldline_cnt > 0 {
		fmt.Fprintf(fGFUZZlog, "%s_repeat=%v %s\n", time.Now().Format("2006/01/02 15:04:05"), oldline_cnt, oldline)
	}
	oldline = outstr
	oldline_cnt = 0
	_, err := fmt.Fprintf(fGFUZZlog, "%s %s\n", time.Now().Format("2006/01/02 15:04:05"), outstr)
	if err != nil {
		log.Logf(0, "cannot write gfuzz log: %v", err)
		return
	}
}

type RuleInferredSyscalls struct {
	Name  string        `json:"name"`
	Id    int           `json:"-"`
	Rules map[string]uint `json:"rules"`
}

var RuleCalls []RuleInferredSyscalls
var UseRuleCall map[string]uint
