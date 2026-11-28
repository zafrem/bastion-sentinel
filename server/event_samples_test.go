package server

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zafrem/bastion-sentinel/types"
)

// TestEventSamples builds an event with every constructor in this package. The cross-module contract test in the
// bastion-rag repository sets BASTION_EVENT_SAMPLES and checks that Tracker handles each one.
func TestEventSamples(t *testing.T) {
	tc := TraceContext{TraceID: "contract-sentinel", SpanID: "span-1", TenantID: "tenant-a", UserID: "user-1", RequestID: "request-1"}
	samples := map[string][]SentinelEvent{
		"EventInputValidated":         {EventInputValidated(tc, 0.1, "full")},
		"EventPipelineRoutingDecided": {EventPipelineRoutingDecided(tc, "full", "input_validated")},
		"EventInjectionDetected":      {EventInjectionDetected(tc, 0.8, []string{"ignore_instructions"})},
		"EventInjectionBlocked":       {EventInjectionBlocked(tc, 0.9, "ignore_instructions")},
		"EventOutputValidated":        {EventOutputValidated(tc, string(types.OutputStatusPassed), ""), EventOutputValidated(tc, string(types.OutputStatusSanitized), ""), EventOutputValidated(tc, string(types.OutputStatusBlocked), ""), EventOutputValidated(tc, string(types.OutputStatusWarning), "")},
		"EventPIIPrevented":           {EventPIIPrevented(tc, []string{"email"}, 1)},
		"EventExceptionApplied":       {EventExceptionApplied(tc, []string{"EXC-1"})},
		"EventContentFiltered":        {EventContentFiltered(tc, "violence")},
		"EventHoneyTokenReferenced":   {EventHoneyTokenReferenced(tc, "HT-0001", "decoy")},
		"EventHoneyTokenLeaked":       {EventHoneyTokenLeaked(tc, "HT-0001", "decoy")},
		"EventIndustryFilterBlocked":  {EventIndustryFilterBlocked(tc, "finance", "reason")},
		"EventIndustryFilterRedacted": {EventIndustryFilterRedacted(tc, "finance", "reason")},
	}

	// A constructor missing from the table would escape the contract test.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() || fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
				continue
			}
			if result, ok := fn.Type.Results.List[0].Type.(*ast.Ident); !ok || result.Name != "SentinelEvent" {
				continue
			}
			if len(samples[fn.Name.Name]) == 0 {
				t.Errorf("%s (%s) has no sample here: add one", fn.Name.Name, file)
			}
		}
	}

	path := os.Getenv("BASTION_EVENT_SAMPLES")
	if path == "" {
		return
	}
	out, err := os.Create(path) // #nosec G304 G703 -- path chosen by the test that asked for the samples
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	for _, events := range samples {
		for _, ev := range events {
			if err := json.NewEncoder(out).Encode(ev); err != nil {
				t.Fatal(err)
			}
		}
	}
}
