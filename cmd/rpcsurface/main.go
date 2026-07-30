// Command rpcsurface prints pm.v1 procedure paths, one per line, as
// `/pm.v1.<Service>/<Method>`.
//
// It exists so the deployment gate can ask a RUNNING listener "do you serve
// exactly these?" without anyone maintaining a list by hand. The set is derived
// from the descriptor registry, so it follows the contract automatically.
//
// -services SELECTS, and selecting is mandatory in practice, because the
// contract's services are deliberately spread across DIFFERENT processes and
// listeners: ControlService on control's public listener, InternalService on
// its mTLS listener, AgentService wherever the agent stream terminates, and
// DeviceAuthService on the agent's own local enrollment socket. A single global
// list is therefore not a meaningful expectation for any one listener — it
// would report the other processes' services as missing, and, worse, could not
// express the property that actually matters: that a service is NOT reachable
// on a listener it does not belong to.
//
// -invert emits every service EXCEPT those named, which is how the caller
// builds the must-not-be-served set for a given listener.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	// Imported for descriptor registration side effects: without this the
	// registry is empty and the tool would print nothing, which the caller must
	// treat as a failure rather than as "no RPCs".
	_ "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

func main() {
	services := flag.String("services", "", "comma-separated service names to include (required)")
	invert := flag.Bool("invert", false, "emit every service EXCEPT those named")
	flag.Parse()

	if strings.TrimSpace(*services) == "" {
		fmt.Fprintln(os.Stderr, "rpcsurface: -services is required; a global list is not a valid "+
			"expectation for any single listener (see the package comment)")
		os.Exit(2)
	}
	want := map[string]bool{}
	for _, s := range strings.Split(*services, ",") {
		if s = strings.TrimSpace(s); s != "" {
			want[s] = true
		}
	}

	seen := map[string]bool{}
	var procedures []string
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if fd.Package() != "pm.v1" {
			return true
		}
		svcs := fd.Services()
		for i := 0; i < svcs.Len(); i++ {
			sd := svcs.Get(i)
			name := string(sd.Name())
			seen[name] = true
			if want[name] == *invert {
				continue
			}
			ms := sd.Methods()
			for j := 0; j < ms.Len(); j++ {
				procedures = append(procedures, fmt.Sprintf("/pm.v1.%s/%s", name, ms.Get(j).Name()))
			}
		}
		return true
	})

	if len(seen) == 0 {
		fmt.Fprintln(os.Stderr, "rpcsurface: no pm.v1 services in the descriptor registry — "+
			"the enumeration is broken, and emitting an empty set would let the gate pass vacuously")
		os.Exit(1)
	}
	// A name that matches no live service is a stale expectation: it would
	// silently contribute nothing and shrink the set the gate checks.
	for name := range want {
		if !seen[name] {
			fmt.Fprintf(os.Stderr, "rpcsurface: -services names %q but no such pm.v1 service exists — stale expectation\n", name)
			os.Exit(1)
		}
	}
	if len(procedures) == 0 {
		fmt.Fprintln(os.Stderr, "rpcsurface: selection matched zero procedures — refusing to emit an empty set")
		os.Exit(1)
	}

	sort.Strings(procedures)
	for _, p := range procedures {
		fmt.Println(p)
	}
}
