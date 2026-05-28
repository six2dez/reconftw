// modules.go — blank imports that trigger init() Task registrations.
//
// The canonical Go pattern: importing a package for its side-effects
// (in this case, the package's init() function calling task.Register).
//
// Phase 3: only the demo.NoopTask. Phase 4-7 plans add more lines here
// when their first module port lands:
//
//	_ "github.com/six2dez/reconftw/internal/modules/subdomains"   // Phase 4
//	_ "github.com/six2dez/reconftw/internal/modules/web"          // Phase 5
//	_ "github.com/six2dez/reconftw/internal/modules/vulns"        // Phase 6
//	_ "github.com/six2dez/reconftw/internal/modules/osint"        // Phase 7
//
// Phase 4 plan-01 also DELETES the demo line below (and the corresponding
// internal/modules/demo/noop.go file) when the first real Task ships.

package main

import (
	// Phase 3 demo Task — DELETED in Phase 4 plan-01. Triggers task.Register
	// of NoopTask via internal/modules/demo/noop.go's init().
	_ "github.com/six2dez/reconftw/internal/modules/demo"
)
