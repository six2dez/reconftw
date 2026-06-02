// modules.go — blank imports that trigger init() Task registrations.
//
// The canonical Go pattern: importing a package for its side-effects
// (in this case, the package's init() function calling task.Register).
//
// Phase 3 demo blank import deleted in Phase 4 plan-01 (along with
// internal/modules/demo/noop.go and cmd/reconftw/kernel_demo.go).
//
// Phase 4-7 plans add lines here when their first module port lands:
//
//	_ "github.com/six2dez/reconftw/internal/modules/subdomains"   // Phase 4 ✓
//	_ "github.com/six2dez/reconftw/internal/modules/web"          // Phase 5
//	_ "github.com/six2dez/reconftw/internal/modules/vulns"        // Phase 6
//	_ "github.com/six2dez/reconftw/internal/modules/osint"        // Phase 7

package main

import (
	// Phase 4 subdomains passive Tasks — triggers task.Register for
	// SubfinderTask, CrtTask, GithubSubdomainsTask, GitlabSubdomainsTask,
	// UrlfinderTask, HackertargetTask via passive.go init() calls.
	_ "github.com/six2dez/reconftw/internal/modules/subdomains"

	// Phase 5 web Tasks — triggers task.Register for HTTPXTask via
	// internal/modules/web/httpx.go init() call.
	_ "github.com/six2dez/reconftw/internal/modules/web"
)
