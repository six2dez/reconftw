module github.com/six2dez/reconftw

// 1.26.6 is the floor because there is no longer a patched 1.25.
//
// This line used to say 1.25.13, justified as "staying on 1.25 rather than
// jumping to 1.26 keeps the source-build floor low". That reasoning held only
// while 1.25 was still receiving stdlib security fixes. It is not: govulncheck
// on 1.25.13 reports **21 reachable stdlib vulnerabilities**, and EVERY ONE of
// them lists its fix on the 1.26 branch — GO-2026-6218 (net/url), GO-2026-6091
// (html/template), GO-2026-6090 (crypto/tls), GO-2026-6089 (net/http),
// GO-2026-6088 (encoding/xml), GO-2026-5972 (encoding/asn1) and the rest, with
// no 1.25 backport for any of them. Keeping the low floor now means shipping a
// release binary built against 21 known-reachable vulnerabilities.
//
// 1.26.6 (not .7) is the exact version that clears all 21 — it is the highest
// "Fixed in" across the set, so it is the minimum that closes the gate rather
// than the newest release for its own sake.
//
// CI resolves its toolchain from this file (every `setup-go` step uses
// `go-version-file: go.mod`), so this is also what the release binary is built
// with. Raising it raises the source-build floor for users; that cost is real
// and is accepted deliberately, because the alternative is known vulnerabilities.
go 1.26.6

require (
	github.com/go-playground/validator/v10 v10.30.2
	github.com/google/uuid v1.6.0
	github.com/knadh/koanf/parsers/toml/v2 v2.2.1
	github.com/knadh/koanf/providers/confmap v1.0.0
	github.com/knadh/koanf/providers/env/v2 v2.0.0
	github.com/knadh/koanf/providers/file v1.2.1
	github.com/knadh/koanf/v2 v2.3.4
	github.com/modelcontextprotocol/go-sdk v1.6.1
	github.com/pelletier/go-toml/v2 v2.3.1
	github.com/shirou/gopsutil/v3 v3.24.5
	github.com/spf13/cobra v1.9.1
	github.com/spf13/pflag v1.0.6
	go.uber.org/goleak v1.3.0
	golang.org/x/net v0.58.0
	golang.org/x/sync v0.22.0
	golang.org/x/time v0.15.0
	golang.org/x/tools v0.48.0
	modernc.org/sqlite v1.51.0
	pgregory.net/rapid v1.3.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.13 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/knadh/koanf/maps v0.1.2 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/mod v0.38.0 // indirect
	golang.org/x/oauth2 v0.35.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	modernc.org/libc v1.72.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
