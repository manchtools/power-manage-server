module github.com/manchtools/power-manage/server

go 1.25.12

require (
	connectrpc.com/connect v1.18.1
	github.com/coder/websocket v1.8.14
	github.com/coreos/go-oidc/v3 v3.17.0
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/go-playground/validator/v10 v10.30.1
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/manchtools/power-manage-sdk v0.5.4-0.20260802194823-693bde8f143e
	github.com/oklog/ulid/v2 v2.1.0
	github.com/pires/go-proxyproto v0.15.0
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.52.0
	golang.org/x/net v0.55.0
	golang.org/x/oauth2 v0.35.0
	google.golang.org/protobuf v1.36.11
	modernc.org/sqlite v1.55.0
)

require (
	github.com/creack/pty v1.1.24 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/gabriel-vasile/mimetype v1.4.12 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.39.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.74.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

// The SDK import path differs from the actual GitHub repo URL
// (monorepo-style import path, polyrepo actual layout). Map it here
// so every `go build` uses a specific, pinned SDK commit rather than
// whatever happens to be in a local ../sdk checkout. Developers who
// want to iterate against a local SDK override this with a per-dev
// go.work at their workspace root — see server/README.md for setup.
