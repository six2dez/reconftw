// checksums.go — the supply-chain pin surface for `reconftw install`.
//
// Every artefact a clean-machine bootstrap downloads and then EXECUTES as the
// installing user (root in the Docker builder, frequently root on a VPS) is
// pinned here to a SHA-256 that came from the vendor, alongside the version
// that digest describes. Version and digest live in the same file on purpose:
// they are one fact, and splitting them across files is exactly how a pin
// silently starts describing an artefact nobody ships any more.
//
// PROVENANCE — every value below was READ from one of these sources and is
// re-fetchable by anyone (the exact commands are in 15-08-SUMMARY.md):
//
//	Go toolchain  https://go.dev/dl/?mode=json&include=all  → files[].sha256
//	              cross-checked against
//	              https://dl.google.com/go/<file>.sha256
//	uv installer  GitHub release asset with SLSA build provenance:
//	              gh attestation verify uv-installer.sh --repo astral-sh/uv
//	rustup-init   https://static.rust-lang.org/rustup/archive/<ver>/<target>/rustup-init.sha256
//
// NEVER write a digest here that was not read from one of those sources. A
// wrong-but-plausible digest is strictly worse than an absent one: an absent
// pin fails closed and is visible, whereas a wrong pin looks resolved and
// converts the verification step into a check the operator believes they
// passed. If a digest cannot be fetched, leave the entry out — the lookup
// helpers below turn a miss into a hard error, not into "skip verification".

package installer

import (
	"fmt"

	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// --- pinned versions -------------------------------------------------------

const (
	// goVersion is the toolchain the bootstrapper installs on a clean machine.
	// It MUST match the `go` directive in go.mod and ARG GO_VERSION in
	// Docker/Dockerfile — otherwise a freshly bootstrapped host builds with a
	// different (in the drift we actually hit: older, vulnerable) toolchain
	// than CI and Docker do. TestGoVersionMatchesGoMod enforces the match.
	//
	// Changing this REQUIRES regenerating every entry in GoToolchainSHA256.
	goVersion = "1.25.13"

	// uvVersion pins the astral.sh uv installer to an immutable GitHub release
	// asset. The previously used https://astral.sh/uv/install.sh is a 301 to
	// .../uv/latest/uv-installer.sh — a FLOATING url whose body changes on
	// every uv release (it was last modified the day before this pin was
	// taken). A digest pinned against a floating url is not a pin: it is a
	// guaranteed future breakage that looks like a supply-chain failure.
	//
	// Changing this REQUIRES regenerating uvInstallerSHA256.
	uvVersion = "0.12.4"

	// rustupVersion pins rustup-init. Same reasoning as uvVersion: the classic
	// https://sh.rustup.rs is a floating script with NO vendor-published
	// checksum, so it cannot be verified at all. The versioned archive ships a
	// per-target binary WITH a published .sha256, so that is what we fetch.
	//
	// Changing this REQUIRES regenerating every entry in RustupInitSHA256.
	rustupVersion = "1.29.0"
)

// --- Go toolchain ----------------------------------------------------------

// supportedPlatforms is the authoritative list of "<GOOS>/<GOARCH>" pairs the
// Go bootstrapper can install a VERIFIED toolchain for. Adding a platform here
// without adding its digest to GoToolchainSHA256 fails
// TestGoToolchainDigestsCoverSupportedPlatforms — that is the point: the list
// and the matrix are only allowed to move together.
var supportedPlatforms = []string{
	"linux/amd64",
	"linux/arm64",
	"linux/arm",
	"darwin/amd64",
	"darwin/arm64",
}

// GoToolchainSHA256 maps "<GOOS>/<GOARCH>" to the vendor-published SHA-256 of
// the corresponding go<goVersion> archive.
//
// A single scalar constant cannot do this job: the artefact differs per
// platform, so one digest can verify at most one of the five. That is why the
// previous scalar pin was unusable in principle and not merely unfilled.
var GoToolchainSHA256 = map[string]string{
	"linux/amd64":  "39042a078ea9ceebe3ecda4a7188f0f5b96e14a071d27923ba7f40b456e85ae3",
	"linux/arm64":  "adad240fcb6bd180cf973b4b7c747baf4ec81d08b7d40ca35940ee4531971490",
	"linux/arm":    "f98ba3beb03a5c269d0115c7f8573483c139be88ce9989e53aff336826d13f5c",
	"darwin/amd64": "d742b7a53f8c8be5e02d75263883482cebabbe14ec9308cb056dd8aebeb040df",
	"darwin/arm64": "916fe61a2bc78dd516b3629ee3428b06e17141b85a70f1986c260149a3d2ffbd",
}

// goDownloadBase is the official Go distribution host.
const goDownloadBase = "https://dl.google.com/go/"

// goArchiveArch maps GOARCH to the architecture token Go uses in its RELEASE
// FILENAMES, which is not always GOARCH. Only 32-bit ARM differs: GOARCH is
// "arm" but the published tarball is go<ver>.linux-armv6l.tar.gz. Deriving the
// filename straight from runtime.GOARCH — as the previous code did — produces
// go<ver>.linux-arm.tar.gz, which does not exist and 404s after three retries.
var goArchiveArch = map[string]string{
	"arm": "armv6l",
}

// goToolchainArchive returns the published archive filename for a platform.
func goToolchainArchive(goos, goarch string) string {
	arch := goarch
	if mapped, ok := goArchiveArch[goarch]; ok {
		arch = mapped
	}
	return fmt.Sprintf("go%s.%s-%s.tar.gz", goVersion, goos, arch)
}

// goToolchainURL returns the download URL for a platform's Go archive.
func goToolchainURL(goos, goarch string) string {
	return goDownloadBase + goToolchainArchive(goos, goarch)
}

// goToolchainDigest returns the pinned SHA-256 for a platform, or an error.
//
// The error on a miss is the entire reason this is a function and not a map
// read. verifyFile treats an EMPTY expected digest as "no explicit pin" and
// returns nil, so handing it the zero value of a failed map lookup would
// silently disable supply-chain verification for every platform not in the
// matrix — the exact opposite of the intended behaviour. A miss must therefore
// terminate the bootstrap, and it does so before any bytes are downloaded.
//
// The returned error is a *coreerrors.ConfigError so it lands in the existing
// 7-class hierarchy (errors.Is(err, ErrConfig)); no eighth class is introduced.
func goToolchainDigest(goos, goarch string) (string, error) {
	platform := goos + "/" + goarch
	sum, ok := GoToolchainSHA256[platform]
	if !ok || sum == "" {
		return "", &coreerrors.ConfigError{
			Key: "platform",
			Message: fmt.Sprintf("no pinned Go digest for %s — refusing to install "+
				"an unverified toolchain", platform),
		}
	}
	return sum, nil
}

// --- uv --------------------------------------------------------------------

// uvInstallerSHA256 is the SHA-256 of the uvVersion release's uv-installer.sh.
//
// Verified via GitHub's SLSA build provenance, not merely by hashing what a
// download happened to return:
//
//	gh attestation verify uv-installer.sh --repo astral-sh/uv
//	→ built by astral-sh/uv/.github/workflows/release.yml
//
// astral publishes a sha256.sum asset per release, but it covers only the
// binary tarballs and the source archive — uv-installer.sh is NOT listed in
// it. The attestation is therefore the strongest available vendor statement
// about this specific file, and it binds this exact digest to astral's build.
//
// A var rather than a const only so the cleanup tests can drive bootstrapUV's
// success path with a stub payload; its value is guarded by
// TestBootstrapPinsAreRealDigests and TestNoPlaceholderPinsRemain.
var uvInstallerSHA256 = "f1ee4a249799525a330df57643335120150c9102db7483b1d37546cc43af3a16"

// uvInstallerURL is the immutable, versioned release asset. GitHub release
// assets cannot be rewritten once published, so this digest stays valid until
// uvVersion is deliberately bumped.
const uvInstallerURL = "https://github.com/astral-sh/uv/releases/download/" +
	uvVersion + "/uv-installer.sh"

// --- rustup ----------------------------------------------------------------

// rustupSupportedPlatforms is deliberately its own list rather than a reuse of
// supportedPlatforms: the Go matrix and the rustup matrix are pinned from
// different vendors and may legitimately diverge. Keeping them separate means
// a future platform gap in one is visible instead of being papered over by the
// other's coverage.
var rustupSupportedPlatforms = []string{
	"linux/amd64",
	"linux/arm64",
	"linux/arm",
	"darwin/amd64",
	"darwin/arm64",
}

// rustupTargets maps "<GOOS>/<GOARCH>" to the Rust target triple whose
// rustup-init binary the archive publishes.
//
// linux/arm maps to arm-unknown-linux-gnueabihf, not armv7-…: GOARCH=arm
// covers ARMv6 as well as ARMv7, and Go itself ships the ARMv6 tarball for
// that GOARCH (see goArchiveArch). Choosing the ARMv6 hard-float Rust target
// keeps the two toolchains consistent and runs on both, whereas an ARMv7
// binary would SIGILL on a Pi Zero.
var rustupTargets = map[string]string{
	"linux/amd64":  "x86_64-unknown-linux-gnu",
	"linux/arm64":  "aarch64-unknown-linux-gnu",
	"linux/arm":    "arm-unknown-linux-gnueabihf",
	"darwin/amd64": "x86_64-apple-darwin",
	"darwin/arm64": "aarch64-apple-darwin",
}

// RustupInitSHA256 maps "<GOOS>/<GOARCH>" to the vendor-published SHA-256 of
// the rustup-init BINARY for rustupVersion.
//
// This replaced a scalar pin on the https://sh.rustup.rs shell script. The
// script is OS-independent, so a scalar was structurally fine — but it is
// served from a floating URL with no published checksum anywhere, so there was
// no honest value to put in that scalar. The versioned per-target binary does
// publish a checksum, so switching to it is what makes a real pin possible at
// all. Consequence: this pin is per-platform, hence the matrix.
var RustupInitSHA256 = map[string]string{
	"linux/amd64":  "4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10",
	"linux/arm64":  "9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792",
	"linux/arm":    "f06435564f0ed1aad970216b737a9594aa676a488baa22c6fbd1488fa916c4d7",
	"darwin/amd64": "33cf85df9142bc6d29cbc62fa5ca1d4c29622cddb55213a4c1a43c457fb9b2d7",
	"darwin/arm64": "aeb4105778ca1bd3c6b0e75768f581c656633cd51368fa61289b6a71696ac7e1",
}

// rustupInitURL returns the versioned rustup-init download URL for a platform,
// erroring for a platform with no pinned target triple.
func rustupInitURL(goos, goarch string) (string, error) {
	platform := goos + "/" + goarch
	target, ok := rustupTargets[platform]
	if !ok {
		return "", &coreerrors.ConfigError{
			Key: "platform",
			Message: fmt.Sprintf("no rustup-init target for %s — refusing to install "+
				"an unverified Rust toolchain", platform),
		}
	}
	return fmt.Sprintf("https://static.rust-lang.org/rustup/archive/%s/%s/rustup-init",
		rustupVersion, target), nil
}

// rustupInitDigest returns the pinned rustup-init SHA-256 for a platform.
// Same fail-closed contract as goToolchainDigest: a miss is an error, never an
// empty string that verifyFile would wave through.
func rustupInitDigest(goos, goarch string) (string, error) {
	platform := goos + "/" + goarch
	sum, ok := RustupInitSHA256[platform]
	if !ok || sum == "" {
		return "", &coreerrors.ConfigError{
			Key: "platform",
			Message: fmt.Sprintf("no pinned rustup-init digest for %s — refusing to "+
				"install an unverified Rust toolchain", platform),
		}
	}
	return sum, nil
}
