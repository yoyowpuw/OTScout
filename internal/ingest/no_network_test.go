package ingest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strconv"
	"strings"
	"testing"
)

// The claim that ingest sends nothing is the reason a plant will let otscout near
// its network at all. A claim that rests on nobody having added a socket by
// accident is worth very little, so the tests below read the package source and
// check it structurally. They fail the moment someone adds the capability, rather
// than the moment someone notices.

// forbiddenImports are packages that exist to talk to something.
var forbiddenImports = map[string]string{
	"net/http":          "an HTTP client or server",
	"net/rpc":           "a remote procedure call client",
	"net/smtp":          "a mail client",
	"os/exec":           "running another program, which could send traffic on our behalf",
	"net/http/httputil": "an HTTP proxy",
}

// forbiddenNetCalls are the functions in the net package that touch the network.
// The package itself is allowed because ParseIP and ParseMAC are pure parsing and
// there is no reason to reimplement them.
var forbiddenNetCalls = map[string]bool{
	"Dial":               true,
	"DialTimeout":        true,
	"DialIP":             true,
	"DialTCP":            true,
	"DialUDP":            true,
	"DialUnix":           true,
	"Listen":             true,
	"ListenIP":           true,
	"ListenTCP":          true,
	"ListenUDP":          true,
	"ListenUnix":         true,
	"ListenPacket":       true,
	"ListenMulticastUDP": true,
	// Resolution and lookup send DNS queries, which is still traffic leaving the
	// machine on account of something otscout read.
	"LookupAddr":      true,
	"LookupCNAME":     true,
	"LookupHost":      true,
	"LookupIP":        true,
	"LookupMX":        true,
	"LookupNS":        true,
	"LookupPort":      true,
	"LookupSRV":       true,
	"LookupTXT":       true,
	"ResolveIPAddr":   true,
	"ResolveTCPAddr":  true,
	"ResolveUDPAddr":  true,
	"ResolveUnixAddr": true,
	"FileConn":        true,
	"FileListener":    true,
	"FilePacketConn":  true,
}

// parsePackageFiles reads the non-test sources of this package.
func parsePackageFiles(t *testing.T) map[string]*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	pkg, ok := pkgs["ingest"]
	if !ok {
		t.Fatal("the ingest package was not found in the current directory")
	}
	if len(pkg.Files) == 0 {
		t.Fatal("no source files were parsed, so the check proved nothing")
	}
	return pkg.Files
}

func TestIngestImportsNothingThatCanReachTheNetwork(t *testing.T) {
	for name, file := range parsePackageFiles(t) {
		for _, imported := range file.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatalf("%s: unreadable import path %s", name, imported.Path.Value)
			}
			if reason, forbidden := forbiddenImports[path]; forbidden {
				t.Errorf("%s imports %q, which provides %s. The passive path must send nothing.",
					name, path, reason)
			}
		}
	}
}

func TestIngestCallsNoNetworkFunction(t *testing.T) {
	for name, file := range parsePackageFiles(t) {
		// Find the local name of the net import, since a file could rename it.
		netAlias := ""
		for _, imported := range file.Imports {
			path, _ := strconv.Unquote(imported.Path.Value)
			if path != "net" {
				continue
			}
			netAlias = "net"
			if imported.Name != nil {
				netAlias = imported.Name.Name
			}
		}
		if netAlias == "" {
			continue
		}

		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := selector.X.(*ast.Ident)
			if !ok || ident.Name != netAlias {
				return true
			}
			if forbiddenNetCalls[selector.Sel.Name] {
				t.Errorf("%s calls %s.%s, which reaches the network. The passive path must send nothing.",
					name, netAlias, selector.Sel.Name)
			}
			return true
		})
	}
}

func TestIngestBuildsNoProtocolRequest(t *testing.T) {
	// The protocol package is imported for its decoders. Its request builders
	// produce bytes meant to be put on the wire, and nothing on the passive path
	// has any reason to construct them. Referring to one would mean a probe had
	// been assembled in the one place that promises never to send.
	for name, file := range parsePackageFiles(t) {
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := selector.X.(*ast.Ident)
			if !ok || ident.Name != "protocol" {
				return true
			}
			if strings.HasSuffix(selector.Sel.Name, "Request") {
				t.Errorf("%s refers to protocol.%s, which builds bytes to send",
					name, selector.Sel.Name)
			}
			return true
		})
	}
}
