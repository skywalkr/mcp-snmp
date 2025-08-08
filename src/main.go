package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"snmp_mcp_server/config"
	"strconv"
	"strings"
	"sync"

	"github.com/gosnmp/gosnmp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	C *config.Config

	// Version returns the version of the mcp-net-snmp binary.
	// It uses runtime/debug to fetch version information from the build, returning "(devel)" for local development builds.
	// The version is computed once and cached for performance.
	Version = sync.OnceValue(func() string {
		// Default version string returned by `runtime/debug` if built
		// from the source repository rather than with `go install`.
		v := "(devel)"
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
			v = bi.Main.Version
		}
		return v
	})
)

func parseLevel(level string) slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return slog.LevelInfo
	}
	return l
}

func main() {
	configFile := flag.String("config-file", "net-snmp.yml", "Path to configuration file.")
	expandEnvVars := flag.Bool("config-expand-environment-variables", false, "Expand environment variables to source secrets")

	transport := flag.String("transport", "stdio", "Transport type (stdio or http)")
	addr := flag.String("transport-address", "localhost:8000", "The host and port to start the streamable-http server on")
	//endpointPath := flag.String("transport-address-path", "/mcp", "Endpoint path for the streamable-http server")
	logLevel := flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	flag.Parse()

	conf, err := config.LoadFile(*configFile, *expandEnvVars)

	if err != nil {
		slog.Error("failed parsing config file", "error", err)
		os.Exit(1)
	}

	C = conf

	if err := run(*transport, *addr, parseLevel(*logLevel)); err != nil {
		panic(err)
	}
}

func run(transport, addr string, logLevel slog.Level) error {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))
	server := mcp.NewServer(&mcp.Implementation{Name: "net-snmp-tools", Version: Version()}, &mcp.ServerOptions{})

	mcp.AddTool(server, &mcp.Tool{Name: "net_snmp_get", Description: "The net_snmp_get command is used to retrieve the value of a specific OID (Object Identifier) from an SNMP-enabled device. It performs a single request to fetch the value of one or more explicitly specified OIDs, and is ideal when you know exactly what piece of data you're querying."}, getHandler)
	mcp.AddTool(server, &mcp.Tool{Name: "net_snmp_walk", Description: "The net_snmp_walk command is used to recursively retrieve a subtree of OIDs from an SNMP agent. It starts from a given root OID and walks down the tree, returning all OIDs and their values beneath it. This is useful for exploring available SNMP data or retrieving entire tables (e.g., interface lists, ARP tables)."}, walkHandler)

	if transport == "http" {
		handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
			return server
		}, nil)
		slog.Info("Starting Net-SNMP MCP server using StreamableHTTP transport", "version", Version(), "address", addr)
		return http.ListenAndServe(addr, handler)
	} else {
		slog.Info("Starting Net-SNMP MCP server using stdio transport", "version", Version())
		return server.Run(context.Background(), mcp.NewStdioTransport())
	}
}

func NewGoSNMP(auth string, target string) (*gosnmp.GoSNMP, error) {
	transport := "udp"
	if s := strings.SplitN(target, "://", 2); len(s) == 2 {
		transport = s[0]
		target = s[1]
	}
	port := uint16(161)
	if host, _port, err := net.SplitHostPort(target); err == nil {
		target = host
		p, err := strconv.Atoi(_port)
		if err != nil {
			return nil, fmt.Errorf("failed converting port number to int for target %q: %w", target, err)
		}
		port = uint16(p)
	}

	g := &gosnmp.GoSNMP{
		ExponentialTimeout: true,
		MaxOids:            gosnmp.MaxOids,
		Port:               port,
		Retries:            *C.Options.Retries,
		Target:             target,
		Timeout:            C.Options.Timeout,
		Transport:          transport,
	}

	if C.Options.AllowNonIncreasingOIDs {
		g.AppOpts = map[string]any{
			"c": true,
		}
	}

	cauth, authOk := C.Auths[auth]
	if authOk {
		cauth.ConfigureSNMP(g, "")
	}

	return g, nil
}
