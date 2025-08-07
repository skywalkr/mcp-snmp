package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"snmp_mcp_server/config"

	"github.com/gosnmp/gosnmp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	C                 *config.Config
	configFile        = flag.String("config-file", "snmp.yml", "Path to configuration file.")
	expandEnvVars     = flag.Bool("config-expand-environment-variables", false, "Expand environment variables to source secrets")
	httpListenAddress = flag.String("http-listen-address", "", "Address to use with SSE instead of STDIO.")
)

func main() {
	flag.Parse()

	conf, err := config.LoadFile(*configFile, *expandEnvVars)

	if err != nil {
		log.Fatalf("Error parsing config file: %s", err)
	}

	C = conf
	server := mcp.NewServer(&mcp.Implementation{Name: "snmp-tools", Version: "v1.0.0"}, nil)

	mcp.AddTool(server, &mcp.Tool{Name: "skywalkr_snmp_get", Description: "The skywalkr_snmp_get command is used to retrieve the value of a specific OID (Object Identifier) from an SNMP-enabled device. It performs a single request to fetch the value of one or more explicitly specified OIDs, and is ideal when you know exactly what piece of data you're querying."}, SnmpGet)
	mcp.AddTool(server, &mcp.Tool{Name: "skywalkr_snmp_walk", Description: "The skywalkr_snmp_walk command is used to recursively retrieve a subtree of OIDs from an SNMP agent. It starts from a given root OID and walks down the tree, returning all OIDs and their values beneath it. This is useful for exploring available SNMP data or retrieving entire tables (e.g., interface lists, ARP tables)."}, SnmpWalk)

	if *httpListenAddress != "" {
		handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
			return server
		}, nil)

		http.ListenAndServe(*httpListenAddress, handler)
		log.Printf("MCP server listening at %s", *httpListenAddress)
	} else {
		// Run the server over stdin/stdout, until the client disconnects
		if err := server.Run(context.Background(), mcp.NewStdioTransport()); err != nil {
			log.Fatal(err)
		}
	}
}

func NewGoSNMP(auth string, target string) *gosnmp.GoSNMP {
	g := &gosnmp.GoSNMP{
		ExponentialTimeout: true,
		MaxOids:            gosnmp.MaxOids,
		Port:               161,
		Retries:            *C.WalkParams.Retries,
		Target:             target,
		Timeout:            C.WalkParams.Timeout,
	}

	if C.WalkParams.AllowNonIncreasingOIDs {
		g.AppOpts = map[string]any{
			"c": true,
		}
	}

	cauth, authOk := C.Auths[auth]
	if authOk {
		cauth.ConfigureSNMP(g, "")
	}

	return g
}
