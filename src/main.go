package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"snmp_mcp_server/config"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	C                 = &config.Config{}
	configFile        = flag.String("config-file", "snmp.yml", "Path to configuration file.")
	dryRun            = flag.Bool("dry-run", false, "Only verify configuration is valid and exit.")
	expandEnvVars     = flag.Bool("config-expand-environment-variables", false, "Expand environment variables to source secrets")
	httpListenAddress = flag.String("http-listen-address", "", "Address to use with SSE instead of STDIO.")
)

type GetParams struct {
	Auth     string   `json:"auth" jsonschema:"the authentication used for the SNMP request"`
	OIDs     []string `json:"oids" jsonschema:"the OID(s) to query"`
	Hostname string   `json:"hostname" jsonschema:"the target of the SNMP request"`
}

type WalkParams struct {
	Auth     string `json:"auth" jsonschema:"the authentication used for the SNMP request"`
	OID      string `json:"oid" jsonschema:"the root OID to query"`
	Hostname string `json:"hostname" jsonschema:"the target of the SNMP request"`
}

func SnmpGet(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[GetParams]) (*mcp.CallToolResultFor[any], error) {
	g := &gosnmp.GoSNMP{
		ExponentialTimeout: true,
		MaxOids:            gosnmp.MaxOids,
		MaxRepetitions:     C.WalkParams.MaxRepetitions,
		Port:               161,
		Retries:            *C.WalkParams.Retries,
		Target:             params.Arguments.Hostname,
		Timeout:            C.WalkParams.Timeout,
	}

	C.Auths[params.Arguments.Auth].ConfigureSNMP(g, "")

	err := g.Connect()
	if err != nil {
		log.Printf("Connect() err: %v", err)
	}
	defer g.Conn.Close()

	res, err := g.Get(params.Arguments.OIDs)

	if err != nil {
		log.Printf("Walk() err: %v", err)
	}

	var sb strings.Builder

	for _, pdu := range res.Variables {
		formatValue(&sb, pdu)
	}

	return &mcp.CallToolResultFor[any]{
		Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}},
	}, nil
}

func SnmpWalk(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[WalkParams]) (*mcp.CallToolResultFor[any], error) {
	g := &gosnmp.GoSNMP{
		ExponentialTimeout: true,
		MaxOids:            gosnmp.MaxOids,
		MaxRepetitions:     C.WalkParams.MaxRepetitions,
		Port:               161,
		Retries:            *C.WalkParams.Retries,
		Target:             params.Arguments.Hostname,
		Timeout:            C.WalkParams.Timeout,
	}

	C.Auths[params.Arguments.Auth].ConfigureSNMP(g, "")

	err := g.Connect()
	if err != nil {
		log.Printf("Connect() err: %v", err)
	}
	defer g.Conn.Close()

	var sb strings.Builder

	err = g.Walk(params.Arguments.OID, func(pdu gosnmp.SnmpPDU) error {
		formatValue(&sb, pdu)
		return nil
	})

	if err != nil {
		log.Printf("Walk() err: %v", err)
	}

	return &mcp.CallToolResultFor[any]{
		Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}},
	}, nil
}

func main() {
	flag.Parse()

	// Bail early if the config is bad.
	conf, err := config.LoadFile(*configFile, *expandEnvVars)

	if err != nil {
		log.Printf("Error parsing config file: %s", err)
		os.Exit(1)
	}
	if len(conf.Auths) == 0 {
		log.Print("Configuration is missing Auths.")
		os.Exit(1)
	}

	// Exit if in dry-run mode.
	if *dryRun {
		log.Print("Configuration parsed successfully")
		return
	}

	C = conf

	// Create a server with a single tool.
	server := mcp.NewServer(&mcp.Implementation{Name: "greeter", Version: "v1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "snmpget", Description: "Communicates with a network entity using SNMP GET requests"}, SnmpGet)
	mcp.AddTool(server, &mcp.Tool{Name: "snmpwalk", Description: "Communicates with a network entity using SNMP WALK requests"}, SnmpWalk)

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

func formatValue(writer io.Writer, pdu gosnmp.SnmpPDU) {
	switch pdu.Type {
	case gosnmp.Integer:
		fmt.Fprintf(writer, "%s = INTEGER: %d\n", pdu.Name, pdu.Value)
	case gosnmp.ObjectIdentifier:
		fmt.Fprintf(writer, "%s = OID: %s\n", pdu.Name, pdu.Value)
	case gosnmp.OctetString:
		bytes := pdu.Value.([]byte)
		fmt.Fprintf(writer, "%s = STRING: %s\n", pdu.Name, string(bytes))
	case gosnmp.TimeTicks:
		duration := time.Duration(gosnmp.ToBigInt(pdu.Value).Int64()*10) * time.Millisecond
		fmt.Fprintf(writer, "%s = Timeticks: (%d) %.2d days, %.2d:%.2d:%.2d.%.3d\n", pdu.Name, gosnmp.ToBigInt(pdu.Value).Int64(), int64(duration.Hours()/24), int64(math.Mod(duration.Hours(), 24)), int64(math.Mod(duration.Minutes(), 60)), int64(math.Mod(duration.Seconds(), 60)), int64(math.Mod(float64(duration.Milliseconds()), 1000)))
	default:
		// ... or often you're just interested in numeric values.
		// ToBigInt() will return the Value as a BigInt, for plugging
		// into your calculations.
		fmt.Fprintf(writer, "%s = %s: %d\n", pdu.Name, pdu.Type, pdu.Value)
	}
}
