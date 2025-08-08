package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type GetParams struct {
	Auth   string   `json:"auth" jsonschema:"Authorization"`
	OIDs   []string `json:"oids" jsonschema:"OID(s) to get"`
	Target string   `json:"target" jsonschema:"Target IP or hostname"`
}

type WalkParams struct {
	Auth   string `json:"auth" jsonschema:"Authorization"`
	OID    string `json:"oid" jsonschema:"Root OID to walk"`
	Target string `json:"target" jsonschema:"Target IP or hostname"`
}

func getHandler(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[GetParams]) (*mcp.CallToolResultFor[any], error) {
	g, err := NewGoSNMP(params.Arguments.Auth, params.Arguments.Target)

	if err != nil {
		return nil, fmt.Errorf("failed to create snmp client: '%w'", err)
	}

	slog.Debug("Connect()", "target", g.Target, "version", g.Version)
	if err := g.Connect(); err != nil {
		slog.Error("Connect()", "target", g.Target, "version", g.Version, "error", err)
		return nil, fmt.Errorf("failed connecting to target %s: %s", g.Target, err)
	}
	defer g.Conn.Close()

	slog.Debug("Get()", "target", g.Target, "OID(s)", params.Arguments.OIDs)
	res, err := g.Get(params.Arguments.OIDs)

	if err != nil {
		slog.Error("Get()", "target", g.Target, "version", g.Version, "error", err)
		return nil, fmt.Errorf("failed getting target %s: %s", g.Target, err)
	}

	var sb strings.Builder

	for _, pdu := range res.Variables {
		formatValue(&sb, pdu)
	}

	return &mcp.CallToolResultFor[any]{
		Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}},
	}, nil
}

func walkHandler(ctx context.Context, cc *mcp.ServerSession, params *mcp.CallToolParamsFor[WalkParams]) (*mcp.CallToolResultFor[any], error) {
	g, err := NewGoSNMP(params.Arguments.Auth, params.Arguments.Target)

	if err != nil {
		return nil, fmt.Errorf("failed to create snmp client: '%w'", err)
	}

	slog.Debug("Connect()", "target", g.Target, "version", g.Version)
	if err := g.Connect(); err != nil {
		slog.Error("Connect()", "target", g.Target, "version", g.Version, "error", err)
		return nil, fmt.Errorf("failed connecting to target %s: %s", g.Target, err)
	}
	defer g.Conn.Close()

	var sb strings.Builder

	slog.Debug("BulkWalk()", "target", g.Target, "OID", params.Arguments.OID)
	if err := g.BulkWalk(params.Arguments.OID, func(pdu gosnmp.SnmpPDU) error {
		formatValue(&sb, pdu)
		return nil
	}); err != nil {
		slog.Error("BulkWalk()", "target", g.Target, "version", g.Version, "error", err)
		return nil, fmt.Errorf("failed walking target %s: %s", g.Target, err)
	}

	return &mcp.CallToolResultFor[any]{
		Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}},
	}, nil
}

func formatValue(writer io.Writer, pdu gosnmp.SnmpPDU) {
	switch pdu.Type {
	case gosnmp.Integer:
		fmt.Fprintf(writer, "%s = INTEGER: %d\n", pdu.Name, pdu.Value)
	case gosnmp.IPAddress:
		fmt.Fprintf(writer, "%s = IpAddress: %s\n", pdu.Name, pdu.Value)
	case gosnmp.NoSuchInstance:
		fmt.Fprintf(writer, "%s = No Such Instance currently exists at this OID\n", pdu.Name)
	case gosnmp.NoSuchObject:
		fmt.Fprintf(writer, "%s = No Such Object available on this agent at this OID\n", pdu.Name)
	case gosnmp.ObjectIdentifier:
		fmt.Fprintf(writer, "%s = OID: %s\n", pdu.Name, pdu.Value)
	case gosnmp.OctetString:
		bytes := pdu.Value.([]byte)

		isHex := false
		for _, r := range string(bytes) {
			if r < 32 || r > 126 {
				isHex = true
			}
		}

		if isHex {
			fmt.Fprintf(writer, "%s = Hex-STRING: % X\n", pdu.Name, bytes)
		} else {
			fmt.Fprintf(writer, "%s = STRING: %s\n", pdu.Name, string(bytes))
		}
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
