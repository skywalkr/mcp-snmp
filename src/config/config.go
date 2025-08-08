package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/gosnmp/gosnmp"
	"gopkg.in/yaml.v2"
)

var (
	defaultRetries = 3

	DefaultAuth = Auth{
		Community:     "public",
		SecurityLevel: "noAuthNoPriv",
		AuthProtocol:  "MD5",
		PrivProtocol:  "DES",
		Version:       2,
	}

	DefaultOptions = Options{
		MaxRepetitions:          25,
		Retries:                 &defaultRetries,
		Timeout:                 time.Second * 5,
		UseUnconnectedUDPSocket: false,
		AllowNonIncreasingOIDs:  false,
	}
)

type Auth struct {
	Community     Secret `yaml:"community,omitempty"`
	SecurityLevel string `yaml:"security_level,omitempty"`
	Username      string `yaml:"username,omitempty"`
	Password      Secret `yaml:"password,omitempty"`
	AuthProtocol  string `yaml:"auth_protocol,omitempty"`
	PrivProtocol  string `yaml:"priv_protocol,omitempty"`
	PrivPassword  Secret `yaml:"priv_password,omitempty"`
	ContextName   string `yaml:"context_name,omitempty"`
	Version       int    `yaml:"version,omitempty"`
}

// Config for the snmp_exporter.
type Config struct {
	Auths   map[string]*Auth `yaml:"auths,omitempty"`
	Options Options          `yaml:"options,omitempty"`
}

type Options struct {
	MaxRepetitions          uint32        `yaml:"max_repetitions,omitempty"`
	Retries                 *int          `yaml:"retries,omitempty"`
	Timeout                 time.Duration `yaml:"timeout,omitempty"`
	UseUnconnectedUDPSocket bool          `yaml:"use_unconnected_udp_socket,omitempty"`
	AllowNonIncreasingOIDs  bool          `yaml:"allow_nonincreasing_oids,omitempty"`
}

type Secret string

func (s *Secret) Set(value string) {
	*s = Secret(value)
}

func LoadFile(path string, expandEnvVars bool) (*Config, error) {
	cfg := &Config{
		Options: DefaultOptions,
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = yaml.UnmarshalStrict(content, cfg)
	if err != nil {
		return nil, err
	}

	if expandEnvVars {
		var err error
		for i, auth := range cfg.Auths {
			if auth.Username != "" {
				cfg.Auths[i].Username, err = substituteEnvVariables(auth.Username)
				if err != nil {
					return nil, err
				}
			}
			if auth.Password != "" {
				password, err := substituteEnvVariables(string(auth.Password))
				if err != nil {
					return nil, err
				}
				cfg.Auths[i].Password.Set(password)
			}
			if auth.PrivPassword != "" {
				privPassword, err := substituteEnvVariables(string(auth.PrivPassword))
				if err != nil {
					return nil, err
				}
				cfg.Auths[i].PrivPassword.Set(privPassword)
			}
		}
	}

	return cfg, nil
}

// ConfigureSNMP sets the various version and auth settings.
func (c Auth) ConfigureSNMP(g *gosnmp.GoSNMP, snmpContext string) {
	switch c.Version {
	case 1:
		g.Version = gosnmp.Version1
	case 2:
		g.Version = gosnmp.Version2c
	case 3:
		g.Version = gosnmp.Version3
	}
	g.Community = string(c.Community)

	if snmpContext == "" {
		g.ContextName = c.ContextName
	} else {
		g.ContextName = snmpContext
	}

	// v3 security settings.
	g.SecurityModel = gosnmp.UserSecurityModel
	usm := &gosnmp.UsmSecurityParameters{
		UserName: c.Username,
	}
	auth, priv := false, false
	switch c.SecurityLevel {
	case "noAuthNoPriv":
		g.MsgFlags = gosnmp.NoAuthNoPriv
	case "authNoPriv":
		g.MsgFlags = gosnmp.AuthNoPriv
		auth = true
	case "authPriv":
		g.MsgFlags = gosnmp.AuthPriv
		auth = true
		priv = true
	}
	if auth {
		usm.AuthenticationPassphrase = string(c.Password)
		switch c.AuthProtocol {
		case "SHA":
			usm.AuthenticationProtocol = gosnmp.SHA
		case "SHA224":
			usm.AuthenticationProtocol = gosnmp.SHA224
		case "SHA256":
			usm.AuthenticationProtocol = gosnmp.SHA256
		case "SHA384":
			usm.AuthenticationProtocol = gosnmp.SHA384
		case "SHA512":
			usm.AuthenticationProtocol = gosnmp.SHA512
		case "MD5":
			usm.AuthenticationProtocol = gosnmp.MD5
		}
	}
	if priv {
		usm.PrivacyPassphrase = string(c.PrivPassword)
		switch c.PrivProtocol {
		case "DES":
			usm.PrivacyProtocol = gosnmp.DES
		case "AES":
			usm.PrivacyProtocol = gosnmp.AES
		case "AES192":
			usm.PrivacyProtocol = gosnmp.AES192
		case "AES192C":
			usm.PrivacyProtocol = gosnmp.AES192C
		case "AES256":
			usm.PrivacyProtocol = gosnmp.AES256
		case "AES256C":
			usm.PrivacyProtocol = gosnmp.AES256C
		}
	}
	g.SecurityParameters = usm
}

func (c *Auth) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultAuth
	type plain Auth
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}

	if c.Version < 1 || c.Version > 3 {
		return fmt.Errorf("SNMP version must be 1, 2 or 3. Got: %d", c.Version)
	}
	if c.Version == 3 {
		switch c.SecurityLevel {
		case "authPriv":
			if c.PrivPassword == "" {
				return fmt.Errorf("priv password is missing, required for SNMPv3 with priv")
			}
			if c.PrivProtocol != "DES" && c.PrivProtocol != "AES" && c.PrivProtocol != "AES192" && c.PrivProtocol != "AES192C" && c.PrivProtocol != "AES256" && c.PrivProtocol != "AES256C" {
				return fmt.Errorf("priv protocol must be DES or AES")
			}
			fallthrough
		case "authNoPriv":
			if c.Password == "" {
				return fmt.Errorf("auth password is missing, required for SNMPv3 with auth")
			}
			if c.AuthProtocol != "MD5" && c.AuthProtocol != "SHA" && c.AuthProtocol != "SHA224" && c.AuthProtocol != "SHA256" && c.AuthProtocol != "SHA384" && c.AuthProtocol != "SHA512" {
				return fmt.Errorf("auth protocol must be SHA or MD5")
			}
			fallthrough
		case "noAuthNoPriv":
			if c.Username == "" {
				return fmt.Errorf("auth username is missing, required for SNMPv3")
			}
		default:
			return fmt.Errorf("security level must be one of authPriv, authNoPriv or noAuthNoPriv")
		}
	}
	return nil
}

func substituteEnvVariables(value string) (string, error) {
	result := os.Expand(value, func(s string) string {
		return os.Getenv(s)
	})
	if result == "" {
		return "", errors.New(value + " environment variable not found")
	}
	return result, nil
}
