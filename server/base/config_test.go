package base

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultConfigValues(t *testing.T) {
	assert := assert.New(t)

	// Build a lookup map from the configs slice for easy access by name
	cfgMap := make(map[string]config)
	for _, c := range configs {
		cfgMap[c.Name] = c
	}

	// Verify string defaults
	strDefaults := map[string]string{
		"server_addr": ":443",
		"admin_addr":  ":8800",
		"db_type":     "sqlite3",
		"link_mode":   "tun",
	}
	for name, expected := range strDefaults {
		c, ok := cfgMap[name]
		assert.True(ok, "config %q should exist", name)
		assert.Equal(cfgStr, c.Typ, "config %q should be a string type", name)
		assert.Equal(expected, c.ValStr, "config %q default", name)
	}

	// Verify integer defaults
	intDefaults := map[string]int{
		"max_client":      200,
		"mtu":             1460,
		"session_timeout": 3600,
	}
	for name, expected := range intDefaults {
		c, ok := cfgMap[name]
		assert.True(ok, "config %q should exist", name)
		assert.Equal(cfgInt, c.Typ, "config %q should be an int type", name)
		assert.Equal(expected, c.ValInt, "config %q default", name)
	}

	// Verify boolean defaults
	boolDefaults := map[string]bool{
		"anti_brute_force": true,
	}
	for name, expected := range boolDefaults {
		c, ok := cfgMap[name]
		assert.True(ok, "config %q should exist", name)
		assert.Equal(cfgBool, c.Typ, "config %q should be a bool type", name)
		assert.Equal(expected, c.ValBool, "config %q default", name)
	}
}

func TestConfigEnvMapping(t *testing.T) {
	assert := assert.New(t)

	// The envs map should exist; document current state (currently empty)
	assert.NotNil(envs, "envs map should be initialized")
}

// validTestConfig returns a ServerConfig with all fields set to valid values.
func validTestConfig() *ServerConfig {
	return &ServerConfig{
		DbType:         "sqlite3",
		LinkMode:       "tun",
		LogLevel:       "info",
		MaxClient:      100,
		MaxUserClient:  3,
		Mtu:            1460,
		IpLease:        86400,
		SessionTimeout: 3600,
		Ipv4CIDR:       "192.168.90.0/24",
		Ipv4Gateway:    "192.168.90.1",
		Ipv4Start:      "192.168.90.100",
		Ipv4End:        "192.168.90.200",
		CstpKeepalive:  3,
		CstpDpd:        20,
	}
}

func TestValidateConfig_Valid(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	errs := ValidateConfig()
	assert.Empty(t, errs, "expected no validation errors for a valid config")
}

func TestValidateConfig_InvalidDbType(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.DbType = "oracle"
	errs := ValidateConfig()
	assert.NotEmpty(t, errs, "expected validation errors")
	assert.Contains(t, errs[0], "db_type")
}

func TestValidateConfig_InvalidLinkMode(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.LinkMode = "invalid"
	errs := ValidateConfig()
	assert.NotEmpty(t, errs, "expected validation errors")
	assert.Contains(t, errs[0], "link_mode")
}

func TestValidateConfig_InvalidMTU(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	// MTU too low
	Cfg = validTestConfig()
	Cfg.Mtu = 0
	errs := ValidateConfig()
	assert.NotEmpty(t, errs, "expected validation errors for mtu=0")
	found := false
	for _, e := range errs {
		if strings.Contains(e, "mtu") {
			found = true
		}
	}
	assert.True(t, found, "expected an error mentioning mtu")

	// MTU too high
	Cfg = validTestConfig()
	Cfg.Mtu = 10000
	errs = ValidateConfig()
	assert.NotEmpty(t, errs, "expected validation errors for mtu=10000")
	found = false
	for _, e := range errs {
		if strings.Contains(e, "mtu") {
			found = true
		}
	}
	assert.True(t, found, "expected an error mentioning mtu")
}

func TestValidateConfig_InvalidCIDR(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.Ipv4CIDR = "invalid"
	errs := ValidateConfig()
	assert.NotEmpty(t, errs, "expected validation errors")
	assert.Contains(t, errs[0], "ipv4_cidr")
}

func TestValidateConfig_InvalidIP(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.Ipv4Gateway = "not-an-ip"
	errs := ValidateConfig()
	assert.NotEmpty(t, errs, "expected validation errors")
	assert.Contains(t, errs[0], "ipv4_gateway")
}

func TestEnvMapping_AllConfigsHaveEnvVars(t *testing.T) {
	assert := assert.New(t)

	for _, c := range configs {
		expected := "LINK_" + strings.ToUpper(c.Name)
		actual, ok := envs[c.Name]
		assert.True(ok, "envs map should have entry for config %q", c.Name)
		assert.Equal(expected, actual, "env var for config %q", c.Name)
	}
}

func TestServerConfigStruct(t *testing.T) {
	assert := assert.New(t)

	cfg := &ServerConfig{}

	// Set and read string fields
	cfg.ServerAddr = ":8443"
	cfg.AdminAddr = ":9900"
	cfg.DbType = "mysql"
	cfg.LinkMode = "tap"
	cfg.Ipv4CIDR = "10.10.0.0/16"
	cfg.Ipv4Gateway = "10.10.0.1"

	assert.Equal(":8443", cfg.ServerAddr)
	assert.Equal(":9900", cfg.AdminAddr)
	assert.Equal("mysql", cfg.DbType)
	assert.Equal("tap", cfg.LinkMode)
	assert.Equal("10.10.0.0/16", cfg.Ipv4CIDR)
	assert.Equal("10.10.0.1", cfg.Ipv4Gateway)

	// Set and read integer fields
	cfg.MaxClient = 500
	cfg.Mtu = 1400
	cfg.SessionTimeout = 7200
	cfg.IpLease = 43200
	cfg.MaxUserClient = 5

	assert.Equal(500, cfg.MaxClient)
	assert.Equal(1400, cfg.Mtu)
	assert.Equal(7200, cfg.SessionTimeout)
	assert.Equal(43200, cfg.IpLease)
	assert.Equal(5, cfg.MaxUserClient)

	// Set and read boolean fields
	cfg.AntiBruteForce = false
	cfg.Compression = true
	cfg.DisplayError = true

	assert.False(cfg.AntiBruteForce)
	assert.True(cfg.Compression)
	assert.True(cfg.DisplayError)
}
