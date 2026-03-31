package base

import (
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
