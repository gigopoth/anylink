package base

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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

// ===================== Logging tests =====================

func setupLogging() {
	origCfg := *Cfg
	Cfg.LogPath = ""
	Cfg.LogLevel = "debug"
	initLog()
	_ = origCfg // keep reference for documentation
}

func TestInitLogAndGetters(t *testing.T) {
	assert := assert.New(t)

	origCfg := *Cfg
	defer func() { *Cfg = origCfg }()

	Cfg.LogPath = ""
	Cfg.LogLevel = "debug"
	initLog()

	assert.NotNil(GetBaseLw(), "GetBaseLw should return non-nil after initLog")
	assert.NotNil(GetServerLog(), "GetServerLog should return non-nil after initLog")
	assert.Equal(LogLevelDebug, GetLogLevel(), "log level should be debug")
}

func TestGetLogLevel_Info(t *testing.T) {
	origCfg := *Cfg
	defer func() { *Cfg = origCfg }()

	Cfg.LogPath = ""
	Cfg.LogLevel = "info"
	initLog()

	assert.Equal(t, LogLevelInfo, GetLogLevel())
}

func TestGetLogLevel_Warn(t *testing.T) {
	origCfg := *Cfg
	defer func() { *Cfg = origCfg }()

	Cfg.LogPath = ""
	Cfg.LogLevel = "warn"
	initLog()

	assert.Equal(t, LogLevelWarn, GetLogLevel())
}

func TestGetLogLevel_Error(t *testing.T) {
	origCfg := *Cfg
	defer func() { *Cfg = origCfg }()

	Cfg.LogPath = ""
	Cfg.LogLevel = "error"
	initLog()

	assert.Equal(t, LogLevelError, GetLogLevel())
}

func TestGetLogLevel_Trace(t *testing.T) {
	origCfg := *Cfg
	defer func() { *Cfg = origCfg }()

	Cfg.LogPath = ""
	Cfg.LogLevel = "trace"
	initLog()

	assert.Equal(t, LogLevelTrace, GetLogLevel())
}

func TestGetLogLevel_Fatal(t *testing.T) {
	origCfg := *Cfg
	defer func() { *Cfg = origCfg }()

	Cfg.LogPath = ""
	Cfg.LogLevel = "fatal"
	initLog()

	assert.Equal(t, LogLevelFatal, GetLogLevel())
}

func TestGetLogLevel_Unknown(t *testing.T) {
	origCfg := *Cfg
	defer func() { *Cfg = origCfg }()

	Cfg.LogPath = ""
	Cfg.LogLevel = "unknown_level"
	initLog()

	// Unknown levels default to Info
	assert.Equal(t, LogLevelInfo, GetLogLevel())
}

func TestLogLevel2Int(t *testing.T) {
	assert := assert.New(t)

	assert.Equal(LogLevelTrace, logLevel2Int("trace"))
	assert.Equal(LogLevelDebug, logLevel2Int("debug"))
	assert.Equal(LogLevelInfo, logLevel2Int("info"))
	assert.Equal(LogLevelWarn, logLevel2Int("warn"))
	assert.Equal(LogLevelError, logLevel2Int("error"))
	assert.Equal(LogLevelFatal, logLevel2Int("fatal"))

	// Case insensitive
	assert.Equal(LogLevelDebug, logLevel2Int("Debug"))
	assert.Equal(LogLevelInfo, logLevel2Int("INFO"))

	// Unknown defaults to Info
	assert.Equal(LogLevelInfo, logLevel2Int("bogus"))
	assert.Equal(LogLevelInfo, logLevel2Int(""))
}

func TestLogFunctionsDoNotPanic(t *testing.T) {
	origCfg := *Cfg
	defer func() { *Cfg = origCfg }()

	Cfg.LogPath = ""
	Cfg.LogLevel = "trace"
	initLog()

	assert.NotPanics(t, func() { Trace("trace msg") })
	assert.NotPanics(t, func() { Debug("debug msg") })
	assert.NotPanics(t, func() { Info("info msg") })
	assert.NotPanics(t, func() { Warn("warn msg") })
	assert.NotPanics(t, func() { Error("error msg") })
}

func TestLogFunctionsFiltered(t *testing.T) {
	origCfg := *Cfg
	defer func() { *Cfg = origCfg }()

	// Set level to Error so Trace/Debug/Info/Warn are filtered
	Cfg.LogPath = ""
	Cfg.LogLevel = "error"
	initLog()

	assert.NotPanics(t, func() { Trace("filtered") })
	assert.NotPanics(t, func() { Debug("filtered") })
	assert.NotPanics(t, func() { Info("filtered") })
	assert.NotPanics(t, func() { Warn("filtered") })
	assert.NotPanics(t, func() { Error("not filtered") })
}

func TestLogLevelConstants(t *testing.T) {
	assert := assert.New(t)

	assert.Equal(0, LogLevelTrace)
	assert.Equal(1, LogLevelDebug)
	assert.Equal(2, LogLevelInfo)
	assert.Equal(3, LogLevelWarn)
	assert.Equal(4, LogLevelError)
	assert.Equal(5, LogLevelFatal)
}

// ===================== logWriter tests =====================

func TestLogWriter_Stdout(t *testing.T) {
	lw := &logWriter{
		UseStdout: true,
		NowDate:   time.Now().Format("2006-01-02"),
	}
	lw.newFile()

	assert.Equal(t, os.Stdout, lw.File, "newFile with UseStdout should set File to os.Stdout")

	n, err := lw.Write([]byte("test log line\n"))
	assert.NoError(t, err)
	assert.Greater(t, n, 0)
}

func TestLogWriter_File(t *testing.T) {
	logFile := filepath.Join(".", "test_log_writer.log")
	defer os.Remove(logFile)

	lw := &logWriter{
		UseStdout: false,
		FileName:  logFile,
	}
	lw.newFile()
	defer lw.File.Close()

	assert.NotNil(t, lw.File)
	assert.NotEqual(t, os.Stdout, lw.File)

	n, err := lw.Write([]byte("file log line\n"))
	assert.NoError(t, err)
	assert.Greater(t, n, 0)

	// Verify content was written
	data, err := os.ReadFile(logFile)
	assert.NoError(t, err)
	assert.Contains(t, string(data), "file log line")
}

// ===================== sLogWriter tests =====================

func TestSLogWriter_Disabled(t *testing.T) {
	origCfg := *Cfg
	defer func() { *Cfg = origCfg }()

	Cfg.HttpServerLog = false
	w := &sLogWriter{}
	n, err := w.Write([]byte("should be discarded"))
	assert.NoError(t, err)
	assert.Equal(t, 0, n, "when HttpServerLog is false, Write should return 0")
}

func TestSLogWriter_Enabled(t *testing.T) {
	origCfg := *Cfg
	defer func() { *Cfg = origCfg }()

	Cfg.HttpServerLog = true
	w := &sLogWriter{}
	n, err := w.Write([]byte("server log\n"))
	assert.NoError(t, err)
	assert.Greater(t, n, 0)
}

// ===================== ServerCfg2Slice tests =====================

func TestServerCfg2Slice_NonEmpty(t *testing.T) {
	assert := assert.New(t)

	result := ServerCfg2Slice()
	assert.NotEmpty(result, "ServerCfg2Slice should return a non-empty slice")
}

func TestServerCfg2Slice_FieldCount(t *testing.T) {
	result := ServerCfg2Slice()

	numFields := reflect.TypeOf(ServerConfig{}).NumField()
	assert.Equal(t, numFields, len(result),
		"ServerCfg2Slice length should match number of ServerConfig fields")
}

func TestServerCfg2Slice_EntriesPopulated(t *testing.T) {
	assert := assert.New(t)

	result := ServerCfg2Slice()
	for i, s := range result {
		assert.NotEmpty(s.Name, "entry %d should have non-empty Name", i)
	}

	// At least some entries should have Env set (those in configs)
	envCount := 0
	for _, s := range result {
		if s.Env != "" {
			envCount++
		}
	}
	assert.Greater(envCount, 0, "some entries should have Env populated")
}

func TestServerCfg2Slice_KnownFields(t *testing.T) {
	assert := assert.New(t)

	result := ServerCfg2Slice()
	nameMap := make(map[string]SCfg)
	for _, s := range result {
		nameMap[s.Name] = s
	}

	// Check a few known fields exist
	for _, name := range []string{"server_addr", "admin_addr", "db_type", "max_client", "mtu", "link_mode"} {
		s, ok := nameMap[name]
		assert.True(ok, "should contain field %q", name)
		if ok {
			assert.NotEmpty(s.Name)
		}
	}
}

// ===================== getAbsPath tests =====================

func TestGetAbsPath_EmptyCfile(t *testing.T) {
	result := getAbsPath("/some/base", "")
	assert.Equal(t, "", result, "empty cfile should return empty string")
}

func TestGetAbsPath_AbsolutePath(t *testing.T) {
	result := getAbsPath("/some/base", "/absolute/path/file.txt")
	assert.Equal(t, "/absolute/path/file.txt", result, "absolute cfile should be returned as-is")
}

func TestGetAbsPath_RelativePath(t *testing.T) {
	result := getAbsPath("/some/base", "relative/file.txt")
	expected := filepath.Join("/some/base", "relative/file.txt")
	assert.Equal(t, expected, result, "relative cfile should be joined with base")
}

func TestGetAbsPath_DotRelative(t *testing.T) {
	result := getAbsPath("/base", "./conf/server.toml")
	expected := filepath.Join("/base", "./conf/server.toml")
	assert.Equal(t, expected, result)
}

func TestGetAbsPath_EmptyBase(t *testing.T) {
	result := getAbsPath("", "file.txt")
	assert.Equal(t, "file.txt", result)
}

// ===================== ValidateConfig edge cases =====================

func TestValidateConfig_MaxClientZero(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.MaxClient = 0
	errs := ValidateConfig()
	assert.NotEmpty(t, errs)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "max_client") {
			found = true
		}
	}
	assert.True(t, found, "expected error mentioning max_client")
}

func TestValidateConfig_MaxClientNegative(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.MaxClient = -5
	errs := ValidateConfig()
	assert.NotEmpty(t, errs)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "max_client") {
			found = true
		}
	}
	assert.True(t, found)
}

func TestValidateConfig_MaxUserClientZero(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.MaxUserClient = 0
	errs := ValidateConfig()
	assert.NotEmpty(t, errs)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "max_user_client") {
			found = true
		}
	}
	assert.True(t, found)
}

func TestValidateConfig_MaxUserClientNegative(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.MaxUserClient = -1
	errs := ValidateConfig()
	assert.NotEmpty(t, errs)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "max_user_client") {
			found = true
		}
	}
	assert.True(t, found)
}

func TestValidateConfig_IpLeaseZero(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.IpLease = 0
	errs := ValidateConfig()
	assert.NotEmpty(t, errs)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "ip_lease") {
			found = true
		}
	}
	assert.True(t, found)
}

func TestValidateConfig_IpLeaseNegative(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.IpLease = -100
	errs := ValidateConfig()
	assert.NotEmpty(t, errs)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "ip_lease") {
			found = true
		}
	}
	assert.True(t, found)
}

func TestValidateConfig_SessionTimeoutNegative(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.SessionTimeout = -1
	errs := ValidateConfig()
	assert.NotEmpty(t, errs)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "session_timeout") {
			found = true
		}
	}
	assert.True(t, found)
}

func TestValidateConfig_SessionTimeoutZero(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.SessionTimeout = 0
	errs := ValidateConfig()
	// 0 is valid (>= 0)
	for _, e := range errs {
		assert.NotContains(t, e, "session_timeout")
	}
}

func TestValidateConfig_CstpKeepaliveZero(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.CstpKeepalive = 0
	errs := ValidateConfig()
	assert.NotEmpty(t, errs)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "cstp_keepalive") {
			found = true
		}
	}
	assert.True(t, found)
}

func TestValidateConfig_CstpKeepaliveNegative(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.CstpKeepalive = -10
	errs := ValidateConfig()
	assert.NotEmpty(t, errs)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "cstp_keepalive") {
			found = true
		}
	}
	assert.True(t, found)
}

func TestValidateConfig_CstpDpdZero(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.CstpDpd = 0
	errs := ValidateConfig()
	assert.NotEmpty(t, errs)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "cstp_dpd") {
			found = true
		}
	}
	assert.True(t, found)
}

func TestValidateConfig_CstpDpdNegative(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.CstpDpd = -5
	errs := ValidateConfig()
	assert.NotEmpty(t, errs)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "cstp_dpd") {
			found = true
		}
	}
	assert.True(t, found)
}

func TestValidateConfig_InvalidLogLevel(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.LogLevel = "verbose"
	errs := ValidateConfig()
	assert.NotEmpty(t, errs)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "log_level") {
			found = true
		}
	}
	assert.True(t, found)
}

func TestValidateConfig_MultipleErrors(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.MaxClient = 0
	Cfg.MaxUserClient = 0
	Cfg.IpLease = -1
	Cfg.CstpKeepalive = 0
	Cfg.CstpDpd = 0
	Cfg.Mtu = 50
	Cfg.LogLevel = "invalid"
	Cfg.DbType = "oracle"
	Cfg.LinkMode = "bad"

	errs := ValidateConfig()
	assert.GreaterOrEqual(t, len(errs), 7, "expected at least 7 validation errors")
}

func TestValidateConfig_InvalidIpv4Start(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.Ipv4Start = "not-an-ip"
	errs := ValidateConfig()
	assert.NotEmpty(t, errs)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "ipv4_start") {
			found = true
		}
	}
	assert.True(t, found)
}

func TestValidateConfig_InvalidIpv4End(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.Ipv4End = "not-an-ip"
	errs := ValidateConfig()
	assert.NotEmpty(t, errs)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "ipv4_end") {
			found = true
		}
	}
	assert.True(t, found)
}

// ===================== getUsageEnv tests =====================

func TestGetUsageEnv_KnownField(t *testing.T) {
	assert := assert.New(t)

	usage, env, val := getUsageEnv("server_addr")
	assert.NotEmpty(usage, "usage should be populated for known config")
	assert.NotEmpty(env, "env should be populated for known config")
	assert.Equal(":443", val, "default value for server_addr")
}

func TestGetUsageEnv_UnknownField(t *testing.T) {
	usage, env, val := getUsageEnv("nonexistent_field")
	assert.Empty(t, usage)
	assert.Empty(t, env)
	assert.Nil(t, val)
}

func TestGetUsageEnv_IntField(t *testing.T) {
	_, _, val := getUsageEnv("max_client")
	assert.Equal(t, 200, val)
}

func TestGetUsageEnv_BoolField(t *testing.T) {
	_, _, val := getUsageEnv("anti_brute_force")
	assert.Equal(t, true, val)
}

// ===================== initServerCfg tests =====================

func TestInitServerCfg_DefaultPassword(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.AdminPass = defaultPwd
	Cfg.JwtSecret = "custom_jwt_secret"
	Cfg.AdvertiseDTLSAddr = ""
	Cfg.ServerDTLSAddr = ":4443"

	initServerCfg()

	// Password should have been changed from the default
	assert.NotEqual(t, defaultPwd, Cfg.AdminPass)
	// AdvertiseDTLSAddr should be set to ServerDTLSAddr when empty
	assert.Equal(t, ":4443", Cfg.AdvertiseDTLSAddr)
}

func TestInitServerCfg_DefaultJwt(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.AdminPass = "already_hashed_pass"
	Cfg.JwtSecret = defaultJwt

	initServerCfg()

	// JwtSecret should have been changed from the default
	assert.NotEqual(t, defaultJwt, Cfg.JwtSecret)
}

func TestInitServerCfg_CustomValues(t *testing.T) {
	origCfg := Cfg
	defer func() { Cfg = origCfg }()

	Cfg = validTestConfig()
	Cfg.AdminPass = "custom_pass"
	Cfg.JwtSecret = "custom_jwt"
	Cfg.AdvertiseDTLSAddr = ":5555"

	initServerCfg()

	// Nothing should change for custom values
	assert.Equal(t, "custom_pass", Cfg.AdminPass)
	assert.Equal(t, "custom_jwt", Cfg.JwtSecret)
	assert.Equal(t, ":5555", Cfg.AdvertiseDTLSAddr)
}

// ===================== printVersion test =====================

func TestPrintVersion(t *testing.T) {
	assert.NotPanics(t, func() { printVersion() })
}

// ===================== logWriter rotation test =====================

func TestLogWriter_FileRotation(t *testing.T) {
	// Test the date rotation path in logWriter.Write when UseStdout=true
	logFile := filepath.Join(".", "test_rotation.log")
	rotatedFile := logFile + ".2020-01-01"
	defer os.Remove(logFile)
	defer os.Remove(rotatedFile)

	// Create initial file
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	assert.NoError(t, err)
	f.Write([]byte("old data\n"))

	lw := &logWriter{
		UseStdout: true,
		FileName:  logFile,
		File:      f,
		NowDate:   "2020-01-01", // Past date triggers rotation
	}

	// Write triggers rotation: closes old file, renames it, opens new via newFile()
	// Since UseStdout=true, newFile sets File=os.Stdout
	n, err := lw.Write([]byte("after rotation\n"))
	assert.NoError(t, err)
	assert.Greater(t, n, 0)

	// Date should now be updated
	today := time.Now().Format("2006-01-02")
	assert.Equal(t, today, lw.NowDate)
}

// ===================== Test() function =====================

func TestTestFunction(t *testing.T) {
	origCfg := *Cfg
	defer func() { *Cfg = origCfg }()

	Cfg.LogPath = ""
	Cfg.LogLevel = "info"

	assert.NotPanics(t, func() { Test() })
}

// ===================== App version constants =====================

func TestAppVersionConstants(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("AnyLink", APP_NAME)
	assert.NotEmpty(APP_VER)
}

// ===================== LinkMode constants =====================

func TestLinkModeConstants(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("tun", LinkModeTUN)
	assert.Equal("tap", LinkModeTAP)
	assert.Equal("macvtap", LinkModeMacvtap)
	assert.Equal("ipvtap", LinkModeIpvtap)
}
