package base

import (
	"fmt"
	"net"
)

// ValidateConfig validates the ServerConfig struct after loading.
// Returns a slice of fatal validation error strings (empty = no errors).
// Non-fatal issues are logged as warnings via fmt.Println.
func ValidateConfig() []string {
	var errs []string
	cfg := Cfg

	// DbType
	switch cfg.DbType {
	case "sqlite3", "mysql", "postgres", "mssql":
	default:
		errs = append(errs, fmt.Sprintf("invalid db_type %q: must be one of sqlite3, mysql, postgres, mssql", cfg.DbType))
	}

	// LinkMode
	switch cfg.LinkMode {
	case LinkModeTUN, LinkModeTAP, LinkModeMacvtap, LinkModeIpvtap:
	default:
		errs = append(errs, fmt.Sprintf("invalid link_mode %q: must be one of tun, tap, macvtap, ipvtap", cfg.LinkMode))
	}

	// LogLevel
	switch cfg.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Sprintf("invalid log_level %q: must be one of debug, info, warn, error", cfg.LogLevel))
	}

	// MaxClient
	if cfg.MaxClient <= 0 {
		errs = append(errs, fmt.Sprintf("max_client must be > 0, got %d", cfg.MaxClient))
	}

	// MaxUserClient
	if cfg.MaxUserClient <= 0 {
		errs = append(errs, fmt.Sprintf("max_user_client must be > 0, got %d", cfg.MaxUserClient))
	}

	// Mtu
	if cfg.Mtu < 100 || cfg.Mtu > 9000 {
		errs = append(errs, fmt.Sprintf("mtu must be between 100 and 9000, got %d", cfg.Mtu))
	}

	// IpLease
	if cfg.IpLease <= 0 {
		errs = append(errs, fmt.Sprintf("ip_lease must be > 0, got %d", cfg.IpLease))
	}

	// SessionTimeout
	if cfg.SessionTimeout < 0 {
		errs = append(errs, fmt.Sprintf("session_timeout must be >= 0, got %d", cfg.SessionTimeout))
	}

	// Ipv4CIDR
	if _, _, err := net.ParseCIDR(cfg.Ipv4CIDR); err != nil {
		errs = append(errs, fmt.Sprintf("invalid ipv4_cidr %q: %v", cfg.Ipv4CIDR, err))
	}

	// Ipv4Gateway
	if net.ParseIP(cfg.Ipv4Gateway) == nil {
		errs = append(errs, fmt.Sprintf("invalid ipv4_gateway %q: not a valid IP address", cfg.Ipv4Gateway))
	}

	// Ipv4Start
	if net.ParseIP(cfg.Ipv4Start) == nil {
		errs = append(errs, fmt.Sprintf("invalid ipv4_start %q: not a valid IP address", cfg.Ipv4Start))
	}

	// Ipv4End
	if net.ParseIP(cfg.Ipv4End) == nil {
		errs = append(errs, fmt.Sprintf("invalid ipv4_end %q: not a valid IP address", cfg.Ipv4End))
	}

	// CstpKeepalive
	if cfg.CstpKeepalive <= 0 {
		errs = append(errs, fmt.Sprintf("cstp_keepalive must be > 0, got %d", cfg.CstpKeepalive))
	}

	// CstpDpd
	if cfg.CstpDpd <= 0 {
		errs = append(errs, fmt.Sprintf("cstp_dpd must be > 0, got %d", cfg.CstpDpd))
	}

	return errs
}
