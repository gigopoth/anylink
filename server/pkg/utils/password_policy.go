package utils

import (
	"fmt"
	"unicode"
)

// PasswordPolicyConfig defines the password strength requirements
type PasswordPolicyConfig struct {
	MinLength    int  `json:"min_length"`    // 最小密码长度
	MaxLength    int  `json:"max_length"`    // 最大密码长度
	RequireUpper bool `json:"require_upper"` // 要求包含大写字母
	RequireLower bool `json:"require_lower"` // 要求包含小写字母
	RequireDigit bool `json:"require_digit"` // 要求包含数字
	RequireSpec  bool `json:"require_spec"`  // 要求包含特殊字符
}

// DefaultPasswordPolicy returns the default password policy
func DefaultPasswordPolicy() PasswordPolicyConfig {
	return PasswordPolicyConfig{
		MinLength:    6,
		MaxLength:    64,
		RequireUpper: false,
		RequireLower: false,
		RequireDigit: false,
		RequireSpec:  false,
	}
}

// ValidatePassword checks if a password meets the policy requirements
func ValidatePassword(password string, policy PasswordPolicyConfig) error {
	if policy.MinLength <= 0 {
		policy.MinLength = 6 // absolute minimum
	}
	if policy.MaxLength <= 0 {
		policy.MaxLength = 64
	}

	pl := len(password)
	if pl < policy.MinLength {
		return fmt.Errorf("密码长度不能少于%d个字符", policy.MinLength)
	}
	if pl > policy.MaxLength {
		return fmt.Errorf("密码长度不能超过%d个字符", policy.MaxLength)
	}

	var hasUpper, hasLower, hasDigit, hasSpec bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpec = true
		}
	}

	if policy.RequireUpper && !hasUpper {
		return fmt.Errorf("密码必须包含至少一个大写字母")
	}
	if policy.RequireLower && !hasLower {
		return fmt.Errorf("密码必须包含至少一个小写字母")
	}
	if policy.RequireDigit && !hasDigit {
		return fmt.Errorf("密码必须包含至少一个数字")
	}
	if policy.RequireSpec && !hasSpec {
		return fmt.Errorf("密码必须包含至少一个特殊字符")
	}

	return nil
}
