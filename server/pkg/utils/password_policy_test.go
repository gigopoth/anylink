package utils

import (
	"testing"
)

func TestValidatePassword(t *testing.T) {
	policy := PasswordPolicyConfig{
		MinLength:    8,
		MaxLength:    64,
		RequireUpper: true,
		RequireLower: true,
		RequireDigit: true,
		RequireSpec:  true,
	}

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"too short", "Aa1!", false},
		{"too short really", "Ab1!", true},
		{"no upper", "abcdefg1!", true},
		{"no lower", "ABCDEFG1!", true},
		{"no digit", "Abcdefg!x", true},
		{"no special", "Abcdefg1x", true},
		{"valid", "Abcdefg1!", false},
		{"valid complex", "MyP@ssw0rd!", false},
	}

	// Fix: too short cases
	tests[0].password = "Aa1!"
	tests[0].wantErr = true // less than 8

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password, policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePassword(%q) error = %v, wantErr %v", tt.password, err, tt.wantErr)
			}
		})
	}

	// Test with relaxed policy
	relaxed := PasswordPolicyConfig{
		MinLength: 6,
	}
	err := ValidatePassword("simple", relaxed)
	if err != nil {
		t.Errorf("Relaxed policy should accept 'simple': %v", err)
	}

	// Test max length
	maxPolicy := PasswordPolicyConfig{
		MinLength: 1,
		MaxLength: 5,
	}
	err = ValidatePassword("toolongpassword", maxPolicy)
	if err == nil {
		t.Error("Should reject password exceeding max length")
	}
}
