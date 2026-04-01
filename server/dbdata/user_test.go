package dbdata

import (
	"testing"
	"time"

	"github.com/bjdgyc/anylink/base"
	"github.com/stretchr/testify/assert"
)

func TestCheckUser(t *testing.T) {
	base.Test()
	ast := assert.New(t)

	preIpData()
	defer closeIpdata()

	group := "group1"

	// 添加一个组
	dns := []ValData{{Val: "114.114.114.114"}}
	route := []ValData{{Val: "192.168.1.0/24"}}
	g := Group{Name: group, Status: 1, ClientDns: dns, RouteInclude: route}
	err := SetGroup(&g)
	ast.Nil(err)
	// 判断 IpMask
	ast.Equal(g.RouteInclude[0].IpMask, "192.168.1.0/255.255.255.0")

	// 添加一个用户
	pincode := "a123456"
	u := User{Username: "aaa", PinCode: pincode, Groups: []string{group}, Status: 1}
	err = SetUser(&u)
	ast.Nil(err)

	// 验证 PinCode + OtpSecret
	// totp := gotp.NewDefaultTOTP(u.OtpSecret)
	// secret := totp.Now()
	// err = CheckUser("aaa", u.PinCode+secret, group)
	// ast.Nil(err)

	// 单独验证密码
	u.DisableOtp = true
	_ = SetUser(&u)
	ext := map[string]any{
		"mac_addr": "",
	}
	err = CheckUser("aaa", pincode, group, ext)
	ast.Nil(err)

	// 添加一个radius组
	group2 := "group2"
	authData := map[string]interface{}{
		"type": "radius",
		"radius": map[string]string{
			"addr":   "192.168.1.12:1044",
			"secret": "43214132",
		},
	}
	g2 := Group{Name: group2, Status: 1, ClientDns: dns, RouteInclude: route, Auth: authData}
	err = SetGroup(&g2)
	ast.Nil(err)
	err = CheckUser("aaa", "bbbbbbb", group2, ext)
	if ast.NotNil(err) {
		ast.Contains(err.Error(), "aaa Radius服务器连接异常")
	}
	// 添加用户策略
	dns2 := []ValData{{Val: "8.8.8.8"}}
	route2 := []ValData{{Val: "192.168.2.0/24"}}
	p1 := Policy{Username: "aaa", Status: 1, ClientDns: dns2, RouteInclude: route2}
	err = SetPolicy(&p1)
	ast.Nil(err)
	err = CheckUser("aaa", pincode, group, ext)
	ast.Nil(err)
	// 添加一个ldap组
	group3 := "group3"
	authData = map[string]interface{}{
		"type": "ldap",
		"ldap": map[string]interface{}{
			"addr":         "192.168.8.12:389",
			"tls":          true,
			"bind_name":    "userfind@abc.com",
			"bind_pwd":     "afdbfdsafds",
			"base_dn":      "dc=abc,dc=com",
			"object_class": "person",
			"search_attr":  "sAMAccountName",
			"member_of":    "cn=vpn,cn=user,dc=abc,dc=com",
		},
	}
	g3 := Group{Name: group3, Status: 1, ClientDns: dns, RouteInclude: route, Auth: authData}
	err = SetGroup(&g3)
	ast.Nil(err)
	err = CheckUser("aaa", "bbbbbbb", group3, ext)
	if ast.NotNil(err) {
		ast.Equal("aaa LDAP服务器连接异常, 请检测服务器和端口", err.Error())
	}
}

func TestCheckUser_NonExistentUser(t *testing.T) {
	base.Test()
	ast := assert.New(t)

	preIpData()
	defer closeIpdata()

	group := "group1"
	dns := []ValData{{Val: "114.114.114.114"}}
	route := []ValData{{Val: "192.168.1.0/24"}}
	err := SetGroup(&Group{Name: group, Status: 1, ClientDns: dns, RouteInclude: route})
	ast.Nil(err)

	ext := map[string]any{"mac_addr": ""}
	err = CheckUser("nonexistent", "a123456", group, ext)
	if ast.NotNil(err) {
		ast.Contains(err.Error(), "用户名或密码错误")
	}
}

func TestCheckUser_DisabledUser(t *testing.T) {
	base.Test()
	ast := assert.New(t)

	preIpData()
	defer closeIpdata()

	group := "group1"
	dns := []ValData{{Val: "114.114.114.114"}}
	route := []ValData{{Val: "192.168.1.0/24"}}
	err := SetGroup(&Group{Name: group, Status: 1, ClientDns: dns, RouteInclude: route})
	ast.Nil(err)

	u := User{Username: "disabled_user", PinCode: "a123456", Groups: []string{group}, Status: 1, DisableOtp: true}
	err = SetUser(&u)
	ast.Nil(err)

	// Disable user
	u.Status = 0
	err = Set(&u)
	ast.Nil(err)

	ext := map[string]any{"mac_addr": ""}
	err = CheckUser("disabled_user", "a123456", group, ext)
	if ast.NotNil(err) {
		ast.Contains(err.Error(), "用户名或密码错误")
	}
}

func TestCheckUser_WrongPassword(t *testing.T) {
	base.Test()
	ast := assert.New(t)

	preIpData()
	defer closeIpdata()

	group := "group1"
	dns := []ValData{{Val: "114.114.114.114"}}
	route := []ValData{{Val: "192.168.1.0/24"}}
	err := SetGroup(&Group{Name: group, Status: 1, ClientDns: dns, RouteInclude: route})
	ast.Nil(err)

	u := User{Username: "wrongpwd_user", PinCode: "a123456", Groups: []string{group}, Status: 1, DisableOtp: true}
	err = SetUser(&u)
	ast.Nil(err)

	ext := map[string]any{"mac_addr": ""}
	err = CheckUser("wrongpwd_user", "wrong_password", group, ext)
	if ast.NotNil(err) {
		ast.Contains(err.Error(), "密码错误")
	}
}

func TestCheckUser_ShortPassword(t *testing.T) {
	base.Test()
	ast := assert.New(t)

	preIpData()
	defer closeIpdata()

	group := "group1"
	dns := []ValData{{Val: "114.114.114.114"}}
	route := []ValData{{Val: "192.168.1.0/24"}}
	err := SetGroup(&Group{Name: group, Status: 1, ClientDns: dns, RouteInclude: route})
	ast.Nil(err)

	u := User{Username: "shortpwd_user", PinCode: "a123456", Groups: []string{group}, Status: 1, DisableOtp: true}
	err = SetUser(&u)
	ast.Nil(err)

	ext := map[string]any{"mac_addr": ""}
	err = CheckUser("shortpwd_user", "abc", group, ext)
	if ast.NotNil(err) {
		ast.Contains(err.Error(), "密码错误")
	}
}

func TestCheckUser_WrongGroup(t *testing.T) {
	base.Test()
	ast := assert.New(t)

	preIpData()
	defer closeIpdata()

	dns := []ValData{{Val: "114.114.114.114"}}
	route := []ValData{{Val: "192.168.1.0/24"}}
	err := SetGroup(&Group{Name: "grpA", Status: 1, ClientDns: dns, RouteInclude: route})
	ast.Nil(err)
	err = SetGroup(&Group{Name: "grpB", Status: 1, ClientDns: dns, RouteInclude: route})
	ast.Nil(err)

	u := User{Username: "grp_user", PinCode: "a123456", Groups: []string{"grpA"}, Status: 1, DisableOtp: true}
	err = SetUser(&u)
	ast.Nil(err)

	ext := map[string]any{"mac_addr": ""}
	err = CheckUser("grp_user", "a123456", "grpB", ext)
	if ast.NotNil(err) {
		ast.Contains(err.Error(), "用户组错误")
	}
}

func TestCheckUser_InvalidGroup(t *testing.T) {
	base.Test()
	ast := assert.New(t)

	preIpData()
	defer closeIpdata()

	dns := []ValData{{Val: "114.114.114.114"}}
	route := []ValData{{Val: "192.168.1.0/24"}}
	err := SetGroup(&Group{Name: "real_group", Status: 1, ClientDns: dns, RouteInclude: route})
	ast.Nil(err)

	u := User{Username: "inv_grp_user", PinCode: "a123456", Groups: []string{"real_group"}, Status: 1, DisableOtp: true}
	err = SetUser(&u)
	ast.Nil(err)

	ext := map[string]any{"mac_addr": ""}
	err = CheckUser("inv_grp_user", "a123456", "no_such_group", ext)
	if ast.NotNil(err) {
		ast.Contains(err.Error(), "用户组错误")
	}
}

func TestCheckUser_PasswordExpiry(t *testing.T) {
	base.Test()
	ast := assert.New(t)

	preIpData()
	defer closeIpdata()

	// Enable encryption so bcrypt passwords are stored (len 60)
	base.Cfg.EncryptionPassword = true
	defer func() { base.Cfg.EncryptionPassword = false }()

	group := "group1"
	dns := []ValData{{Val: "114.114.114.114"}}
	route := []ValData{{Val: "192.168.1.0/24"}}
	err := SetGroup(&Group{Name: group, Status: 1, ClientDns: dns, RouteInclude: route})
	ast.Nil(err)

	pincode := "a123456"
	u := User{Username: "expiry_user", PinCode: pincode, Groups: []string{group}, Status: 1, DisableOtp: true}
	err = SetUser(&u)
	ast.Nil(err)

	// Insert password policy with 30 day max age
	sess := GetXdb().NewSession()
	defer sess.Close()
	err = SettingSessAdd(sess, &SettingPasswordPolicy{PasswordMaxAge: 30, MinLength: 6, MaxLength: 64})
	ast.Nil(err)

	// Set PasswordChangedAt to 2 years ago
	oldTime := time.Now().AddDate(-2, 0, 0)
	u.PasswordChangedAt = &oldTime
	err = Set(&u)
	ast.Nil(err)

	ext := map[string]any{"mac_addr": ""}
	err = CheckUser("expiry_user", pincode, group, ext)
	if ast.NotNil(err) {
		ast.Contains(err.Error(), "密码已过期")
	}
}

func TestCheckUser_PlaintextPasswordMigration(t *testing.T) {
	base.Test()
	ast := assert.New(t)

	preIpData()
	defer closeIpdata()

	// Disable auto-encrypt so plaintext is stored directly
	base.Cfg.EncryptionPassword = false

	group := "group1"
	dns := []ValData{{Val: "114.114.114.114"}}
	route := []ValData{{Val: "192.168.1.0/24"}}
	err := SetGroup(&Group{Name: group, Status: 1, ClientDns: dns, RouteInclude: route})
	ast.Nil(err)

	pincode := "plaintext123"
	u := User{Username: "plain_user", PinCode: pincode, Groups: []string{group}, Status: 1, DisableOtp: true}
	err = SetUser(&u)
	ast.Nil(err)

	// Verify it's stored as plaintext (not 60 chars)
	stored := &User{}
	err = One("Username", "plain_user", stored)
	ast.Nil(err)
	ast.NotEqual(60, len(stored.PinCode))

	ext := map[string]any{"mac_addr": ""}
	err = CheckUser("plain_user", pincode, group, ext)
	ast.Nil(err)

	// After successful login with plaintext, password should be migrated to bcrypt (60 chars)
	migrated := &User{}
	err = One("Username", "plain_user", migrated)
	ast.Nil(err)
	ast.Equal(60, len(migrated.PinCode))
}

func TestIsPasswordExpired(t *testing.T) {
	base.Test()
	ast := assert.New(t)

	preIpData()
	defer closeIpdata()

	// No policy (MaxAge=0) - should never expire
	sess := GetXdb().NewSession()
	defer sess.Close()
	err := SettingSessAdd(sess, &SettingPasswordPolicy{PasswordMaxAge: 0, MinLength: 6, MaxLength: 64})
	ast.Nil(err)

	now := time.Now()
	oldTime := time.Now().AddDate(-2, 0, 0)
	user := &User{PasswordChangedAt: &oldTime, CreatedAt: now}
	ast.False(IsPasswordExpired(user))

	// Set policy with 30 day max age (update existing record)
	err = SettingSet(&SettingPasswordPolicy{PasswordMaxAge: 30, MinLength: 6, MaxLength: 64})
	ast.Nil(err)

	// Not expired - password changed recently
	recentTime := time.Now().Add(-24 * time.Hour)
	user.PasswordChangedAt = &recentTime
	ast.False(IsPasswordExpired(user))

	// Expired - password changed long ago
	user.PasswordChangedAt = &oldTime
	ast.True(IsPasswordExpired(user))

	// Fallback to CreatedAt when PasswordChangedAt is nil
	user.PasswordChangedAt = nil
	user.CreatedAt = time.Now().Add(-24 * time.Hour)
	ast.False(IsPasswordExpired(user))

	user.CreatedAt = time.Now().AddDate(-2, 0, 0)
	ast.True(IsPasswordExpired(user))
}

func TestGenerateRecoveryCodes(t *testing.T) {
	base.Test()
	ast := assert.New(t)

	codes := GenerateRecoveryCodes(5)
	ast.Equal(5, len(codes))
	for _, code := range codes {
		ast.Equal(8, len(code))
	}

	// Different count
	codes2 := GenerateRecoveryCodes(10)
	ast.Equal(10, len(codes2))

	// Zero count
	codes0 := GenerateRecoveryCodes(0)
	ast.Equal(0, len(codes0))
}

func TestVerifyRecoveryCode(t *testing.T) {
	base.Test()
	ast := assert.New(t)

	preIpData()
	defer closeIpdata()

	group := "group1"
	dns := []ValData{{Val: "114.114.114.114"}}
	route := []ValData{{Val: "192.168.1.0/24"}}
	err := SetGroup(&Group{Name: group, Status: 1, ClientDns: dns, RouteInclude: route})
	ast.Nil(err)

	codes := GenerateRecoveryCodes(3)
	u := User{
		Username:         "recovery_user",
		PinCode:          "a123456",
		Groups:           []string{group},
		Status:           1,
		DisableOtp:       true,
		OtpRecoveryCodes: codes,
	}
	err = SetUser(&u)
	ast.Nil(err)

	// Invalid code should be rejected
	ast.False(VerifyRecoveryCode(&u, "invalidx"))

	// Valid code should succeed
	validCode := codes[0]
	ast.True(VerifyRecoveryCode(&u, validCode))

	// Same code cannot be used twice (already consumed)
	ast.False(VerifyRecoveryCode(&u, validCode))

	// Remaining codes still work
	ast.True(VerifyRecoveryCode(&u, codes[1]))
	ast.Equal(1, len(u.OtpRecoveryCodes))
}

func TestSetUser_Validation(t *testing.T) {
	base.Test()
	ast := assert.New(t)

	preIpData()
	defer closeIpdata()

	// Empty username
	u := User{Username: "", PinCode: "a123456", Groups: []string{"group1"}, Status: 1}
	err := SetUser(&u)
	if ast.NotNil(err) {
		ast.Contains(err.Error(), "用户名或组错误")
	}

	// Empty groups
	u2 := User{Username: "testuser", PinCode: "a123456", Groups: []string{}, Status: 1}
	err = SetUser(&u2)
	if ast.NotNil(err) {
		ast.Contains(err.Error(), "用户名或组错误")
	}

	// Invalid group (doesn't exist in DB)
	u3 := User{Username: "testuser", PinCode: "a123456", Groups: []string{"nonexistent_group"}, Status: 1}
	err = SetUser(&u3)
	if ast.NotNil(err) {
		ast.Contains(err.Error(), "用户名或组错误")
	}

	// Valid creation
	dns := []ValData{{Val: "114.114.114.114"}}
	route := []ValData{{Val: "192.168.1.0/24"}}
	err = SetGroup(&Group{Name: "valid_group", Status: 1, ClientDns: dns, RouteInclude: route})
	ast.Nil(err)

	u4 := User{Username: "valid_user", PinCode: "a123456", Groups: []string{"valid_group"}, Status: 1}
	err = SetUser(&u4)
	ast.Nil(err)
	ast.NotEmpty(u4.OtpSecret)
	ast.True(u4.Id > 0)
}
