package dbdata

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bjdgyc/anylink/base"
	"github.com/bjdgyc/anylink/pkg/utils"
	"github.com/xlzd/gotp"
)

// type User struct {
// 	Id       int    `json:"id"  xorm:"pk autoincr not null"`
// 	Username string `json:"username" storm:"not null unique"`
// 	Nickname string `json:"nickname"`
// 	Email    string `json:"email"`
// 	// Password  string    `json:"password"`
// 	PinCode    string    `json:"pin_code"`
// 	OtpSecret  string    `json:"otp_secret"`
// 	DisableOtp bool      `json:"disable_otp"` // 禁用otp
// 	Groups     []string  `json:"groups"`
// 	Status     int8      `json:"status"` // 1正常
// 	SendEmail  bool      `json:"send_email"`
// 	CreatedAt  time.Time `json:"created_at"`
// 	UpdatedAt  time.Time `json:"updated_at"`
// }

func SetUser(v *User) error {
	var err error
	if v.Username == "" || len(v.Groups) == 0 {
		return errors.New("用户名或组错误")
	}

	planPass := v.PinCode
	// 自动生成密码
	if len(planPass) < 6 {
		planPass = utils.RandomRunes(8)
	} else {
		// 验证密码强度策略
		policy := GetPasswordPolicy()
		policyConfig := utils.PasswordPolicyConfig{
			MinLength:    policy.MinLength,
			MaxLength:    policy.MaxLength,
			RequireUpper: policy.RequireUpper,
			RequireLower: policy.RequireLower,
			RequireDigit: policy.RequireDigit,
			RequireSpec:  policy.RequireSpec,
		}
		if err := utils.ValidatePassword(planPass, policyConfig); err != nil {
			return fmt.Errorf("密码强度不符合要求: %v", err)
		}
	}
	v.PinCode = planPass

	if v.OtpSecret == "" {
		v.OtpSecret = gotp.RandomSecret(32)
	}

	// 判断组是否有效
	ng := []string{}
	groups := GetGroupNames()
	for _, g := range v.Groups {
		if utils.InArrStr(groups, g) {
			ng = append(ng, g)
		}
	}
	if len(ng) == 0 {
		return errors.New("用户名或组错误")
	}
	v.Groups = ng

	v.UpdatedAt = time.Now()
	if v.Id > 0 {
		err = Set(v)
	} else {
		err = Add(v)
	}

	return err
}

// 验证用户登录信息
func CheckUser(name, pwd, group string, ext map[string]interface{}) error {
	base.Trace("CheckUser", name, pwd, group, ext)

	// 获取登入的group数据
	groupData := &Group{}
	err := One("Name", group, groupData)
	if err != nil || groupData.Status != 1 {
		return fmt.Errorf("%s - %s", name, "用户组错误")
	}
	// 初始化Auth
	if len(groupData.Auth) == 0 {
		groupData.Auth["type"] = "local"
	}
	authType := groupData.Auth["type"].(string)
	// 本地认证方式
	if authType == "local" {
		return checkLocalUser(name, pwd, group, ext)
	}
	// 其它认证方式, 支持自定义
	_, ok := authRegistry[authType]
	if !ok {
		return fmt.Errorf("%s %s", "未知的认证方式: ", authType)
	}
	auth := makeInstance(authType).(IUserAuth)
	return auth.checkUser(name, pwd, groupData, ext)
}

// 验证本地用户登录信息
func checkLocalUser(name, pwd, group string, ext map[string]interface{}) error {
	pl := len(pwd)
	if name == "" || pl < 6 {
		return fmt.Errorf("%s %s", name, "密码错误")
	}
	v := &User{}
	err := One("Username", name, v)
	if err != nil || v.Status != 1 {
		// 内部日志记录详细原因
		switch v.Status {
		case 0:
			base.Warn(name, "用户不存在或用户已停用")
		case 2:
			base.Warn(name, "用户已过期")
		}
		// 对外统一返回通用错误信息，防止用户名枚举
		return fmt.Errorf("%s %s", name, "用户名或密码错误")
	}
	// 判断用户组信息
	if !utils.InArrStr(v.Groups, group) {
		return fmt.Errorf("%s %s", name, "用户组错误")
	}

	pinCode := pwd
	if !base.Cfg.AuthAloneOtp {
		// 判断otp信息
		if !v.DisableOtp {
			pinCode = pwd[:pl-6]
			otp := pwd[pl-6:]
			// First try regular OTP, then try recovery code
			if !CheckOtp(name, otp, v.OtpSecret) {
				// Try recovery code (8 chars instead of 6-digit OTP)
				if len(pwd) > 8 {
					pinCode = pwd[:pl-8]
					recoveryCode := pwd[pl-8:]
					if !VerifyRecoveryCode(v, recoveryCode) {
						return fmt.Errorf("%s %s", name, "动态码错误")
					}
					base.Info("用户", name, "使用了恢复码登录")
				} else {
					return fmt.Errorf("%s %s", name, "动态码错误")
				}
			}
		}
	}

	// 判断用户密码
	// 兼容明文密码
	if len(v.PinCode) != 60 {
		if pinCode != v.PinCode {
			return fmt.Errorf("%s %s", name, "密码错误")
		}
		// 明文密码验证通过后，自动迁移为 bcrypt 存储
		if hashedPwd, err := utils.PasswordHash(pinCode); err == nil {
			v.PinCode = hashedPwd
			if err := Set(v); err != nil {
				base.Error("自动迁移密码失败:", name, err)
			} else {
				base.Info("密码已自动迁移至bcrypt:", name)
			}
		}
		return nil
	}
	// 密文密码
	if !utils.PasswordVerify(pinCode, v.PinCode) {
		return fmt.Errorf("%s %s", name, "密码错误")
	}

	// Check password expiry
	if IsPasswordExpired(v) {
		return fmt.Errorf("%s %s", name, "密码已过期，请通过用户门户修改密码")
	}

	return nil
}

// 用户过期时间到达后，更新用户状态，并返回一个状态为过期的用户切片
func CheckUserlimittime() (limitUser []interface{}) {
	if _, err := xdb.Where("limittime <= ?", time.Now()).And("status = ?", 1).Update(&User{Status: 2}); err != nil {
		return
	}
	user := make(map[int64]User)
	if err := xdb.Where("status != ?", 1).Find(user); err != nil {
		return
	}
	for _, v := range user {
		limitUser = append(limitUser, v.Username)
	}
	return
}

var (
	userOtpMux = sync.Mutex{}
	userOtp    = map[string]time.Time{}
)

func init() {
	go func() {
		expire := time.Second * 60

		for range time.Tick(time.Second * 10) {
			tnow := time.Now()
			userOtpMux.Lock()
			for k, v := range userOtp {
				if tnow.After(v.Add(expire)) {
					delete(userOtp, k)
				}
			}
			userOtpMux.Unlock()
		}
	}()
}

// 判断令牌信息
func CheckOtp(name, otp, secret string) bool {
	key := fmt.Sprintf("%s:%s", name, otp)

	userOtpMux.Lock()
	defer userOtpMux.Unlock()

	// 令牌只能使用一次
	if _, ok := userOtp[key]; ok {
		// 已经存在
		return false
	}

	// 防止无界增长，超过上限时拒绝新的 OTP 验证
	const maxOtpEntries = 10000
	if len(userOtp) >= maxOtpEntries {
		return false
	}
	userOtp[key] = time.Now()

	totp := gotp.NewDefaultTOTP(secret)
	unix := time.Now().Unix()
	verify := totp.Verify(otp, unix)

	return verify
}

// 插入数据库前加密密码
func (u *User) BeforeInsert() {
	if base.Cfg.EncryptionPassword {
		hashedPassword, err := utils.PasswordHash(u.PinCode)
		if err != nil {
			base.Error(err)
		}
		u.PinCode = hashedPassword
	}
}

// 更新数据库前加密密码
func (u *User) BeforeUpdate() {
	if len(u.PinCode) != 60 && base.Cfg.EncryptionPassword {
		hashedPassword, err := utils.PasswordHash(u.PinCode)
		if err != nil {
			base.Error(err)
		}
		u.PinCode = hashedPassword
	}
}

// GenerateRecoveryCodes generates a set of one-time backup recovery codes for OTP
func GenerateRecoveryCodes(count int) []string {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		codes[i] = utils.RandomRunes(8)
	}
	return codes
}

// VerifyRecoveryCode checks a recovery code and removes it if valid (one-time use)
func VerifyRecoveryCode(user *User, code string) bool {
	for i, c := range user.OtpRecoveryCodes {
		if c == code {
			// Remove the used code
			user.OtpRecoveryCodes = append(user.OtpRecoveryCodes[:i], user.OtpRecoveryCodes[i+1:]...)
			user.UpdatedAt = time.Now()
			if err := Set(user); err != nil {
				base.Error("移除已使用的恢复码失败:", err)
			}
			return true
		}
	}
	return false
}

// IsPasswordExpired checks if the user's password has exceeded the max age
func IsPasswordExpired(user *User) bool {
	policy := GetPasswordPolicy()
	if policy.PasswordMaxAge <= 0 {
		return false
	}
	if user.PasswordChangedAt == nil {
		// If no password change record, treat as expired to force change
		return true
	}
	maxAge := time.Duration(policy.PasswordMaxAge) * 24 * time.Hour
	return time.Since(*user.PasswordChangedAt) > maxAge
}
