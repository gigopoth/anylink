package admin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/bjdgyc/anylink/base"
	"github.com/bjdgyc/anylink/dbdata"
	"github.com/bjdgyc/anylink/pkg/utils"
	"github.com/bjdgyc/anylink/sessdata"
)

// User portal: self-service API for VPN end users (separate from admin)

const (
	userJwtExpiry = 3600 * 8 // 8 hours
)

// UserPortalLogin authenticates a VPN user and returns a user-scoped JWT
func UserPortalLogin(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	defer r.Body.Close()

	var loginReq struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Group    string `json:"group"`
	}
	if err := json.Unmarshal(body, &loginReq); err != nil {
		RespError(w, RespParamErr, "请求格式错误")
		return
	}

	if loginReq.Username == "" || loginReq.Password == "" {
		RespError(w, RespUserOrPassErr)
		return
	}

	// Check brute force lock
	lm := GetLockManager()
	if !lm.CheckLocked(loginReq.Username, r.RemoteAddr) {
		w.WriteHeader(http.StatusTooManyRequests)
		RespError(w, RespInternalErr, "登录尝试次数过多，请稍后再试")
		return
	}

	// Verify user exists and get their info
	user := &dbdata.User{}
	err = dbdata.One("Username", loginReq.Username, user)
	if err != nil || user.Status != 1 {
		lm.UpdateLoginStatus(loginReq.Username, r.RemoteAddr, false)
		RespError(w, RespUserOrPassErr)
		return
	}

	// Verify password (without OTP - portal uses separate flow)
	pinCode := loginReq.Password
	if len(user.PinCode) != 60 {
		// Legacy plaintext
		if pinCode != user.PinCode {
			lm.UpdateLoginStatus(loginReq.Username, r.RemoteAddr, false)
			RespError(w, RespUserOrPassErr)
			return
		}
	} else {
		if !utils.PasswordVerify(pinCode, user.PinCode) {
			lm.UpdateLoginStatus(loginReq.Username, r.RemoteAddr, false)
			RespError(w, RespUserOrPassErr)
			return
		}
	}

	lm.UpdateLoginStatus(loginReq.Username, r.RemoteAddr, true)

	// Generate user-scoped JWT
	expiresAt := time.Now().Unix() + userJwtExpiry
	jwtData := map[string]interface{}{
		"portal_user": user.Username,
		"user_id":     user.Id,
	}
	tokenString, err := SetJwtData(jwtData, expiresAt)
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}

	data := map[string]interface{}{
		"token":      tokenString,
		"username":   user.Username,
		"expires_at": expiresAt,
	}
	RespSucess(w, data)
}

// UserPortalProfile returns the authenticated user's own profile
func UserPortalProfile(w http.ResponseWriter, r *http.Request) {
	username := getUsernameFromCtx(r)
	if username == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	user := &dbdata.User{}
	err := dbdata.One("Username", username, user)
	if err != nil {
		RespError(w, RespInternalErr, "用户不存在")
		return
	}

	// Return safe profile (no password hash, no OTP secret)
	profile := map[string]interface{}{
		"id":         user.Id,
		"username":   user.Username,
		"nickname":   user.Nickname,
		"email":      user.Email,
		"groups":     user.Groups,
		"status":     user.Status,
		"limittime":  user.LimitTime,
		"disable_otp": user.DisableOtp,
		"created_at": user.CreatedAt,
		"updated_at": user.UpdatedAt,
	}
	RespSucess(w, profile)
}

// UserPortalChangePassword allows the user to change their own password
func UserPortalChangePassword(w http.ResponseWriter, r *http.Request) {
	username := getUsernameFromCtx(r)
	if username == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	defer r.Body.Close()

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		RespError(w, RespParamErr, "请求格式错误")
		return
	}

	if req.OldPassword == "" || req.NewPassword == "" {
		RespError(w, RespParamErr, "旧密码和新密码不能为空")
		return
	}

	user := &dbdata.User{}
	err = dbdata.One("Username", username, user)
	if err != nil {
		RespError(w, RespInternalErr, "用户不存在")
		return
	}

	// Verify old password
	if len(user.PinCode) != 60 {
		if req.OldPassword != user.PinCode {
			RespError(w, RespUserOrPassErr, "旧密码错误")
			return
		}
	} else {
		if !utils.PasswordVerify(req.OldPassword, user.PinCode) {
			RespError(w, RespUserOrPassErr, "旧密码错误")
			return
		}
	}

	// Validate new password against policy
	policy := dbdata.GetPasswordPolicy()
	policyConfig := utils.PasswordPolicyConfig{
		MinLength:    policy.MinLength,
		MaxLength:    policy.MaxLength,
		RequireUpper: policy.RequireUpper,
		RequireLower: policy.RequireLower,
		RequireDigit: policy.RequireDigit,
		RequireSpec:  policy.RequireSpec,
	}
	if err := utils.ValidatePassword(req.NewPassword, policyConfig); err != nil {
		RespError(w, RespParamErr, fmt.Sprintf("密码强度不符合要求: %v", err))
		return
	}

	// Hash and save new password
	if base.Cfg.EncryptionPassword {
		hashedPwd, err := utils.PasswordHash(req.NewPassword)
		if err != nil {
			RespError(w, RespInternalErr, "密码加密失败")
			return
		}
		user.PinCode = hashedPwd
	} else {
		user.PinCode = req.NewPassword
	}
	user.UpdatedAt = time.Now()
	if err := dbdata.Set(user); err != nil {
		RespError(w, RespInternalErr, "密码修改失败")
		return
	}

	RespSucess(w, "密码修改成功")
}

// UserPortalLoginHistory returns the user's own login history
func UserPortalLoginHistory(w http.ResponseWriter, r *http.Request) {
	username := getUsernameFromCtx(r)
	if username == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	_ = r.ParseForm()
	pageS := r.FormValue("page")
	page, _ := strconv.Atoi(pageS)
	if page < 1 {
		page = 1
	}

	pageSize := dbdata.PageSize
	where := "username = ?"
	count := dbdata.FindWhereCount(&dbdata.UserActLog{}, where, username)

	var logs []dbdata.UserActLog
	err := dbdata.FindWhere(&logs, pageSize, page, where, username)
	if err != nil && !dbdata.CheckErrNotFound(err) {
		RespError(w, RespInternalErr, err)
		return
	}

	data := map[string]interface{}{
		"count":     count,
		"page_size": pageSize,
		"datas":     logs,
	}
	RespSucess(w, data)
}

// UserPortalActiveSessions returns the user's active VPN sessions
func UserPortalActiveSessions(w http.ResponseWriter, r *http.Request) {
	username := getUsernameFromCtx(r)
	if username == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	datas := sessdata.GetOnlineSess("username", username, false)
	data := map[string]interface{}{
		"count": len(datas),
		"datas": datas,
	}
	RespSucess(w, data)
}

// Password reset token storage (in-memory with expiry)
var (
	resetTokens    = make(map[string]resetTokenInfo)
	resetTokensMux sync.Mutex
)

type resetTokenInfo struct {
	Username  string
	ExpiresAt time.Time
}

func init() {
	// Cleanup expired reset tokens every 5 minutes
	go func() {
		for range time.Tick(5 * time.Minute) {
			resetTokensMux.Lock()
			now := time.Now()
			for token, info := range resetTokens {
				if now.After(info.ExpiresAt) {
					delete(resetTokens, token)
				}
			}
			resetTokensMux.Unlock()
		}
	}()
}

// UserPortalRequestPasswordReset sends a password reset email
func UserPortalRequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	defer r.Body.Close()

	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		RespError(w, RespParamErr, "请求格式错误")
		return
	}

	// Always return success to prevent username enumeration
	successMsg := "如果账号和邮箱匹配，重置链接已发送到您的邮箱"

	if req.Username == "" || req.Email == "" {
		RespSucess(w, successMsg)
		return
	}

	user := &dbdata.User{}
	err = dbdata.One("Username", req.Username, user)
	if err != nil || user.Email != req.Email || user.Status != 1 {
		// Don't reveal whether user exists
		RespSucess(w, successMsg)
		return
	}

	// Generate secure reset token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		RespError(w, RespInternalErr, "生成重置令牌失败")
		return
	}
	resetToken := hex.EncodeToString(tokenBytes)

	// Store token with 30-minute expiry
	resetTokensMux.Lock()
	// Limit total reset tokens to prevent memory exhaustion
	if len(resetTokens) >= 10000 {
		resetTokensMux.Unlock()
		RespSucess(w, successMsg)
		return
	}
	resetTokens[resetToken] = resetTokenInfo{
		Username:  user.Username,
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
	resetTokensMux.Unlock()

	// Send email with reset link
	setting := &dbdata.SettingOther{}
	if err := dbdata.SettingGet(setting); err != nil {
		base.Error("获取设置失败:", err)
		RespSucess(w, successMsg)
		return
	}

	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>密码重置</title></head>
<body>
<p>您好 %s,</p>
<p>您请求了密码重置。请使用以下令牌重置您的密码：</p>
<p><b>重置令牌: %s</b></p>
<p>此令牌将在30分钟后过期。</p>
<p>如果您没有请求密码重置，请忽略此邮件。</p>
</body>
</html>`, user.Nickname, resetToken)

	go func() {
		if err := SendMail(base.Cfg.Issuer+" - 密码重置", user.Email, htmlBody, nil); err != nil {
			base.Error("发送密码重置邮件失败:", err)
		}
	}()

	RespSucess(w, successMsg)
}

// UserPortalResetPassword resets the password using a token
func UserPortalResetPassword(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	defer r.Body.Close()

	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		RespError(w, RespParamErr, "请求格式错误")
		return
	}

	if req.Token == "" || req.NewPassword == "" {
		RespError(w, RespParamErr, "重置令牌和新密码不能为空")
		return
	}

	// Validate token
	resetTokensMux.Lock()
	info, exists := resetTokens[req.Token]
	if !exists || time.Now().After(info.ExpiresAt) {
		if exists {
			delete(resetTokens, req.Token)
		}
		resetTokensMux.Unlock()
		RespError(w, RespParamErr, "重置令牌无效或已过期")
		return
	}
	delete(resetTokens, req.Token) // One-time use
	resetTokensMux.Unlock()

	// Validate password policy
	policy := dbdata.GetPasswordPolicy()
	policyConfig := utils.PasswordPolicyConfig{
		MinLength:    policy.MinLength,
		MaxLength:    policy.MaxLength,
		RequireUpper: policy.RequireUpper,
		RequireLower: policy.RequireLower,
		RequireDigit: policy.RequireDigit,
		RequireSpec:  policy.RequireSpec,
	}
	if err := utils.ValidatePassword(req.NewPassword, policyConfig); err != nil {
		RespError(w, RespParamErr, fmt.Sprintf("密码强度不符合要求: %v", err))
		return
	}

	// Update password
	user := &dbdata.User{}
	err = dbdata.One("Username", info.Username, user)
	if err != nil {
		RespError(w, RespInternalErr, "用户不存在")
		return
	}

	if base.Cfg.EncryptionPassword {
		hashedPwd, err := utils.PasswordHash(req.NewPassword)
		if err != nil {
			RespError(w, RespInternalErr, "密码加密失败")
			return
		}
		user.PinCode = hashedPwd
	} else {
		user.PinCode = req.NewPassword
	}
	user.UpdatedAt = time.Now()
	if err := dbdata.Set(user); err != nil {
		RespError(w, RespInternalErr, "密码重置失败")
		return
	}

	base.Info("用户", info.Username, "通过邮件重置了密码")
	RespSucess(w, "密码重置成功")
}

// UserPortalGetPasswordPolicy returns the current password policy for the frontend
func UserPortalGetPasswordPolicy(w http.ResponseWriter, r *http.Request) {
	policy := dbdata.GetPasswordPolicy()
	RespSucess(w, policy)
}

// portalAuthMiddleware validates user portal JWT tokens
func portalAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwtToken := r.Header.Get("Jwt")
		if jwtToken == "" {
			jwtToken = r.Header.Get("Authorization")
			if len(jwtToken) > 7 && jwtToken[:7] == "Bearer " {
				jwtToken = jwtToken[7:]
			}
		}
		if jwtToken == "" {
			jwtToken = r.FormValue("jwt")
		}

		data, err := GetJwtData(jwtToken)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			RespError(w, RespTokenErr, "登录已过期，请重新登录")
			return
		}

		portalUser, ok := data["portal_user"]
		if !ok || fmt.Sprint(portalUser) == "" {
			w.WriteHeader(http.StatusUnauthorized)
			RespError(w, RespTokenErr, "无效的用户令牌")
			return
		}

		// Store username in header for downstream handlers
		r.Header.Set("X-Portal-User", fmt.Sprint(portalUser))
		next.ServeHTTP(w, r)
	})
}

// getUsernameFromCtx extracts the username from the portal auth context
func getUsernameFromCtx(r *http.Request) string {
	return r.Header.Get("X-Portal-User")
}
