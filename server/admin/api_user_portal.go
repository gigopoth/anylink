package admin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/bjdgyc/anylink/base"
	"github.com/bjdgyc/anylink/dbdata"
	"github.com/bjdgyc/anylink/pkg/utils"
	"github.com/bjdgyc/anylink/sessdata"
	"github.com/skip2/go-qrcode"
	"github.com/xlzd/gotp"
)

// User portal: self-service API for VPN end users (separate from admin)

// contextKey is an unexported type for context keys to avoid collisions.
type contextKey string

const portalUserKey contextKey = "portal_user"

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

	// Check if password is expired
	passwordExpired := dbdata.IsPasswordExpired(user)

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
		"token":            tokenString,
		"username":         user.Username,
		"expires_at":       expiresAt,
		"password_expired": passwordExpired,
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
	passwordExpired := dbdata.IsPasswordExpired(user)
	profile := map[string]interface{}{
		"id":                user.Id,
		"username":          user.Username,
		"nickname":          user.Nickname,
		"email":             user.Email,
		"groups":            user.Groups,
		"status":            user.Status,
		"limittime":         user.LimitTime,
		"disable_otp":       user.DisableOtp,
		"otp_bound":         user.OtpSecret != "",
		"has_recovery_codes": len(user.OtpRecoveryCodes) > 0,
		"recovery_codes_count": len(user.OtpRecoveryCodes),
		"password_expired":  passwordExpired,
		"password_changed_at": user.PasswordChangedAt,
		"created_at":        user.CreatedAt,
		"updated_at":        user.UpdatedAt,
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
	now := time.Now()
	user.PasswordChangedAt = &now
	user.UpdatedAt = now
	if err := dbdata.Set(user); err != nil {
		RespError(w, RespInternalErr, "密码修改失败")
		return
	}

	// Send password change notification email
	if user.Email != "" {
		go sendPasswordChangeNotification(user)
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
	// Rate limiter for password reset requests (CWE-770)
	resetRateLimiter    = make(map[string]resetRateInfo)
	resetRateLimiterMux sync.Mutex
)

const (
	resetRateMaxRequests = 3               // max requests per window
	resetRateWindow      = 5 * time.Minute // rate limit window
	resetRateMaxEntries  = 10000           // max entries in rate limiter map to prevent memory exhaustion
)

type resetRateInfo struct {
	Count     int
	WindowEnd time.Time
}

type resetTokenInfo struct {
	Username  string
	ExpiresAt time.Time
}

func init() {
	// Cleanup expired reset tokens and rate limit entries every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			resetTokensMux.Lock()
			now := time.Now()
			for token, info := range resetTokens {
				if now.After(info.ExpiresAt) {
					delete(resetTokens, token)
				}
			}
			resetTokensMux.Unlock()

			resetRateLimiterMux.Lock()
			for key, info := range resetRateLimiter {
				if now.After(info.WindowEnd) {
					delete(resetRateLimiter, key)
				}
			}
			resetRateLimiterMux.Unlock()
		}
	}()
}

// checkResetRateLimit checks and enforces rate limiting for password reset requests.
// Returns true if the request is allowed, false if rate limited.
func checkResetRateLimit(clientIP string) bool {
	resetRateLimiterMux.Lock()
	defer resetRateLimiterMux.Unlock()

	now := time.Now()
	info, exists := resetRateLimiter[clientIP]
	if !exists || now.After(info.WindowEnd) {
		// Prevent unbounded map growth from distributed attacks
		if !exists && len(resetRateLimiter) >= resetRateMaxEntries {
			return false
		}
		resetRateLimiter[clientIP] = resetRateInfo{
			Count:     1,
			WindowEnd: now.Add(resetRateWindow),
		}
		return true
	}
	if info.Count >= resetRateMaxRequests {
		return false
	}
	info.Count++
	resetRateLimiter[clientIP] = info
	return true
}

// UserPortalRequestPasswordReset sends a password reset email
func UserPortalRequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	// Rate limit password reset requests to prevent abuse (CWE-770)
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" {
		clientIP = r.RemoteAddr // fallback when RemoteAddr has no port
	}
	if !checkResetRateLimit(clientIP) {
		w.WriteHeader(http.StatusTooManyRequests)
		RespError(w, RespInternalErr, "请求过于频繁，请稍后再试")
		return
	}

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
</html>`, html.EscapeString(user.Nickname), html.EscapeString(resetToken))

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
	now := time.Now()
	user.PasswordChangedAt = &now
	user.UpdatedAt = now
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

		// Store username in request context for downstream handlers (CWE-287)
		ctx := context.WithValue(r.Context(), portalUserKey, fmt.Sprint(portalUser))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// getUsernameFromCtx extracts the username from the portal auth context
func getUsernameFromCtx(r *http.Request) string {
	if v, ok := r.Context().Value(portalUserKey).(string); ok {
		return v
	}
	return ""
}

// verifyUserPassword verifies a password against the stored hash or plaintext
func verifyUserPassword(password string, user *dbdata.User) bool {
	if len(user.PinCode) != 60 {
		return password == user.PinCode
	}
	return utils.PasswordVerify(password, user.PinCode)
}

// UserPortalDisconnectSession allows users to force-disconnect one of their own sessions
func UserPortalDisconnectSession(w http.ResponseWriter, r *http.Request) {
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
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		RespError(w, RespParamErr, "请求格式错误")
		return
	}

	if req.Token == "" {
		RespError(w, RespParamErr, "会话令牌不能为空")
		return
	}

	// Verify the session belongs to this user
	datas := sessdata.GetOnlineSess("username", username, false)
	found := false
	for _, d := range datas {
		if d.Token == req.Token {
			found = true
			break
		}
	}
	if !found {
		RespError(w, RespParamErr, "未找到该会话或不属于当前用户")
		return
	}

	sessdata.CloseSess(req.Token, dbdata.UserLogoutAdmin)
	base.Info("用户", username, "通过门户主动断开了会话:", req.Token)
	RespSucess(w, "会话已断开")
}

// UserPortalGetOtpStatus returns OTP status for the current user
func UserPortalGetOtpStatus(w http.ResponseWriter, r *http.Request) {
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

	data := map[string]interface{}{
		"otp_enabled":         !user.DisableOtp,
		"otp_bound":           user.OtpSecret != "",
		"has_recovery_codes":  len(user.OtpRecoveryCodes) > 0,
		"recovery_codes_count": len(user.OtpRecoveryCodes),
	}
	RespSucess(w, data)
}

// UserPortalBindOtp generates a new OTP secret and returns QR code for binding
func UserPortalBindOtp(w http.ResponseWriter, r *http.Request) {
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

	// Generate new OTP secret
	newSecret := gotp.RandomSecret(32)

	// Generate QR code - use email if available, username as fallback
	issuer := url.QueryEscape(base.Cfg.Issuer)
	accountName := user.Email
	if accountName == "" {
		accountName = user.Username
	}
	qrStr := fmt.Sprintf("otpauth://totp/%s:%s?issuer=%s&secret=%s", issuer, accountName, issuer, newSecret)
	qr, err := qrcode.New(qrStr, qrcode.High)
	if err != nil {
		RespError(w, RespInternalErr, "生成二维码失败")
		return
	}

	imgData, err := qr.PNG(300)
	if err != nil {
		RespError(w, RespInternalErr, "生成二维码图片失败")
		return
	}

	// Store the new secret temporarily - user must verify before it's saved
	pendingOtpMux.Lock()
	if len(pendingOtpSecrets) >= maxPendingOtpSecrets {
		pendingOtpMux.Unlock()
		RespError(w, RespInternalErr, "系统繁忙，请稍后重试")
		return
	}
	pendingOtpSecrets[username] = pendingOtpInfo{
		Secret:    newSecret,
		ExpiresAt: time.Now().Add(pendingOtpExpiry),
	}
	pendingOtpMux.Unlock()

	data := map[string]interface{}{
		"qr_code": base64.StdEncoding.EncodeToString(imgData),
		"secret":  newSecret,
	}
	RespSucess(w, data)
}

// Constants for pending OTP management
const (
	maxPendingOtpSecrets  = 10000
	pendingOtpExpiry      = 10 * time.Minute
	pendingOtpCleanupFreq = 2 * time.Minute
)

// Pending OTP secrets storage
var (
	pendingOtpSecrets = make(map[string]pendingOtpInfo)
	pendingOtpMux     sync.Mutex
)

type pendingOtpInfo struct {
	Secret    string
	ExpiresAt time.Time
}

func init() {
	// Cleanup expired pending OTP secrets periodically
	go func() {
		ticker := time.NewTicker(pendingOtpCleanupFreq)
		defer ticker.Stop()
		for range ticker.C {
			pendingOtpMux.Lock()
			now := time.Now()
			for k, v := range pendingOtpSecrets {
				if now.After(v.ExpiresAt) {
					delete(pendingOtpSecrets, k)
				}
			}
			pendingOtpMux.Unlock()
		}
	}()
}

// UserPortalConfirmOtp verifies and saves the OTP binding
func UserPortalConfirmOtp(w http.ResponseWriter, r *http.Request) {
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
		OtpCode string `json:"otp_code"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		RespError(w, RespParamErr, "请求格式错误")
		return
	}

	if req.OtpCode == "" {
		RespError(w, RespParamErr, "验证码不能为空")
		return
	}

	// Get pending secret
	pendingOtpMux.Lock()
	pending, exists := pendingOtpSecrets[username]
	if !exists || time.Now().After(pending.ExpiresAt) {
		if exists {
			delete(pendingOtpSecrets, username)
		}
		pendingOtpMux.Unlock()
		RespError(w, RespParamErr, "OTP绑定已过期，请重新生成")
		return
	}
	pendingOtpMux.Unlock()

	// Verify OTP code with the pending secret
	totp := gotp.NewDefaultTOTP(pending.Secret)
	if !totp.Verify(req.OtpCode, time.Now().Unix()) {
		RespError(w, RespParamErr, "验证码错误，请重试")
		return
	}

	// Save the OTP secret to user
	user := &dbdata.User{}
	err = dbdata.One("Username", username, user)
	if err != nil {
		RespError(w, RespInternalErr, "用户不存在")
		return
	}

	user.OtpSecret = pending.Secret
	user.DisableOtp = false
	// Generate recovery codes
	recoveryCodes := dbdata.GenerateRecoveryCodes(10)
	user.OtpRecoveryCodes = recoveryCodes
	user.UpdatedAt = time.Now()
	if err := dbdata.Set(user); err != nil {
		RespError(w, RespInternalErr, "保存OTP配置失败")
		return
	}

	// Clean up pending secret
	pendingOtpMux.Lock()
	delete(pendingOtpSecrets, username)
	pendingOtpMux.Unlock()

	base.Info("用户", username, "通过门户绑定了OTP")

	data := map[string]interface{}{
		"message":        "OTP绑定成功",
		"recovery_codes": recoveryCodes,
	}
	RespSucess(w, data)
}

// UserPortalResetOtp resets the user's OTP (requires password verification)
func UserPortalResetOtp(w http.ResponseWriter, r *http.Request) {
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
		Password string `json:"password"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		RespError(w, RespParamErr, "请求格式错误")
		return
	}

	if req.Password == "" {
		RespError(w, RespParamErr, "密码不能为空")
		return
	}

	user := &dbdata.User{}
	err = dbdata.One("Username", username, user)
	if err != nil {
		RespError(w, RespInternalErr, "用户不存在")
		return
	}

	// Verify password
	if !verifyUserPassword(req.Password, user) {
		RespError(w, RespUserOrPassErr, "密码错误")
		return
	}

	// Reset OTP - clear secret to avoid inconsistent state
	user.OtpSecret = ""
	user.DisableOtp = true
	user.OtpRecoveryCodes = nil
	user.UpdatedAt = time.Now()
	if err := dbdata.Set(user); err != nil {
		RespError(w, RespInternalErr, "重置OTP失败")
		return
	}

	base.Info("用户", username, "通过门户重置了OTP")
	RespSucess(w, "OTP已重置，请重新绑定")
}

// UserPortalRegenerateRecoveryCodes regenerates recovery codes (requires password verification)
func UserPortalRegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
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
		Password string `json:"password"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		RespError(w, RespParamErr, "请求格式错误")
		return
	}

	if req.Password == "" {
		RespError(w, RespParamErr, "密码不能为空")
		return
	}

	user := &dbdata.User{}
	err = dbdata.One("Username", username, user)
	if err != nil {
		RespError(w, RespInternalErr, "用户不存在")
		return
	}

	// Verify password
	if !verifyUserPassword(req.Password, user) {
		RespError(w, RespUserOrPassErr, "密码错误")
		return
	}

	if user.DisableOtp {
		RespError(w, RespParamErr, "OTP未启用，请先绑定OTP")
		return
	}

	// Generate new recovery codes
	recoveryCodes := dbdata.GenerateRecoveryCodes(10)
	user.OtpRecoveryCodes = recoveryCodes
	user.UpdatedAt = time.Now()
	if err := dbdata.Set(user); err != nil {
		RespError(w, RespInternalErr, "生成恢复码失败")
		return
	}

	base.Info("用户", username, "通过门户重新生成了恢复码")
	data := map[string]interface{}{
		"recovery_codes": recoveryCodes,
	}
	RespSucess(w, data)
}

// UserPortalBandwidthStats returns the user's current session bandwidth statistics
func UserPortalBandwidthStats(w http.ResponseWriter, r *http.Request) {
	username := getUsernameFromCtx(r)
	if username == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	datas := sessdata.GetOnlineSess("username", username, false)
	var sessions []map[string]interface{}
	for _, d := range datas {
		sessions = append(sessions, map[string]interface{}{
			"token":              d.Token,
			"ip":                 d.Ip,
			"remote_addr":       d.RemoteAddr,
			"transport_protocol": d.TransportProtocol,
			"bandwidth_up":       d.BandwidthUp,
			"bandwidth_down":     d.BandwidthDown,
			"bandwidth_up_all":   d.BandwidthUpAll,
			"bandwidth_down_all": d.BandwidthDownAll,
			"last_login":         d.LastLogin,
		})
	}

	data := map[string]interface{}{
		"count":    len(sessions),
		"sessions": sessions,
	}
	RespSucess(w, data)
}

// UserPortalGetRoutes returns the effective routes and DNS config for the user's groups
func UserPortalGetRoutes(w http.ResponseWriter, r *http.Request) {
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

	// Check if user has a personal policy
	policy := &dbdata.Policy{}
	hasPolicy := false
	if err := dbdata.One("Username", username, policy); err == nil && policy.Status == 1 {
		hasPolicy = true
	}

	var groupConfigs []map[string]interface{}
	for _, groupName := range user.Groups {
		group := &dbdata.Group{}
		if err := dbdata.One("Name", groupName, group); err != nil {
			continue
		}

		config := map[string]interface{}{
			"group_name":    group.Name,
			"client_dns":    group.ClientDns,
			"split_dns":     group.SplitDns,
			"route_include": group.RouteInclude,
			"route_exclude": group.RouteExclude,
			"allow_lan":     group.AllowLan,
		}
		groupConfigs = append(groupConfigs, config)
	}

	data := map[string]interface{}{
		"groups":     groupConfigs,
		"has_policy": hasPolicy,
	}

	// If user has personal policy, include it
	if hasPolicy {
		data["policy"] = map[string]interface{}{
			"client_dns":          policy.ClientDns,
			"route_include":       policy.RouteInclude,
			"route_exclude":       policy.RouteExclude,
			"ds_exclude_domains":  policy.DsExcludeDomains,
			"ds_include_domains":  policy.DsIncludeDomains,
			"allow_lan":           policy.AllowLan,
		}
	}

	RespSucess(w, data)
}

// sendPasswordChangeNotification sends email notification when password is changed
func sendPasswordChangeNotification(user *dbdata.User) {
	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>密码修改通知</title></head>
<body>
<p>%s 您好,</p>
<p>您的 <b>%s</b> VPN 账号密码已于 %s 成功修改。</p>
<p>如果这不是您本人的操作，请立即联系管理员。</p>
</body>
</html>`, html.EscapeString(user.Nickname), html.EscapeString(base.Cfg.Issuer), time.Now().Format("2006-01-02 15:04:05"))

	subject := fmt.Sprintf("%s - 密码修改通知", base.Cfg.Issuer)
	if err := SendMail(subject, user.Email, htmlBody, nil); err != nil {
		base.Error("发送密码修改通知邮件失败:", err)
	}
}

// SendLoginAlertEmail sends email notification for login from new IP/device
func SendLoginAlertEmail(username, remoteAddr, deviceType, platformVersion string) {
	user := &dbdata.User{}
	err := dbdata.One("Username", username, user)
	if err != nil || user.Email == "" {
		return
	}

	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>登录提醒</title></head>
<body>
<p>%s 您好,</p>
<p>您的 <b>%s</b> VPN 账号于 %s 从以下位置登录：</p>
<p>
    IP地址: <b>%s</b><br/>
    设备类型: <b>%s</b><br/>
    系统版本: <b>%s</b><br/>
</p>
<p>如果这不是您本人的操作，请立即修改密码并联系管理员。</p>
</body>
</html>`, html.EscapeString(user.Nickname), html.EscapeString(base.Cfg.Issuer), time.Now().Format("2006-01-02 15:04:05"),
		html.EscapeString(remoteAddr), html.EscapeString(deviceType), html.EscapeString(platformVersion))

	subject := fmt.Sprintf("%s - 登录提醒", base.Cfg.Issuer)
	if err := SendMail(subject, user.Email, htmlBody, nil); err != nil {
		base.Error("发送登录提醒邮件失败:", err)
	}
}

// SendAccountLockedEmail sends email notification when account is locked
func SendAccountLockedEmail(username string) {
	user := &dbdata.User{}
	err := dbdata.One("Username", username, user)
	if err != nil || user.Email == "" {
		return
	}

	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>账号锁定通知</title></head>
<body>
<p>%s 您好,</p>
<p>您的 <b>%s</b> VPN 账号因连续多次登录失败，已被临时锁定。</p>
<p>锁定时间: %s</p>
<p>账号将在一段时间后自动解锁。如需立即解锁，请联系管理员。</p>
<p>如果这些登录尝试不是您本人的操作，请在解锁后立即修改密码。</p>
</body>
</html>`, html.EscapeString(user.Nickname), html.EscapeString(base.Cfg.Issuer), time.Now().Format("2006-01-02 15:04:05"))

	subject := fmt.Sprintf("%s - 账号锁定通知", base.Cfg.Issuer)
	if err := SendMail(subject, user.Email, htmlBody, nil); err != nil {
		base.Error("发送账号锁定通知邮件失败:", err)
	}
}
