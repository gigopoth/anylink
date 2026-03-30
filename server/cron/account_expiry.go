package cron

import (
	"bytes"
	"fmt"
	"text/template"
	"time"

	"github.com/bjdgyc/anylink/admin"
	"github.com/bjdgyc/anylink/base"
	"github.com/bjdgyc/anylink/dbdata"
)

const expiryReminderDays = 7 // 提前7天提醒

// CheckAccountExpiry checks for users whose accounts are about to expire
// and sends reminder emails
func CheckAccountExpiry() {
	now := time.Now()
	reminderDeadline := now.Add(time.Duration(expiryReminderDays) * 24 * time.Hour)

	// Find active users whose limittime is between now and 7 days from now
	// limit=0 fetches all matching records (no pagination)
	var users []dbdata.User
	where := "status = ? AND limittime IS NOT NULL AND limittime > ? AND limittime <= ?"
	err := dbdata.FindWhere(&users, 0, 1, where, 1, now, reminderDeadline)
	if err != nil {
		if !dbdata.CheckErrNotFound(err) {
			base.Error("检查账号过期提醒失败:", err)
		}
		return
	}

	setting := &dbdata.SettingOther{}
	if err := dbdata.SettingGet(setting); err != nil {
		base.Error("获取设置失败:", err)
		return
	}

	for _, user := range users {
		if user.Email == "" {
			continue
		}
		if user.LimitTime == nil {
			continue
		}

		daysLeft := int(user.LimitTime.Sub(now).Hours() / 24)
		if daysLeft < 0 {
			daysLeft = 0
		}

		err := sendExpiryReminder(&user, setting, daysLeft)
		if err != nil {
			base.Error("发送过期提醒邮件失败:", user.Username, err)
		} else {
			base.Info("已发送过期提醒邮件:", user.Username, "剩余天数:", daysLeft)
		}
	}
}

const expiryReminderTemplate = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>账号即将过期提醒</title></head>
<body>
<p>{{.Nickname}} 您好,</p>
<p>您的 <b>{{.Issuer}}</b> VPN 账号将于 <b>{{.ExpireDate}}</b> 过期，距离过期还有 <b>{{.DaysLeft}}</b> 天。</p>
<p>请联系管理员续期，以免影响您的正常使用。</p>
<p>
    账号信息：<br/>
    用户名: <b>{{.Username}}</b><br/>
    过期时间: <b>{{.ExpireDate}}</b><br/>
</p>
<p>谢谢！</p>
</body>
</html>
`

type expiryReminderData struct {
	Issuer     string
	Username   string
	Nickname   string
	ExpireDate string
	DaysLeft   int
}

func sendExpiryReminder(user *dbdata.User, setting *dbdata.SettingOther, daysLeft int) error {
	data := expiryReminderData{
		Issuer:     base.Cfg.Issuer,
		Username:   user.Username,
		Nickname:   user.Nickname,
		ExpireDate: user.LimitTime.Local().Format("2006-01-02"),
		DaysLeft:   daysLeft,
	}

	t, err := template.New("expiry_reminder").Parse(expiryReminderTemplate)
	if err != nil {
		return fmt.Errorf("模板解析失败: %v", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return fmt.Errorf("模板渲染失败: %v", err)
	}

	subject := fmt.Sprintf("%s - 账号即将过期提醒", base.Cfg.Issuer)
	return admin.SendMail(subject, user.Email, buf.String(), nil)
}
