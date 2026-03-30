package cron

import (
	"time"

	"github.com/bjdgyc/anylink/dbdata"
	"github.com/bjdgyc/anylink/sessdata"
	"github.com/go-co-op/gocron"
)

func Start() {
	s := gocron.NewScheduler(time.Local)
	s.Cron("0 * * * *").Do(ClearAudit)
	s.Cron("0 * * * *").Do(ClearStatsInfo)
	s.Cron("0 * * * *").Do(ClearUserActLog)
	s.Every(1).Day().At("00:00").Do(sessdata.CloseUserLimittimeSession)
	s.Every(1).Day().At("00:00").Do(dbdata.ReNewCert)
	// 每天上午9点检查账号即将过期的用户并发送提醒邮件
	s.Every(1).Day().At("09:00").Do(CheckAccountExpiry)
	s.StartAsync()
}
