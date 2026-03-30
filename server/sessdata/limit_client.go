package sessdata

import (
	"sync"

	"github.com/bjdgyc/anylink/base"
)

const limitAllKey = "__ALL__"

var (
	limitClient = map[string]int{limitAllKey: 0}
	limitMux    = sync.Mutex{}
)

// LimitClient checks and updates the client connection count.
// maxUserClient overrides the global limit when > 0 (per-group setting).
func LimitClient(user string, close bool, maxUserClient ...int) bool {
	limitMux.Lock()
	defer limitMux.Unlock()

	_all := limitClient[limitAllKey]
	c, ok := limitClient[user]
	if !ok { // 不存在用户
		limitClient[user] = 0
	}

	if close {
		limitClient[user] = c - 1
		limitClient[limitAllKey] = _all - 1
		return true
	}

	// 全局判断
	if _all >= base.Cfg.MaxClient {
		return false
	}

	// 超出同一个用户限制
	userMax := base.Cfg.MaxUserClient
	if len(maxUserClient) > 0 && maxUserClient[0] > 0 {
		userMax = maxUserClient[0] // 使用组级别的限制
	}
	if c >= userMax {
		return false
	}

	limitClient[user] = c + 1
	limitClient[limitAllKey] = _all + 1
	return true
}
