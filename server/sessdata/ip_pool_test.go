package sessdata

import (
	"fmt"
	"net"
	"os"
	"path"
	"testing"
	"time"

	"github.com/bjdgyc/anylink/base"
	"github.com/bjdgyc/anylink/dbdata"
	"github.com/stretchr/testify/assert"
)

func preData(tmpDir string) {
	base.Test()
	tmpDb := path.Join(tmpDir, "test.db")
	base.Cfg.DbType = "sqlite3"
	base.Cfg.DbSource = tmpDb
	base.Cfg.Ipv4CIDR = "192.168.3.0/24"
	base.Cfg.Ipv4Gateway = "192.168.3.1"
	base.Cfg.Ipv4Start = "192.168.3.100"
	base.Cfg.Ipv4End = "192.168.3.150"
	base.Cfg.MaxClient = 100
	base.Cfg.MaxUserClient = 3
	base.Cfg.IpLease = 5

	dbdata.Start()
	group := dbdata.Group{
		Name:      "group1",
		Bandwidth: 1000,
	}
	_ = dbdata.Add(&group)
	initIpPool()
}

func cleardata(tmpDir string) {
	_ = dbdata.Stop()
	tmpDb := path.Join(tmpDir, "test.db")
	os.Remove(tmpDb)
}

func TestIpPool(t *testing.T) {
	assert := assert.New(t)
	tmp := t.TempDir()
	preData(tmp)
	defer cleardata(tmp)

	var ip net.IP

	for i := 100; i <= 150; i++ {
		_ = AcquireIp(getTestUser(i), getTestMacAddr(i), true)
	}

	// 回收
	ReleaseIp(net.IPv4(192, 168, 3, 140), getTestMacAddr(140))
	time.Sleep(time.Second * 6)

	// 从头循环获取可用ip
	user_new := getTestUser(210)
	mac_new := getTestMacAddr(210)
	ip = AcquireIp(user_new, mac_new, true)
	t.Log("mac_new", ip)
	assert.NotNil(ip)
	assert.True(net.IPv4(192, 168, 3, 140).Equal(ip))

	// 回收全部
	for i := 100; i <= 150; i++ {
		ReleaseIp(net.IPv4(192, 168, 3, byte(i)), getTestMacAddr(i))
	}
}

func TestIpPool_Exhaustion(t *testing.T) {
	assert := assert.New(t)
	tmp := t.TempDir()
	preData(tmp)
	defer cleardata(tmp)

	// Allocate all 51 IPs (100-150)
	for i := 100; i <= 150; i++ {
		ip := AcquireIp(getTestUser(i), getTestMacAddr(i), true)
		assert.NotNil(ip, "should allocate IP for index %d", i)
	}

	// The pool is fully active. The next allocation should still return an IP
	// because loopIp reuses the entry with the earliest LastLogin when exhausted.
	// However, since all are active, it finds the oldest non-active (loopFarIp)
	// but they're all marked active, so newIp stays nil.
	ip := AcquireIp(getTestUser(999), getTestMacAddr(999), true)
	assert.Nil(ip, "should not allocate when pool is fully exhausted")

	// Release all
	for i := 100; i <= 150; i++ {
		ReleaseIp(net.IPv4(192, 168, 3, byte(i)), getTestMacAddr(i))
	}
}

func TestIpPool_SameMac(t *testing.T) {
	assert := assert.New(t)
	tmp := t.TempDir()
	preData(tmp)
	defer cleardata(tmp)

	mac := getTestMacAddr(200)
	user := getTestUser(200)

	// First allocation
	ip1 := AcquireIp(user, mac, true)
	assert.NotNil(ip1)
	t.Logf("First allocation: %s", ip1)

	// Release the IP
	ReleaseIp(ip1, mac)

	// Allocate again with the same MAC — should get the same IP (MAC affinity)
	ip2 := AcquireIp(user, mac, true)
	assert.NotNil(ip2)
	t.Logf("Second allocation: %s", ip2)
	assert.True(ip1.Equal(ip2), "same MAC should get same IP back")

	// Cleanup
	ReleaseIp(ip2, mac)
}

func TestIpPool_BoundaryIPs(t *testing.T) {
	assert := assert.New(t)
	tmp := t.TempDir()
	preData(tmp)
	defer cleardata(tmp)

	// First IP in range: 192.168.3.100
	ip1 := AcquireIp(getTestUser(300), getTestMacAddr(300), true)
	assert.NotNil(ip1)
	assert.True(net.IPv4(192, 168, 3, 100).Equal(ip1),
		"first allocation should be the start IP 192.168.3.100, got %s", ip1)

	// Allocate remaining IPs to reach the last one (101-150)
	for i := 101; i <= 150; i++ {
		ip := AcquireIp(getTestUser(300+i), getTestMacAddr(300+i), true)
		assert.NotNil(ip, "should allocate IP for index %d", i)
	}

	// Verify the last IP 192.168.3.150 was allocated by checking all IPs are taken
	// The 51st allocation (index 150) should have gotten 192.168.3.150
	// We verify indirectly: pool is now exhausted
	ipExtra := AcquireIp(getTestUser(999), getTestMacAddr(999), true)
	assert.Nil(ipExtra, "pool should be exhausted after allocating 51 IPs")

	// Release all — first IP was allocated with index 300, rest with 300+i
	ReleaseIp(net.IPv4(192, 168, 3, 100), getTestMacAddr(300))
	for i := 101; i <= 150; i++ {
		ReleaseIp(net.IPv4(192, 168, 3, byte(i)), getTestMacAddr(300+i))
	}
}

func TestIpPool_ConcurrentAllocation(t *testing.T) {
	assert := assert.New(t)
	tmp := t.TempDir()
	preData(tmp)
	defer cleardata(tmp)

	const numGoroutines = 20
	type allocResult struct {
		ip  net.IP
		mac string
	}
	results := make(chan allocResult, numGoroutines)

	// Concurrently allocate IPs from goroutines
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			mac := getTestMacAddr(400 + idx)
			ip := AcquireIp(getTestUser(400+idx), mac, true)
			results <- allocResult{ip: ip, mac: mac}
		}(i)
	}

	// Collect all results
	allocs := make([]allocResult, 0, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		r := <-results
		assert.NotNil(r.ip, "concurrent allocation should not return nil")
		allocs = append(allocs, r)
	}

	// Verify all IPs are unique
	seen := make(map[string]bool)
	for _, r := range allocs {
		key := r.ip.String()
		assert.False(seen[key], "duplicate IP allocated: %s", key)
		seen[key] = true
	}

	// Cleanup with correct MAC addresses
	for _, r := range allocs {
		ReleaseIp(r.ip, r.mac)
	}
}

func getTestUser(i int) string {
	return fmt.Sprintf("user-%d", i)
}

func getTestMacAddr(i int) string {
	// 前缀mac
	macAddr := "02:00:00:00:00"
	return fmt.Sprintf("%s:%x", macAddr, i)
}
