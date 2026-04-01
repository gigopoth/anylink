package sessdata

import (
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bjdgyc/anylink/base"
	"github.com/stretchr/testify/assert"
)

func resetSessions() {
	sessMux.Lock()
	sessions = make(map[string]*Session)
	dtlsIds = make(map[string]string)
	sessMux.Unlock()
}

// helper: create an active session with a minimal ConnSession (no DB needed)
func makeActiveSession(token, username, group, macAddr string, ip net.IP) *Session {
	sess := &Session{
		Token:    token,
		Username: username,
		Group:    group,
		MacAddr:  macAddr,
		IsActive: true,
		LastLogin: time.Now(),
	}
	dSess := &atomic.Value{}
	dSess.Store(&DtlsSession{isActive: -1})
	cSess := &ConnSession{
		Sess:      sess,
		IpAddr:    ip,
		Username:  username,
		MacHw:     net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		CloseChan: make(chan struct{}),
		closeOnce: sync.Once{},
		dSess:     dSess,
	}
	sess.CSess = cSess

	sessMux.Lock()
	sessions[token] = sess
	sessMux.Unlock()
	return sess
}

// --- Onlines sort interface ---

func TestOnlinesSort(t *testing.T) {
	ast := assert.New(t)

	onlines := Onlines{
		{Ip: net.IPv4(10, 0, 0, 3), Username: "c"},
		{Ip: net.IPv4(10, 0, 0, 1), Username: "a"},
		{Ip: net.IPv4(10, 0, 0, 2), Username: "b"},
	}

	ast.Equal(3, onlines.Len())
	ast.True(onlines.Less(1, 0))  // 10.0.0.1 < 10.0.0.3
	ast.False(onlines.Less(0, 1)) // 10.0.0.3 > 10.0.0.1

	sort.Sort(onlines)
	ast.Equal("a", onlines[0].Username)
	ast.Equal("b", onlines[1].Username)
	ast.Equal("c", onlines[2].Username)
}

func TestOnlinesSortEmpty(t *testing.T) {
	ast := assert.New(t)
	onlines := Onlines{}
	ast.Equal(0, onlines.Len())
	sort.Sort(onlines) // should not panic
}

// --- OnlineSess / GetOnlineSess ---

func TestOnlineSessEmpty(t *testing.T) {
	ast := assert.New(t)
	base.Test()
	resetSessions()

	result := OnlineSess()
	ast.Empty(result)
}

func TestOnlineSessWithActiveSessions(t *testing.T) {
	ast := assert.New(t)
	base.Test()
	resetSessions()

	makeActiveSession("tok1", "alice", "grp1", "00:11:22:33:44:55", net.IPv4(10, 0, 0, 2))
	makeActiveSession("tok2", "bob", "grp2", "00:11:22:33:44:66", net.IPv4(10, 0, 0, 1))

	result := OnlineSess()
	ast.Len(result, 2)
	// should be sorted by IP
	ast.True(net.IPv4(10, 0, 0, 1).Equal(result[0].Ip))
	ast.True(net.IPv4(10, 0, 0, 2).Equal(result[1].Ip))
	ast.Equal("bob", result[0].Username)
	ast.Equal("alice", result[1].Username)
	ast.Equal("TCP", result[0].TransportProtocol)
}

func TestGetOnlineSessInactiveHidden(t *testing.T) {
	ast := assert.New(t)
	base.Test()
	resetSessions()

	sess := makeActiveSession("tok1", "alice", "grp1", "aa:bb:cc:dd:ee:ff", net.IPv4(10, 0, 0, 1))
	sess.IsActive = false

	// Without show_sleeper, inactive sessions are hidden
	result := GetOnlineSess("", "", false)
	ast.Empty(result)

	// With show_sleeper, inactive sessions are shown
	result = GetOnlineSess("", "", true)
	ast.Len(result, 1)
	ast.Equal("alice", result[0].Username)
}

func TestGetOnlineSessSearchUsername(t *testing.T) {
	ast := assert.New(t)
	base.Test()
	resetSessions()

	makeActiveSession("tok1", "alice", "grp1", "00:11:22:33:44:55", net.IPv4(10, 0, 0, 1))
	makeActiveSession("tok2", "bob", "grp2", "00:11:22:33:44:66", net.IPv4(10, 0, 0, 2))

	result := GetOnlineSess("username", "alice", false)
	ast.Len(result, 1)
	ast.Equal("alice", result[0].Username)

	result = GetOnlineSess("username", "bob", false)
	ast.Len(result, 1)
	ast.Equal("bob", result[0].Username)

	result = GetOnlineSess("username", "nonexistent", false)
	ast.Empty(result)
}

func TestGetOnlineSessSearchGroup(t *testing.T) {
	ast := assert.New(t)
	base.Test()
	resetSessions()

	makeActiveSession("tok1", "alice", "grp1", "00:11:22:33:44:55", net.IPv4(10, 0, 0, 1))
	makeActiveSession("tok2", "bob", "grp2", "00:11:22:33:44:66", net.IPv4(10, 0, 0, 2))

	result := GetOnlineSess("group", "grp1", false)
	ast.Len(result, 1)
	ast.Equal("grp1", result[0].Group)
}

func TestGetOnlineSessSearchMacAddr(t *testing.T) {
	ast := assert.New(t)
	base.Test()
	resetSessions()

	makeActiveSession("tok1", "alice", "grp1", "00:11:22:33:44:55", net.IPv4(10, 0, 0, 1))

	result := GetOnlineSess("mac_addr", "00:11:22:33:44:55", false)
	ast.Len(result, 1)
	ast.Equal("alice", result[0].Username)

	result = GetOnlineSess("mac_addr", "ff:ff:ff:ff:ff:ff", false)
	ast.Empty(result)
}

func TestGetOnlineSessSearchIP(t *testing.T) {
	ast := assert.New(t)
	base.Test()
	resetSessions()

	makeActiveSession("tok1", "alice", "grp1", "00:11:22:33:44:55", net.IPv4(10, 0, 0, 1))

	result := GetOnlineSess("ip", "10.0.0.1", false)
	ast.Len(result, 1)

	result = GetOnlineSess("ip", "10.0.0.99", false)
	ast.Empty(result)
}

func TestGetOnlineSessSearchRemoteAddr(t *testing.T) {
	ast := assert.New(t)
	base.Test()
	resetSessions()

	sess := makeActiveSession("tok1", "alice", "grp1", "00:11:22:33:44:55", net.IPv4(10, 0, 0, 1))
	sess.CSess.RemoteAddr = "203.0.113.5:12345"

	result := GetOnlineSess("remote_addr", "203.0.113.5", false)
	ast.Len(result, 1)

	result = GetOnlineSess("remote_addr", "1.2.3.4", false)
	ast.Empty(result)
}

func TestGetOnlineSessEmptySearchText(t *testing.T) {
	ast := assert.New(t)
	base.Test()
	resetSessions()

	makeActiveSession("tok1", "alice", "grp1", "00:11:22:33:44:55", net.IPv4(10, 0, 0, 1))

	// Empty search text should ignore the category and return all
	result := GetOnlineSess("username", "", false)
	ast.Len(result, 1)

	result = GetOnlineSess("username", "   ", false)
	ast.Len(result, 1)
}

func TestGetOnlineSessUDPTransport(t *testing.T) {
	ast := assert.New(t)
	base.Test()
	resetSessions()

	sess := makeActiveSession("tok1", "alice", "grp1", "00:11:22:33:44:55", net.IPv4(10, 0, 0, 1))
	// Store an active DtlsSession to simulate UDP
	activeDtls := &DtlsSession{isActive: 1, CloseChan: make(chan struct{})}
	sess.CSess.dSess.Store(activeDtls)

	result := OnlineSess()
	ast.Len(result, 1)
	ast.Equal("UDP", result[0].TransportProtocol)
}

// --- Token2Sess ---

func TestToken2Sess(t *testing.T) {
	ast := assert.New(t)
	resetSessions()

	sess := NewSession("mytoken123")
	found := Token2Sess("mytoken123")
	ast.Equal(sess, found)

	notFound := Token2Sess("nonexistent")
	ast.Nil(notFound)
}

// --- SToken2Sess ---

func TestSToken2Sess(t *testing.T) {
	ast := assert.New(t)
	resetSessions()

	sess := NewSession("tok-abc")
	found := SToken2Sess("somesid@tok-abc")
	ast.Equal(sess, found)
}

func TestSToken2SessWithWhitespace(t *testing.T) {
	ast := assert.New(t)
	resetSessions()

	NewSession("tok-ws")
	found := SToken2Sess("  sid@tok-ws  ")
	ast.NotNil(found)
	ast.Equal("tok-ws", found.Token)
}

// --- Dtls2Sess / Dtls2CSess / Dtls2MasterSecret ---

func TestDtls2Sess(t *testing.T) {
	ast := assert.New(t)
	resetSessions()

	sess := NewSession("tok-dtls")
	dtlsSid := sess.DtlsSid

	found := Dtls2Sess(dtlsSid)
	ast.Equal(sess, found)

	notFound := Dtls2Sess("nonexistent-dtls-id")
	ast.Nil(notFound)
}

func TestDtls2CSessNilSession(t *testing.T) {
	ast := assert.New(t)
	resetSessions()

	// No session for this dtls id
	cs := Dtls2CSess("nonexistent")
	ast.Nil(cs)
}

func TestDtls2CSessNilCSess(t *testing.T) {
	ast := assert.New(t)
	resetSessions()

	sess := NewSession("tok-dtls2")
	// Session exists but CSess is nil
	cs := Dtls2CSess(sess.DtlsSid)
	ast.Nil(cs)
}

func TestDtls2CSessWithCSess(t *testing.T) {
	ast := assert.New(t)
	base.Test()
	resetSessions()

	sess := makeActiveSession("tok-dtls3", "user1", "grp1", "00:00:00:00:00:01", net.IPv4(10, 0, 0, 1))
	// Register dtls mapping manually
	sessMux.Lock()
	sess.DtlsSid = "dtls-sid-3"
	dtlsIds["dtls-sid-3"] = "tok-dtls3"
	sessMux.Unlock()

	cs := Dtls2CSess("dtls-sid-3")
	ast.NotNil(cs)
	ast.Equal("user1", cs.Username)
}

func TestDtls2MasterSecretNoSession(t *testing.T) {
	ast := assert.New(t)
	resetSessions()

	secret := Dtls2MasterSecret("nonexistent")
	ast.Equal("", secret)
}

func TestDtls2MasterSecretNoCSess(t *testing.T) {
	ast := assert.New(t)
	resetSessions()

	sess := NewSession("tok-ms1")
	// CSess is nil
	secret := Dtls2MasterSecret(sess.DtlsSid)
	ast.Equal("", secret)
}

func TestDtls2MasterSecretWithCSess(t *testing.T) {
	ast := assert.New(t)
	base.Test()
	resetSessions()

	sess := makeActiveSession("tok-ms2", "user1", "grp1", "00:00:00:00:00:01", net.IPv4(10, 0, 0, 1))
	sess.CSess.MasterSecret = "supersecret"
	sessMux.Lock()
	sess.DtlsSid = "dtls-ms2"
	dtlsIds["dtls-ms2"] = "tok-ms2"
	sessMux.Unlock()

	secret := Dtls2MasterSecret("dtls-ms2")
	ast.Equal("supersecret", secret)
}

// --- DelSess (no-op) ---

func TestDelSess(t *testing.T) {
	resetSessions()

	sess := NewSession("tok-del")
	// DelSess is currently a no-op, so the session should still exist
	DelSess("tok-del")

	sessMux.RLock()
	_, ok := sessions["tok-del"]
	sessMux.RUnlock()
	assert.True(t, ok, "session should still exist since DelSess is a no-op")
	_ = sess
}

// --- CloseSess ---

func TestCloseSessNonExistent(t *testing.T) {
	resetSessions()
	// Should not panic
	CloseSess("nonexistent-token")
}

func TestCloseSessRemovesSession(t *testing.T) {
	ast := assert.New(t)
	tmp := t.TempDir()
	preData(tmp)
	defer cleardata(tmp)
	time.Sleep(time.Millisecond * 200)

	sess := NewSession("")
	sess.Username = "user-close"
	sess.Group = "group1"
	sess.MacAddr = "00:15:5d:50:14:43"
	token := sess.Token
	dtlsSid := sess.DtlsSid

	cSess := sess.NewConn()
	ast.NotNil(cSess)

	CloseSess(token)

	sessMux.RLock()
	_, tokOk := sessions[token]
	_, dtlsOk := dtlsIds[dtlsSid]
	sessMux.RUnlock()

	ast.False(tokOk, "session should be removed")
	ast.False(dtlsOk, "dtls mapping should be removed")
}

func TestCloseSessWithoutCSess(t *testing.T) {
	ast := assert.New(t)
	tmp := t.TempDir()
	preData(tmp)
	defer cleardata(tmp)
	time.Sleep(time.Millisecond * 200)

	sess := NewSession("")
	sess.Username = "user-nocsess"
	sess.Group = "group1"
	token := sess.Token

	// CSess is nil, should exercise the AddUserActLogBySess path
	CloseSess(token)

	sessMux.RLock()
	_, ok := sessions[token]
	sessMux.RUnlock()
	ast.False(ok)
}

// --- CloseCSess ---

func TestCloseCSessNonExistent(t *testing.T) {
	resetSessions()
	// Should not panic
	CloseCSess("nonexistent")
}

func TestCloseCSessWithCSess(t *testing.T) {
	ast := assert.New(t)
	tmp := t.TempDir()
	preData(tmp)
	defer cleardata(tmp)
	time.Sleep(time.Millisecond * 200)

	sess := NewSession("")
	sess.Username = "user-cclose"
	sess.Group = "group1"
	sess.MacAddr = "00:15:5d:50:14:44"
	token := sess.Token

	cSess := sess.NewConn()
	ast.NotNil(cSess)

	CloseCSess(token)
	// Session should still exist in the map, but CSess should be nil
	sessMux.RLock()
	s := sessions[token]
	sessMux.RUnlock()
	ast.NotNil(s)
	s.mux.RLock()
	ast.Nil(s.CSess)
	s.mux.RUnlock()
}

func TestCloseCSessNilCSess(t *testing.T) {
	resetSessions()
	sess := NewSession("tok-nilcsess")
	// CSess is nil — should not panic
	CloseCSess(sess.Token)
}

// --- SetMtu ---

func TestSetMtuValid(t *testing.T) {
	ast := assert.New(t)
	base.Test()
	base.Cfg.Mtu = 0
	MaxMtu = 1460

	sess := &Session{}
	dSess := &atomic.Value{}
	dSess.Store(&DtlsSession{isActive: -1})
	cs := &ConnSession{Sess: sess, dSess: dSess}

	cs.SetMtu("1200")
	ast.Equal(1200, cs.Mtu)
}

func TestSetMtuLargerThanMax(t *testing.T) {
	ast := assert.New(t)
	base.Test()
	base.Cfg.Mtu = 0
	MaxMtu = 1460

	sess := &Session{}
	dSess := &atomic.Value{}
	dSess.Store(&DtlsSession{isActive: -1})
	cs := &ConnSession{Sess: sess, dSess: dSess}

	cs.SetMtu("9999")
	ast.Equal(1460, cs.Mtu) // capped at MaxMtu
}

func TestSetMtuInvalid(t *testing.T) {
	ast := assert.New(t)
	base.Test()
	base.Cfg.Mtu = 0
	MaxMtu = 1460

	sess := &Session{}
	dSess := &atomic.Value{}
	dSess.Store(&DtlsSession{isActive: -1})
	cs := &ConnSession{Sess: sess, dSess: dSess}

	cs.SetMtu("abc")
	ast.Equal(1460, cs.Mtu) // falls back to MaxMtu

	cs.SetMtu("50") // below 100
	ast.Equal(1460, cs.Mtu)
}

func TestSetMtuConfigOverride(t *testing.T) {
	ast := assert.New(t)
	base.Test()
	base.Cfg.Mtu = 1000
	MaxMtu = 1460

	sess := &Session{}
	dSess := &atomic.Value{}
	dSess.Store(&DtlsSession{isActive: -1})
	cs := &ConnSession{Sess: sess, dSess: dSess}

	cs.SetMtu("900")
	ast.Equal(900, cs.Mtu)
	ast.Equal(1000, MaxMtu) // MaxMtu updated from config

	// Reset for other tests
	base.Cfg.Mtu = 0
	MaxMtu = 1460
}

// --- SetIfName ---

func TestSetIfName(t *testing.T) {
	ast := assert.New(t)

	sess := &Session{}
	cs := &ConnSession{Sess: sess}

	cs.SetIfName("tun0")
	ast.Equal("tun0", cs.IfName)

	cs.SetIfName("utun5")
	ast.Equal("utun5", cs.IfName)
}

// --- DtlsSession.Close ---

func TestDtlsSessionClose(t *testing.T) {
	ast := assert.New(t)
	base.Test()

	ds := &DtlsSession{
		isActive:  1,
		CloseChan: make(chan struct{}),
		IpAddr:    net.IPv4(10, 0, 0, 1),
	}

	ds.Close()
	ast.Equal(int32(-1), atomic.LoadInt32(&ds.isActive))

	// Verify channel is closed
	select {
	case <-ds.CloseChan:
		// expected
	default:
		t.Fatal("CloseChan should be closed")
	}

	// Double-close should not panic (sync.Once)
	ds.Close()
}

// --- GetOnlineSess with nil CSess ---

func TestGetOnlineSessNilCSess(t *testing.T) {
	ast := assert.New(t)
	base.Test()
	resetSessions()

	// Session without CSess and inactive — should not appear without show_sleeper
	sess := &Session{
		Token:    "tok-nilcsess-online",
		Username: "ghost",
		IsActive: false,
	}
	sessMux.Lock()
	sessions["tok-nilcsess-online"] = sess
	sessMux.Unlock()

	result := GetOnlineSess("", "", false)
	ast.Empty(result)
}
