package dbdata

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckErrNotFound(t *testing.T) {
	ast := assert.New(t)

	ast.True(CheckErrNotFound(ErrNotFound))
	ast.False(CheckErrNotFound(nil))
	ast.False(CheckErrNotFound(errors.New("other error")))
}

func TestStructName(t *testing.T) {
	ast := assert.New(t)

	// Pointer to struct
	ast.Equal("SettingSmtp", StructName(&SettingSmtp{}))
	// Value struct
	ast.Equal("SettingOther", StructName(SettingOther{}))
	ast.Equal("SettingPasswordPolicy", StructName(&SettingPasswordPolicy{}))
}

func TestSettingGetAuditLogDefault(t *testing.T) {
	ast := assert.New(t)

	d := SettingGetAuditLogDefault()
	ast.Equal(0, d.LifeDay)
	ast.Equal("05:00", d.ClearTime)
	ast.Equal(0, d.AuditInterval)
}

func TestSettingGetSet(t *testing.T) {
	ast := assert.New(t)
	preIpData()
	defer closeIpdata()

	// SettingGet on non-existent key returns ErrNotFound
	smtp := SettingSmtp{}
	err := SettingGet(&smtp)
	ast.ErrorIs(err, ErrNotFound)

	// Insert a setting via session, then retrieve it
	sess := xdb.NewSession()
	defer sess.Close()
	smtpIn := SettingSmtp{Host: "mail.example.com", Port: 587, Username: "user"}
	err = SettingSessAdd(sess, smtpIn)
	ast.Nil(err)

	smtpOut := SettingSmtp{}
	err = SettingGet(&smtpOut)
	ast.Nil(err)
	ast.Equal("mail.example.com", smtpOut.Host)
	ast.Equal(587, smtpOut.Port)
	ast.Equal("user", smtpOut.Username)

	// SettingSet updates the existing setting
	smtpIn.Host = "smtp.example.com"
	err = SettingSet(&smtpIn)
	ast.Nil(err)

	smtpOut2 := SettingSmtp{}
	err = SettingGet(&smtpOut2)
	ast.Nil(err)
	ast.Equal("smtp.example.com", smtpOut2.Host)
}

func TestGetPasswordPolicy(t *testing.T) {
	ast := assert.New(t)
	preIpData()
	defer closeIpdata()

	// No policy in DB yet — should return fallback defaults
	p := GetPasswordPolicy()
	ast.Equal(6, p.MinLength)
	ast.Equal(64, p.MaxLength)

	// Insert a custom policy, then verify retrieval
	sess := xdb.NewSession()
	defer sess.Close()
	custom := SettingPasswordPolicy{MinLength: 10, MaxLength: 32, RequireUpper: true}
	err := SettingSessAdd(sess, custom)
	ast.Nil(err)

	p2 := GetPasswordPolicy()
	ast.Equal(10, p2.MinLength)
	ast.Equal(32, p2.MaxLength)
	ast.True(p2.RequireUpper)
}

func TestSettingGetAuditLog(t *testing.T) {
	ast := assert.New(t)
	preIpData()
	defer closeIpdata()

	// First call should auto-create default audit log setting
	al, err := SettingGetAuditLog()
	ast.Nil(err)
	ast.Equal(0, al.LifeDay)
	ast.Equal("05:00", al.ClearTime)

	// Second call should retrieve existing record
	al2, err := SettingGetAuditLog()
	ast.Nil(err)
	ast.Equal(al.ClearTime, al2.ClearTime)
}

func TestORMOperations(t *testing.T) {
	ast := assert.New(t)
	preIpData()
	defer closeIpdata()

	// CountAll on empty table
	count := CountAll(&IpMap{})
	ast.Equal(0, count)

	// AddBatch — insert multiple records
	maps := []IpMap{
		{IpAddr: "10.0.0.1", MacAddr: "00:11:22:33:44:55", Username: "u1"},
		{IpAddr: "10.0.0.2", MacAddr: "00:11:22:33:44:56", Username: "u2"},
		{IpAddr: "10.0.0.3", MacAddr: "00:11:22:33:44:57", Username: "u3"},
	}
	err := AddBatch(&maps)
	ast.Nil(err)

	count = CountAll(&IpMap{})
	ast.Equal(3, count)

	// Del — delete one record
	err = Del(&IpMap{Id: 1})
	ast.Nil(err)
	count = CountAll(&IpMap{})
	ast.Equal(2, count)

	// FindWhereCount
	wc := FindWhereCount(&IpMap{}, "username = ?", "u2")
	ast.Equal(1, wc)

	// FindWhere with limit=0 (all)
	var results []IpMap
	err = FindWhere(&results, 0, 0, "username like ?", "u%")
	ast.Nil(err)
	ast.Equal(2, len(results))

	// FindWhere with pagination
	var page1 []IpMap
	err = FindWhere(&page1, 1, 1, "username like ?", "u%")
	ast.Nil(err)
	ast.Equal(1, len(page1))

	// CountPrefix
	cp := CountPrefix("username", "u", &IpMap{})
	ast.Equal(2, cp)

	// Prefix with limit=0
	var prefixAll []IpMap
	err = Prefix("username", "u", &prefixAll, 0, 0)
	ast.Nil(err)
	ast.Equal(2, len(prefixAll))

	// Prefix with pagination
	var prefixPage []IpMap
	err = Prefix("username", "u", &prefixPage, 1, 1)
	ast.Nil(err)
	ast.Equal(1, len(prefixPage))

	// FindAndCount with limit=0
	sess := xdb.NewSession()
	defer sess.Close()
	var fc []IpMap
	total, err := FindAndCount(sess, &fc, 0, 0)
	ast.Nil(err)
	ast.Equal(int64(2), total)

	// FindAndCount with pagination
	sess2 := xdb.NewSession()
	defer sess2.Close()
	var fc2 []IpMap
	total2, err := FindAndCount(sess2, &fc2, 1, 1)
	ast.Nil(err)
	ast.Equal(int64(2), total2)
	ast.Equal(1, len(fc2))
}

func TestSetIpMap(t *testing.T) {
	ast := assert.New(t)
	preIpData()
	defer closeIpdata()

	// Validation: short IP
	err := SetIpMap(&IpMap{IpAddr: "1", MacAddr: "00:11:22:33:44:55"})
	ast.NotNil(err)

	// Validation: short MAC
	err = SetIpMap(&IpMap{IpAddr: "10.0.0.1", MacAddr: "00"})
	ast.NotNil(err)

	// Validation: invalid MAC format
	err = SetIpMap(&IpMap{IpAddr: "10.0.0.1", MacAddr: "not-a-mac"})
	ast.NotNil(err)

	// Insert new (Id <= 0)
	v := &IpMap{IpAddr: "10.0.0.1", MacAddr: "00:11:22:33:44:55", Username: "test"}
	err = SetIpMap(v)
	ast.Nil(err)
	ast.True(v.Id > 0)

	// MAC should be normalized
	ast.Equal("00:11:22:33:44:55", v.MacAddr)

	// Update existing (Id > 0)
	v.Username = "updated"
	err = SetIpMap(v)
	ast.Nil(err)

	// Verify update
	out := &IpMap{}
	err = One("id", v.Id, out)
	ast.Nil(err)
	ast.Equal("updated", out.Username)
}
