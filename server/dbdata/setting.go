package dbdata

import (
	"encoding/json"
	"reflect"

	"xorm.io/xorm"
)

type SettingInstall struct {
	Installed bool `json:"installed"`
}

type SettingSmtp struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	From               string `json:"from"`
	Encryption         string `json:"encryption"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

type SettingAuditLog struct {
	AuditInterval int    `json:"audit_interval"`
	LifeDay       int    `json:"life_day"`
	ClearTime     string `json:"clear_time"`
}

type SettingOther struct {
	LinkAddr    string `json:"link_addr"`
	Banner      string `json:"banner"`
	Homecode    int    `json:"homecode"`
	Homeindex   string `json:"homeindex"`
	AccountMail string `json:"account_mail"`
}

// SettingPasswordPolicy defines the password strength requirements
type SettingPasswordPolicy struct {
	MinLength    int  `json:"min_length"`    // 最小密码长度(默认8)
	MaxLength    int  `json:"max_length"`    // 最大密码长度(默认64)
	RequireUpper bool `json:"require_upper"` // 要求包含大写字母
	RequireLower bool `json:"require_lower"` // 要求包含小写字母
	RequireDigit bool `json:"require_digit"` // 要求包含数字
	RequireSpec  bool `json:"require_spec"`  // 要求包含特殊字符
	PasswordMaxAge int `json:"password_max_age"` // 密码最大有效天数(0=不限制)
}

// GetPasswordPolicy retrieves the password policy from the database, initializing defaults if not found
func GetPasswordPolicy() SettingPasswordPolicy {
	data := SettingPasswordPolicy{}
	err := SettingGet(&data)
	if err == nil {
		return data
	}
	// Fallback defaults for existing installations without policy in DB
	// MinLength=6 matches the original minimum to maintain backward compatibility
	// New installations get MinLength=8 from addInitData()
	return SettingPasswordPolicy{
		MinLength: 6,
		MaxLength: 64,
	}
}

func StructName(data interface{}) string {
	ref := reflect.ValueOf(data)
	s := &ref
	if s.Kind() == reflect.Ptr {
		e := s.Elem()
		s = &e
	}
	name := s.Type().Name()
	return name
}

func SettingSessAdd(sess *xorm.Session, data interface{}) error {
	name := StructName(data)
	v, _ := json.Marshal(data)
	s := &Setting{Name: name, Data: v}
	_, err := sess.InsertOne(s)
	return err
}

func SettingSet(data interface{}) error {
	name := StructName(data)
	v, _ := json.Marshal(data)
	s := &Setting{Data: v}
	err := Update("name", name, s)
	return err
}

func SettingGet(data interface{}) error {
	name := StructName(data)
	s := &Setting{}
	err := One("name", name, s)
	if err != nil {
		return err
	}
	err = json.Unmarshal(s.Data, data)
	return err
}

func SettingGetAuditLog() (SettingAuditLog, error) {
	data := SettingAuditLog{}
	err := SettingGet(&data)
	if err == nil {
		return data, err
	}
	if !CheckErrNotFound(err) {
		return data, err
	}
	sess := xdb.NewSession()
	defer sess.Close()
	auditLog := SettingGetAuditLogDefault()
	err = SettingSessAdd(sess, auditLog)
	if err != nil {
		return data, err
	}
	return auditLog, nil
}

func SettingGetAuditLogDefault() SettingAuditLog {
	auditLog := SettingAuditLog{
		LifeDay:   0,
		ClearTime: "05:00",
	}
	return auditLog
}
