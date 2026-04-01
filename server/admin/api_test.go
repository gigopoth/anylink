package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bjdgyc/anylink/base"
	"github.com/bjdgyc/anylink/dbdata"
	"github.com/bjdgyc/anylink/pkg/utils"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

// ========== JWT Security Tests ==========

func TestJwtData_Expired(t *testing.T) {
	assert := assert.New(t)
	base.Cfg.JwtSecret = "test_secret_expired_jwt_key"

	data := map[string]interface{}{"user": "admin"}
	expiresAt := time.Now().Add(-time.Hour).Unix() // already expired
	token, err := SetJwtData(data, expiresAt)
	assert.Nil(err)

	_, err = GetJwtData(token)
	assert.NotNil(err)
}

func TestJwtData_Tampered(t *testing.T) {
	assert := assert.New(t)
	base.Cfg.JwtSecret = "test_secret_tampered_jwt_key"

	data := map[string]interface{}{"user": "admin"}
	expiresAt := time.Now().Add(time.Hour).Unix()
	token, err := SetJwtData(data, expiresAt)
	assert.Nil(err)

	// Tamper with the token by modifying a character in the middle of the signature
	// Avoid last char which may be base64 padding and not affect decoded bytes
	tampered := []byte(token)
	// Find the last '.' which separates header.payload.signature
	sigStart := strings.LastIndex(token, ".") + 1
	modIdx := sigStart + 2 // Modify a character well inside the signature
	if modIdx < len(tampered) {
		if tampered[modIdx] == 'A' {
			tampered[modIdx] = 'B'
		} else {
			tampered[modIdx] = 'A'
		}
	}

	_, err = GetJwtData(string(tampered))
	assert.NotNil(err)
}

func TestJwtData_EmptyToken(t *testing.T) {
	assert := assert.New(t)
	base.Cfg.JwtSecret = "test_secret_empty_jwt_key"

	_, err := GetJwtData("")
	assert.NotNil(err)
}

func TestJwtData_WrongSecret(t *testing.T) {
	assert := assert.New(t)
	base.Cfg.JwtSecret = "original_secret_key_1234"

	data := map[string]interface{}{"user": "admin"}
	expiresAt := time.Now().Add(time.Hour).Unix()
	token, err := SetJwtData(data, expiresAt)
	assert.Nil(err)

	// Change the secret before decoding
	base.Cfg.JwtSecret = "different_secret_key_5678"

	_, err = GetJwtData(token)
	assert.NotNil(err)
}

// ========== Admin Login Tests ==========

func TestLogin_Success(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	base.Cfg.JwtSecret = "test_login_jwt_secret"
	base.Cfg.AdminUser = "admin"
	base.Cfg.AdminOtp = ""
	hash, err := utils.PasswordHash("testpass123")
	assert.Nil(err)
	base.Cfg.AdminPass = hash

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/base/login", nil)
	r.PostForm = url.Values{
		"admin_user": {"admin"},
		"admin_pass": {"testpass123"},
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	Login(w, r)

	assert.Equal(http.StatusOK, w.Code)

	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err = json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespSuccess, resp.Code)
	assert.Equal("success", resp.Msg)

	// Verify the response contains a token
	dataMap, ok := resp.Data.(map[string]interface{})
	assert.True(ok)
	assert.NotEmpty(dataMap["token"])
	assert.Equal("admin", dataMap["admin_user"])
}

func TestLogin_WrongPassword(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	base.Cfg.JwtSecret = "test_login_jwt_secret"
	base.Cfg.AdminUser = "admin"
	base.Cfg.AdminOtp = ""
	hash, err := utils.PasswordHash("correctpass")
	assert.Nil(err)
	base.Cfg.AdminPass = hash

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/base/login", nil)
	r.PostForm = url.Values{
		"admin_user": {"admin"},
		"admin_pass": {"wrongpass"},
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	Login(w, r)

	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err = json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespUserOrPassErr, resp.Code)
}

func TestLogin_WrongUsername(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	base.Cfg.JwtSecret = "test_login_jwt_secret"
	base.Cfg.AdminUser = "admin"
	base.Cfg.AdminOtp = ""
	hash, err := utils.PasswordHash("testpass123")
	assert.Nil(err)
	base.Cfg.AdminPass = hash

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/base/login", nil)
	r.PostForm = url.Values{
		"admin_user": {"wronguser"},
		"admin_pass": {"testpass123"},
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	Login(w, r)

	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err = json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespUserOrPassErr, resp.Code)
}

// ========== Auth Middleware Tests ==========

func TestAuthMiddleware_NoToken(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	base.Cfg.JwtSecret = "test_auth_middleware_secret"
	base.Cfg.AdminUser = "admin"

	router := mux.NewRouter()
	router.Use(authMiddleware)
	router.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}).Name("protected")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	router.ServeHTTP(w, r)

	assert.Equal(http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_ValidToken(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	base.Cfg.JwtSecret = "test_auth_middleware_secret"
	base.Cfg.AdminUser = "admin"

	jwtData := map[string]interface{}{"admin_user": "admin"}
	expiresAt := time.Now().Add(time.Hour).Unix()
	token, err := SetJwtData(jwtData, expiresAt)
	assert.Nil(err)

	router := mux.NewRouter()
	router.Use(authMiddleware)
	router.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}).Name("protected")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.Header.Set("Jwt", token)
	router.ServeHTTP(w, r)

	assert.Equal(http.StatusOK, w.Code)
}

func TestAuthMiddleware_ExpiredToken(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	base.Cfg.JwtSecret = "test_auth_middleware_secret"
	base.Cfg.AdminUser = "admin"

	jwtData := map[string]interface{}{"admin_user": "admin"}
	expiresAt := time.Now().Add(-time.Hour).Unix() // expired
	token, err := SetJwtData(jwtData, expiresAt)
	assert.Nil(err)

	router := mux.NewRouter()
	router.Use(authMiddleware)
	router.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}).Name("protected")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.Header.Set("Jwt", token)
	router.ServeHTTP(w, r)

	assert.Equal(http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_ExemptRoutes(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	base.Cfg.JwtSecret = "test_auth_middleware_secret"

	exemptNames := []string{"login", "index", "static"}
	paths := []string{"/base/login", "/status.html", "/ui/"}

	for i, name := range exemptNames {
		router := mux.NewRouter()
		router.Use(authMiddleware)
		router.HandleFunc(paths[i], func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		}).Name(name)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, paths[i], nil)
		// No JWT token provided
		router.ServeHTTP(w, r)

		assert.Equal(http.StatusOK, w.Code, "route %q (name=%q) should be exempt from auth", paths[i], name)
	}
}

// ========== Admin API Handler Tests (with DB) ==========

func setupTestDB(t *testing.T) func() {
	tmpDb := filepath.Join(t.TempDir(), "test_admin.db")
	base.Cfg.DbType = "sqlite3"
	base.Cfg.DbSource = tmpDb
	dbdata.Start()
	return func() {
		dbdata.Stop()
	}
}

func TestUserList_Empty(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/user/list", nil)

	UserList(w, r)

	assert.Equal(http.StatusOK, w.Code)

	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err := json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespSuccess, resp.Code)

	dataMap, ok := resp.Data.(map[string]interface{})
	assert.True(ok)
	count, ok := dataMap["count"].(float64)
	assert.True(ok)
	assert.Equal(float64(0), count)
}

func TestUserDetail_NotFound(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/user/detail?id=9999", nil)

	UserDetail(w, r)

	assert.Equal(http.StatusOK, w.Code)

	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err := json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.NotEqual(RespSuccess, resp.Code)
}

func TestGroupNames_Empty(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	// Remove groups created by initData so the table is empty
	initialGroups := dbdata.GetGroupNames()
	for _, name := range initialGroups {
		var g dbdata.Group
		err := dbdata.One("Name", name, &g)
		assert.Nil(err)
		err = dbdata.Del(&dbdata.Group{Id: g.Id})
		assert.Nil(err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/group/names", nil)

	GroupNames(w, r)

	assert.Equal(http.StatusOK, w.Code)

	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err := json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespSuccess, resp.Code)

	dataMap, ok := resp.Data.(map[string]interface{})
	assert.True(ok)
	count, ok := dataMap["count"].(float64)
	assert.True(ok)
	assert.Equal(float64(0), count)
}

// ========== Group CRUD Tests ==========

func TestGroupCRUD(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	// Create a group
	groupJSON := `{"name":"testgroup","status":1,"bandwidth":100,"client_dns":[{"val":"8.8.8.8"}],"route_include":[{"val":"10.0.0.0/8"}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/group/set", bytes.NewReader([]byte(groupJSON)))
	r.Header.Set("Content-Type", "application/json")
	GroupSet(w, r)
	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err := json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespSuccess, resp.Code, "GroupSet failed: %s", resp.Msg)

	// List groups
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/group/list", nil)
	GroupList(w, r)
	body, _ = io.ReadAll(w.Body)
	err = json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespSuccess, resp.Code)
	dataMap, ok := resp.Data.(map[string]interface{})
	assert.True(ok)
	listCount := dataMap["count"].(float64)
	assert.True(listCount > 0, "expected groups count > 0")

	// Get group detail (id=1 for default "all" group)
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/group/detail?id=1", nil)
	GroupDetail(w, r)
	body, _ = io.ReadAll(w.Body)
	err = json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespSuccess, resp.Code)

	// Get group names
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/group/names", nil)
	GroupNames(w, r)
	body, _ = io.ReadAll(w.Body)
	err = json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespSuccess, resp.Code)
	dataMap, ok = resp.Data.(map[string]interface{})
	assert.True(ok)
	namesCount := dataMap["count"].(float64)
	assert.True(namesCount > 0)

	// Get group names with IDs
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/group/namesids", nil)
	GroupNamesIds(w, r)
	body, _ = io.ReadAll(w.Body)
	err = json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespSuccess, resp.Code)

	// Delete the created group by looking up its actual ID
	var createdGroup dbdata.Group
	err = dbdata.One("Name", "testgroup", &createdGroup)
	assert.Nil(err)
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/group/del?id=%d", createdGroup.Id), nil)
	GroupDel(w, r)
	body, _ = io.ReadAll(w.Body)
	err = json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespSuccess, resp.Code)
}

func TestGroupDetail_InvalidId(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/group/detail?id=0", nil)
	GroupDetail(w, r)
	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err := json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespParamErr, resp.Code)
}

func TestGroupDel_InvalidId(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/group/del?id=0", nil)
	GroupDel(w, r)
	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err := json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespParamErr, resp.Code)
}

// ========== User CRUD Tests ==========

func TestUserCRUD(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()
	base.Cfg.EncryptionPassword = false

	// Create user
	userJSON := `{"username":"testuser","pin_code":"Test@1234","groups":["all"],"status":1}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/user/set", bytes.NewReader([]byte(userJSON)))
	r.Header.Set("Content-Type", "application/json")
	UserSet(w, r)
	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err := json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespSuccess, resp.Code, "UserSet failed: %s", resp.Msg)

	// List users
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/user/list", nil)
	UserList(w, r)
	body, _ = io.ReadAll(w.Body)
	err = json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespSuccess, resp.Code)
	dataMap, ok := resp.Data.(map[string]interface{})
	assert.True(ok)
	userCount := dataMap["count"].(float64)
	assert.True(userCount > 0)

	// Search users with prefix
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/user/list?prefix=test", nil)
	UserList(w, r)
	body, _ = io.ReadAll(w.Body)
	err = json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespSuccess, resp.Code)
	dataMap, ok = resp.Data.(map[string]interface{})
	assert.True(ok)
	searchCount := dataMap["count"].(float64)
	assert.True(searchCount > 0)

	// Delete user by looking up its actual ID
	var createdUser dbdata.User
	err = dbdata.One("Username", "testuser", &createdUser)
	assert.Nil(err)
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/user/del?id=%d", createdUser.Id), nil)
	UserDel(w, r)
	body, _ = io.ReadAll(w.Body)
	err = json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespSuccess, resp.Code)
}

func TestUserDetail_InvalidId(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/user/detail?id=0", nil)
	UserDetail(w, r)
	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err := json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespParamErr, resp.Code)
}

func TestUserDel_InvalidId(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/user/del?id=0", nil)
	UserDel(w, r)
	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err := json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespParamErr, resp.Code)
}

// ========== Policy CRUD Tests ==========

func TestPolicyCRUD(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	// Create policy
	policyJSON := `{"username":"testpolicy","status":1,"client_dns":[{"val":"8.8.8.8"}],"route_include":[{"val":"192.168.0.0/16"}]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/policy/set", bytes.NewReader([]byte(policyJSON)))
	r.Header.Set("Content-Type", "application/json")
	PolicySet(w, r)
	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err := json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespSuccess, resp.Code, "PolicySet failed: %s", resp.Msg)

	// List policies
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/policy/list", nil)
	PolicyList(w, r)
	body, _ = io.ReadAll(w.Body)
	err = json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespSuccess, resp.Code)
	dataMap, ok := resp.Data.(map[string]interface{})
	assert.True(ok)
	policyCount := dataMap["count"].(float64)
	assert.True(policyCount > 0)

	// Get policy detail (id=1)
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/policy/detail?id=1", nil)
	PolicyDetail(w, r)
	body, _ = io.ReadAll(w.Body)
	err = json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespSuccess, resp.Code)

	// Delete policy (id=1)
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/policy/del?id=1", nil)
	PolicyDel(w, r)
	body, _ = io.ReadAll(w.Body)
	err = json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespSuccess, resp.Code)
}

func TestPolicyDetail_InvalidId(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/policy/detail?id=0", nil)
	PolicyDetail(w, r)
	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err := json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespParamErr, resp.Code)
}

func TestPolicyDel_InvalidId(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/policy/del?id=0", nil)
	PolicyDel(w, r)
	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err := json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespParamErr, resp.Code)
}

// ========== Health/Metrics Tests ==========

func TestHealthCheck(t *testing.T) {
	assert := assert.New(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	HealthCheck(w, r)
	assert.Equal(http.StatusOK, w.Code)

	body, _ := io.ReadAll(w.Body)
	var result map[string]interface{}
	err := json.Unmarshal(body, &result)
	assert.Nil(err)
	assert.Equal("ok", result["status"])
}

func TestMetrics(t *testing.T) {
	assert := assert.New(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	Metrics(w, r)
	assert.Equal(http.StatusOK, w.Code)

	body, _ := io.ReadAll(w.Body)
	var result map[string]interface{}
	err := json.Unmarshal(body, &result)
	assert.Nil(err)
	assert.Contains(result, "uptime_seconds")
	assert.Contains(result, "goroutines")
	assert.Contains(result, "online_users")
	assert.Contains(result, "memory_alloc_bytes")
}

func TestPrometheusMetrics(t *testing.T) {
	assert := assert.New(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/prometheus", nil)
	PrometheusMetrics(w, r)
	assert.Equal(http.StatusOK, w.Code)

	body := w.Body.String()
	assert.Contains(body, "anylink_uptime_seconds")
	assert.Contains(body, "anylink_online_users")
	assert.Contains(body, "anylink_goroutines")
	assert.Contains(body, "anylink_memory_alloc_bytes")
}

// ========== SetHome Test ==========

func TestSetHome(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/set/home", nil)
	SetHome(w, r)
	assert.Equal(http.StatusOK, w.Code)

	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err := json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespSuccess, resp.Code)
	dataMap, ok := resp.Data.(map[string]interface{})
	assert.True(ok)
	assert.Contains(dataMap, "counts")
}

// ========== Portal Login Tests ==========

func TestUserPortalLogin_Success(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()
	base.Cfg.JwtSecret = "test_portal_jwt_secret"
	base.Cfg.EncryptionPassword = false

	// Create a user directly in DB
	user := &dbdata.User{
		Username: "portaluser",
		PinCode:  "Portal@123",
		Groups:   []string{"all"},
		Status:   1,
	}
	err := dbdata.SetUser(user)
	assert.Nil(err)

	// Login
	loginJSON := `{"username":"portaluser","password":"Portal@123","group":"all"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/user/portal/login", bytes.NewReader([]byte(loginJSON)))
	r.Header.Set("Content-Type", "application/json")
	UserPortalLogin(w, r)
	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err = json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespSuccess, resp.Code, "portal login failed: %s", resp.Msg)
	dataMap, ok := resp.Data.(map[string]interface{})
	assert.True(ok)
	assert.NotEmpty(dataMap["token"])
}

func TestUserPortalLogin_WrongPassword(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()
	base.Cfg.JwtSecret = "test_portal_jwt_secret"
	base.Cfg.EncryptionPassword = false

	user := &dbdata.User{
		Username: "portaluser2",
		PinCode:  "Portal@123",
		Groups:   []string{"all"},
		Status:   1,
	}
	err := dbdata.SetUser(user)
	assert.Nil(err)

	loginJSON := `{"username":"portaluser2","password":"wrongpassword","group":"all"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/user/portal/login", bytes.NewReader([]byte(loginJSON)))
	r.Header.Set("Content-Type", "application/json")
	UserPortalLogin(w, r)
	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err = json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespUserOrPassErr, resp.Code)
}

func TestUserPortalLogin_NonExistentUser(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()
	base.Cfg.JwtSecret = "test_portal_jwt_secret"

	loginJSON := `{"username":"nonexistent","password":"somepass","group":"all"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/user/portal/login", bytes.NewReader([]byte(loginJSON)))
	r.Header.Set("Content-Type", "application/json")
	UserPortalLogin(w, r)
	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err := json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespUserOrPassErr, resp.Code)
}

// ========== Portal Middleware Tests ==========

func TestPortalAuthMiddleware_NoToken(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	base.Cfg.JwtSecret = "test_portal_middleware_secret"

	handler := portalAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/portal/protected", nil)
	handler.ServeHTTP(w, r)
	assert.Equal(http.StatusUnauthorized, w.Code)
}

func TestPortalAuthMiddleware_ValidToken(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	base.Cfg.JwtSecret = "test_portal_middleware_secret"

	jwtData := map[string]interface{}{"portal_user": "testuser"}
	expiresAt := time.Now().Add(time.Hour).Unix()
	token, err := SetJwtData(jwtData, expiresAt)
	assert.Nil(err)

	handler := portalAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/portal/protected", nil)
	r.Header.Set("Jwt", token)
	handler.ServeHTTP(w, r)
	assert.Equal(http.StatusOK, w.Code)
}

// ========== Portal Password Policy Test ==========

func TestPortalGetPasswordPolicy(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/portal/password_policy", nil)
	UserPortalGetPasswordPolicy(w, r)
	assert.Equal(http.StatusOK, w.Code)

	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err := json.Unmarshal(body, &resp)
	assert.Nil(err)
	assert.Equal(RespSuccess, resp.Code)
}

// parseResp is a helper to parse JSON response
func parseResp(t *testing.T, w *httptest.ResponseRecorder) Resp {
	body, _ := io.ReadAll(w.Body)
	var resp Resp
	err := json.Unmarshal(body, &resp)
	assert.Nil(t, err)
	return resp
}

// ========== Settings Tests ==========

func TestSetOtherSmtp(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/set/other/smtp", nil)
	SetOtherSmtp(w, r)
	assert.Equal(http.StatusOK, w.Code)

	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

func TestSetPasswordPolicy(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	// Read current policy
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/set/password_policy", nil)
	SetPasswordPolicy(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)

	// Edit policy
	policyJSON := `{"min_length":10,"max_length":64,"require_upper":true,"require_lower":true,"require_digit":true,"require_spec":false}`
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/set/password_policy/edit", bytes.NewReader([]byte(policyJSON)))
	r.Header.Set("Content-Type", "application/json")
	SetPasswordPolicyEdit(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp = parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)

	// Read again and verify min_length was updated
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/set/password_policy", nil)
	SetPasswordPolicy(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp = parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
	dataMap, ok := resp.Data.(map[string]interface{})
	assert.True(ok)
	assert.Equal(float64(10), dataMap["min_length"])
}

func TestSetPasswordPolicyEdit_InvalidRange(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	policyJSON := `{"min_length":100,"max_length":10}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/set/password_policy/edit", bytes.NewReader([]byte(policyJSON)))
	r.Header.Set("Content-Type", "application/json")
	SetPasswordPolicyEdit(w, r)

	resp := parseResp(t, w)
	assert.Equal(RespParamErr, resp.Code)
}

func TestSetOtherAuditLog(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/set/other/audit_log", nil)
	SetOtherAuditLog(w, r)
	assert.Equal(http.StatusOK, w.Code)

	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

func TestSetOtherAuditLogEdit_InvalidLifeDay(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	body := `{"life_day":999,"clear_time":"3:00"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/set/other/audit_log/edit", bytes.NewReader([]byte(body)))
	r.Header.Set("Content-Type", "application/json")
	SetOtherAuditLogEdit(w, r)

	resp := parseResp(t, w)
	assert.Equal(RespParamErr, resp.Code)
}

func TestSetOtherAuditLogEdit_InvalidClearTime(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	body := `{"life_day":30,"clear_time":"25:00"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/set/other/audit_log/edit", bytes.NewReader([]byte(body)))
	r.Header.Set("Content-Type", "application/json")
	SetOtherAuditLogEdit(w, r)

	resp := parseResp(t, w)
	assert.Equal(RespParamErr, resp.Code)
}

// ========== Portal Password Change Tests ==========

func TestUserPortalChangePassword_Success(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()
	base.Cfg.EncryptionPassword = false

	user := &dbdata.User{
		Username:   "pwduser",
		PinCode:    "OldPass@123",
		Groups:     []string{"all"},
		Status:     1,
		DisableOtp: true,
	}
	err := dbdata.SetUser(user)
	assert.Nil(err)

	body := `{"old_password":"OldPass@123","new_password":"NewPass@456"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/portal/change_password", bytes.NewReader([]byte(body)))
	r.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(r.Context(), portalUserKey, "pwduser")
	r = r.WithContext(ctx)
	UserPortalChangePassword(w, r)

	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

func TestUserPortalChangePassword_WrongOld(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()
	base.Cfg.EncryptionPassword = false

	user := &dbdata.User{
		Username:   "pwduser2",
		PinCode:    "Correct@123",
		Groups:     []string{"all"},
		Status:     1,
		DisableOtp: true,
	}
	err := dbdata.SetUser(user)
	assert.Nil(err)

	body := `{"old_password":"Wrong@123","new_password":"NewPass@456"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/portal/change_password", bytes.NewReader([]byte(body)))
	r.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(r.Context(), portalUserKey, "pwduser2")
	r = r.WithContext(ctx)
	UserPortalChangePassword(w, r)

	resp := parseResp(t, w)
	assert.Equal(RespUserOrPassErr, resp.Code)
}

func TestUserPortalChangePassword_EmptyFields(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	body := `{"old_password":"","new_password":""}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/portal/change_password", bytes.NewReader([]byte(body)))
	r.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(r.Context(), portalUserKey, "someuser")
	r = r.WithContext(ctx)
	UserPortalChangePassword(w, r)

	resp := parseResp(t, w)
	assert.Equal(RespParamErr, resp.Code)
}

// ========== Portal Profile Tests ==========

func TestUserPortalProfile(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()
	base.Cfg.EncryptionPassword = false

	user := &dbdata.User{
		Username:   "profileuser",
		PinCode:    "Profile@123",
		Groups:     []string{"all"},
		Status:     1,
		DisableOtp: true,
	}
	err := dbdata.SetUser(user)
	assert.Nil(err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/portal/profile", nil)
	ctx := context.WithValue(r.Context(), portalUserKey, "profileuser")
	r = r.WithContext(ctx)
	UserPortalProfile(w, r)
	assert.Equal(http.StatusOK, w.Code)

	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
	dataMap, ok := resp.Data.(map[string]interface{})
	assert.True(ok)
	assert.Equal("profileuser", dataMap["username"])
}

// ========== Portal OTP Tests ==========

func TestUserPortalGetOtpStatus(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()
	base.Cfg.EncryptionPassword = false

	user := &dbdata.User{
		Username:   "otpuser",
		PinCode:    "OtpUser@123",
		Groups:     []string{"all"},
		Status:     1,
		DisableOtp: true,
	}
	err := dbdata.SetUser(user)
	assert.Nil(err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/portal/otp_status", nil)
	ctx := context.WithValue(r.Context(), portalUserKey, "otpuser")
	r = r.WithContext(ctx)
	UserPortalGetOtpStatus(w, r)
	assert.Equal(http.StatusOK, w.Code)

	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

// ========== LockManager Tests ==========

func TestGetLockManager(t *testing.T) {
	assert := assert.New(t)
	lm1 := GetLockManager()
	lm2 := GetLockManager()
	assert.NotNil(lm1)
	assert.True(lm1 == lm2, "GetLockManager should return the same singleton instance")
}

func TestGetLocksInfo_Empty(t *testing.T) {
	assert := assert.New(t)
	base.Test()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/lockmanager/locksinfo", nil)
	GetLocksInfo(w, r)
	assert.Equal(http.StatusOK, w.Code)

	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

func TestLockManager_CheckLocked(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	lm := GetLockManager()
	base.Cfg.AntiBruteForce = true
	base.Cfg.MaxBanCount = 3
	base.Cfg.BanResetTime = 60
	base.Cfg.LockTime = 300

	// Not locked yet, should return true (allowed)
	result := lm.CheckLocked("testuser", "1.2.3.4:443")
	assert.True(result, "User should not be locked initially")

	// Simulate failed login attempts to trigger lock
	lm.UpdateLoginStatus("testuser", "1.2.3.4:443", false)
	lm.UpdateLoginStatus("testuser", "1.2.3.4:443", false)
	lm.UpdateLoginStatus("testuser", "1.2.3.4:443", false)
}

func TestUnlockUser_NilState(t *testing.T) {
	assert := assert.New(t)
	base.Test()

	body := `{"description":"test","username":"nobody","ip":"1.2.3.4"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/lockmanager/unlock", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	UnlockUser(w, r)
	assert.Equal(http.StatusOK, w.Code)

	resp := parseResp(t, w)
	assert.Equal(RespInternalErr, resp.Code)
	assert.Contains(resp.Msg, "未找到锁定用户")
}

// ========== Audit API Tests ==========

func TestSetAuditList(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/audit/list", nil)
	SetAuditList(w, r)
	assert.Equal(http.StatusOK, w.Code)

	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

func TestUserActLogList(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/user/act/log/list", nil)
	UserActLogList(w, r)
	assert.Equal(http.StatusOK, w.Code)

	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

// ========== More Portal Tests ==========

func TestUserPortalLoginHistory(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()
	base.Cfg.EncryptionPassword = false

	user := &dbdata.User{
		Username: "historyuser",
		PinCode:  "History@123",
		Groups:   []string{"all"},
		Status:   1,
	}
	err := dbdata.SetUser(user)
	assert.Nil(err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/portal/login_history", nil)
	ctx := context.WithValue(r.Context(), portalUserKey, "historyuser")
	r = r.WithContext(ctx)
	UserPortalLoginHistory(w, r)
	assert.Equal(http.StatusOK, w.Code)

	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

func TestUserPortalActiveSessions(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()
	base.Cfg.EncryptionPassword = false

	user := &dbdata.User{
		Username: "sessionuser",
		PinCode:  "Session@123",
		Groups:   []string{"all"},
		Status:   1,
	}
	err := dbdata.SetUser(user)
	assert.Nil(err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/portal/active_sessions", nil)
	ctx := context.WithValue(r.Context(), portalUserKey, "sessionuser")
	r = r.WithContext(ctx)
	UserPortalActiveSessions(w, r)
	assert.Equal(http.StatusOK, w.Code)

	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

func TestUserPortalGetRoutes(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()
	base.Cfg.EncryptionPassword = false

	user := &dbdata.User{
		Username: "routeuser",
		PinCode:  "Route@123",
		Groups:   []string{"all"},
		Status:   1,
	}
	err := dbdata.SetUser(user)
	assert.Nil(err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/portal/routes", nil)
	ctx := context.WithValue(r.Context(), portalUserKey, "routeuser")
	r = r.WithContext(ctx)
	UserPortalGetRoutes(w, r)
	assert.Equal(http.StatusOK, w.Code)

	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

func TestUserPortalBandwidthStats(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()
	base.Cfg.EncryptionPassword = false

	user := &dbdata.User{
		Username: "bwuser",
		PinCode:  "Bandwidth@123",
		Groups:   []string{"all"},
		Status:   1,
	}
	err := dbdata.SetUser(user)
	assert.Nil(err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/portal/bandwidth_stats", nil)
	ctx := context.WithValue(r.Context(), portalUserKey, "bwuser")
	r = r.WithContext(ctx)
	UserPortalBandwidthStats(w, r)
	assert.Equal(http.StatusOK, w.Code)

	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

func TestUserPortalDisconnectSession_EmptyToken(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()
	base.Cfg.EncryptionPassword = false

	user := &dbdata.User{
		Username: "disconnuser",
		PinCode:  "Disconn@123",
		Groups:   []string{"all"},
		Status:   1,
	}
	err := dbdata.SetUser(user)
	assert.Nil(err)

	body := `{"token":""}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/portal/disconnect_session", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(r.Context(), portalUserKey, "disconnuser")
	r = r.WithContext(ctx)
	UserPortalDisconnectSession(w, r)
	assert.Equal(http.StatusOK, w.Code)

	resp := parseResp(t, w)
	assert.Equal(RespParamErr, resp.Code)
}

// ========== Middleware Tests ==========

func TestLimitBodyMiddleware(t *testing.T) {
	assert := assert.New(t)
	base.Test()

	called := false
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	})
	wrapped := limitBodyMiddleware(innerHandler)

	smallBody := strings.Repeat("a", 100)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(smallBody))
	wrapped.ServeHTTP(w, r)
	assert.True(called, "inner handler should be called")
	assert.Equal(http.StatusOK, w.Code)
}

func TestRecoverHttp(t *testing.T) {
	assert := assert.New(t)
	base.Test()

	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})
	wrapped := recoverHttp(panicHandler)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)
	wrapped.ServeHTTP(w, r)
	assert.Equal(http.StatusOK, w.Code)

	resp := parseResp(t, w)
	assert.Equal(500, resp.Code)
}

// ========== Portal Bind OTP Tests ==========

func TestUserPortalBindOtp(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()
	base.Cfg.EncryptionPassword = false

	user := &dbdata.User{
		Username:   "bindotpuser",
		PinCode:    "BindOtp@123",
		Groups:     []string{"all"},
		Status:     1,
		DisableOtp: true,
	}
	err := dbdata.SetUser(user)
	assert.Nil(err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/portal/bind_otp", nil)
	ctx := context.WithValue(r.Context(), portalUserKey, "bindotpuser")
	r = r.WithContext(ctx)
	UserPortalBindOtp(w, r)
	assert.Equal(http.StatusOK, w.Code)

	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
	dataMap, ok := resp.Data.(map[string]interface{})
	assert.True(ok)
	assert.Contains(dataMap, "qr_code")
	assert.Contains(dataMap, "secret")
}

func TestUserPortalResetOtp_WrongPassword(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()
	base.Cfg.EncryptionPassword = false

	user := &dbdata.User{
		Username: "resetotpuser",
		PinCode:  "Pass@123",
		Groups:   []string{"all"},
		Status:   1,
	}
	err := dbdata.SetUser(user)
	assert.Nil(err)

	body := `{"password":"WrongPass"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/portal/reset_otp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(r.Context(), portalUserKey, "resetotpuser")
	r = r.WithContext(ctx)
	UserPortalResetOtp(w, r)
	assert.Equal(http.StatusOK, w.Code)

	resp := parseResp(t, w)
	assert.Equal(RespUserOrPassErr, resp.Code)
}

// ========== IP Map Tests ==========

func TestUserIpMapCRUD(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	// Create
	ipMap := dbdata.IpMap{IpAddr: "192.168.1.100", MacAddr: "00:11:22:33:44:55", Username: "testuser"}
	body, _ := json.Marshal(ipMap)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/ip_map/set", bytes.NewReader(body))
	UserIpMapSet(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)

	// List
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/ip_map/list?page=1", nil)
	UserIpMapList(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp = parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
	dataMap := resp.Data.(map[string]interface{})
	assert.Equal(float64(1), dataMap["count"].(float64))

	// Detail
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/ip_map/detail?id=1", nil)
	UserIpMapDetail(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp = parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)

	// Delete
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/ip_map/del?id=1", nil)
	UserIpMapDel(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp = parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)

	// Verify deleted
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/ip_map/list?page=1", nil)
	UserIpMapList(w, r)
	resp = parseResp(t, w)
	dataMap = resp.Data.(map[string]interface{})
	assert.Equal(float64(0), dataMap["count"].(float64))
}

func TestUserIpMapList_DefaultPage(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/ip_map/list", nil)
	UserIpMapList(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

func TestUserIpMapDetail_InvalidId(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/ip_map/detail?id=0", nil)
	UserIpMapDetail(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespParamErr, resp.Code)
}

func TestUserIpMapDetail_NotFound(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/ip_map/detail?id=999", nil)
	UserIpMapDetail(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespInternalErr, resp.Code)
}

func TestUserIpMapDel_InvalidId(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/ip_map/del?id=0", nil)
	UserIpMapDel(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespParamErr, resp.Code)
}

func TestUserIpMapDel_NotFound(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/ip_map/del?id=999", nil)
	UserIpMapDel(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespInternalErr, resp.Code)
}

func TestUserIpMapSet_InvalidBody(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/ip_map/set", strings.NewReader("not json"))
	UserIpMapSet(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespInternalErr, resp.Code)
}

func TestUserIpMapSet_ValidationError(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	ipMap := dbdata.IpMap{IpAddr: "1", MacAddr: "ab"}
	body, _ := json.Marshal(ipMap)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/ip_map/set", bytes.NewReader(body))
	UserIpMapSet(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespInternalErr, resp.Code)
}

// ========== StatsInfo Tests ==========

func TestStatsInfoList_InvalidAction(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/statsinfo/list?action=invalid&scope=rt", nil)
	StatsInfoList(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespParamErr, resp.Code)
}

func TestStatsInfoList_InvalidScope(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/statsinfo/list?action=online&scope=invalid", nil)
	StatsInfoList(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespParamErr, resp.Code)
}

func TestStatsInfoList_Valid(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/statsinfo/list?action=online&scope=rt", nil)
	StatsInfoList(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

// ========== SetSoft and decimal Tests ==========

func TestSetSoft(t *testing.T) {
	assert := assert.New(t)
	base.Test()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/set/soft", nil)
	SetSoft(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
	assert.NotNil(resp.Data)
}

func TestDecimal(t *testing.T) {
	assert := assert.New(t)
	assert.Equal(1.23, decimal(1.2345))
	assert.Equal(0.0, decimal(0.0))
	assert.Equal(99.99, decimal(99.999))
	assert.Equal(-1.23, decimal(-1.2399))
}

// ========== Settings Tests ==========

func TestSetOther(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/set/other", nil)
	SetOther(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

func TestSetOtherEdit(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	data := dbdata.SettingOther{LinkAddr: "https://example.com", Banner: "test banner"}
	body, _ := json.Marshal(data)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/set/other/edit", bytes.NewReader(body))
	SetOtherEdit(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)

	// Verify saved
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/set/other", nil)
	SetOther(w, r)
	resp = parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

func TestSetOtherEdit_InvalidBody(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/set/other/edit", strings.NewReader("bad json"))
	SetOtherEdit(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespInternalErr, resp.Code)
}

func TestSetOtherSmtpEdit(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	data := dbdata.SettingSmtp{Host: "smtp.example.com", Port: 587, Username: "user@example.com", Password: "secret"}
	body, _ := json.Marshal(data)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/set/other/smtp/edit", bytes.NewReader(body))
	SetOtherSmtpEdit(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

func TestSetOtherSmtpEdit_EmptyPassword(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	// First set with password
	data := dbdata.SettingSmtp{Host: "smtp.example.com", Port: 587, Password: "secret123"}
	body, _ := json.Marshal(data)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/set/other/smtp/edit", bytes.NewReader(body))
	SetOtherSmtpEdit(w, r)
	assert.Equal(RespSuccess, parseResp(t, w).Code)

	// Edit with empty password (should preserve old)
	data2 := dbdata.SettingSmtp{Host: "smtp2.example.com", Port: 465, Password: ""}
	body2, _ := json.Marshal(data2)
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/set/other/smtp/edit", bytes.NewReader(body2))
	SetOtherSmtpEdit(w, r)
	assert.Equal(RespSuccess, parseResp(t, w).Code)
}

func TestSetOtherSmtp_Get(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/set/other/smtp", nil)
	SetOtherSmtp(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

// ========== GroupAuthLogin Tests ==========

func TestGroupAuthLogin_InvalidBody(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/group/auth/login", strings.NewReader("bad json"))
	GroupAuthLogin(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespInternalErr, resp.Code)
}

func TestGroupAuthLogin_UnknownAuthType(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	data := map[string]interface{}{
		"name": "testuser",
		"pwd":  "testpwd",
		"auth": map[string]interface{}{"type": "unknown_auth"},
	}
	body, _ := json.Marshal(data)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/group/auth/login", bytes.NewReader(body))
	GroupAuthLogin(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespInternalErr, resp.Code)
}

func TestGroupAuthLogin_LocalAuth(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	data := map[string]interface{}{
		"name": "testuser",
		"pwd":  "testpwd",
		"auth": map[string]interface{}{"type": "local"},
	}
	body, _ := json.Marshal(data)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/group/auth/login", bytes.NewReader(body))
	GroupAuthLogin(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespInternalErr, resp.Code)
}

// ========== Audit Tests ==========

func TestSetAuditExport_Empty(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/set/audit/export", nil)
	SetAuditExport(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespParamErr, resp.Code)
}

// ========== Online/Offline/Reline Tests ==========

func TestUserOnline_Empty(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/user/online?search_cate=username&search_text=&show_sleeper=false", nil)
	UserOnline(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
	dataMap := resp.Data.(map[string]interface{})
	assert.Equal(float64(0), dataMap["count"].(float64))
}

func TestUserOffline_NonExistentToken(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/user/offline?token=nonexistent", nil)
	UserOffline(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

func TestUserReline_NonExistentToken(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/user/reline?token=nonexistent", nil)
	UserReline(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

// ========== AuditLog Settings Tests ==========

func TestSetOtherAuditLogEdit_ValidData(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	data := map[string]interface{}{"life_day": 30, "clear_time": "3:00"}
	body, _ := json.Marshal(data)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/set/other/audit_log/edit", bytes.NewReader(body))
	SetOtherAuditLogEdit(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

func TestSetOtherAuditLogEdit_InvalidBody(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/set/other/audit_log/edit", strings.NewReader("bad"))
	SetOtherAuditLogEdit(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespInternalErr, resp.Code)
}

// ========== Password Policy Tests ==========

func TestSetPasswordPolicyEdit_ValidData(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	data := map[string]interface{}{"min_length": 8, "max_length": 64, "require_uppercase": true}
	body, _ := json.Marshal(data)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/set/password_policy/edit", bytes.NewReader(body))
	SetPasswordPolicyEdit(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

func TestSetPasswordPolicyEdit_MinGreaterThanMax(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	data := map[string]interface{}{"min_length": 100, "max_length": 10}
	body, _ := json.Marshal(data)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/set/password_policy/edit", bytes.NewReader(body))
	SetPasswordPolicyEdit(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespParamErr, resp.Code)
}

func TestSetPasswordPolicyEdit_InvalidBody(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/set/password_policy/edit", strings.NewReader("bad"))
	SetPasswordPolicyEdit(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespInternalErr, resp.Code)
}

// ========== SetSystem Test ==========

func TestSetSystem(t *testing.T) {
	assert := assert.New(t)
	base.Test()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/set/system", nil)
	SetSystem(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
	dataMap := resp.Data.(map[string]interface{})
	assert.Contains(dataMap, "mem")
	assert.Contains(dataMap, "disk")
	assert.Contains(dataMap, "cpu")
	assert.Contains(dataMap, "sys")
}

// ========== PolicySet Tests ==========

func TestPolicySet_InvalidBody(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/policy/set", strings.NewReader("bad json"))
	PolicySet(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespInternalErr, resp.Code)
}

func TestPolicySet_Valid(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	policy := dbdata.Policy{Username: "policyuser", Status: 1}
	body, _ := json.Marshal(policy)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/policy/set", bytes.NewReader(body))
	PolicySet(w, r)
	assert.Equal(http.StatusOK, w.Code)
}

// ========== LockManager Tests ==========

func TestCheckGlobalIPLock_NotLocked(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	lm := GetLockManager()
	locked := lm.CheckGlobalIPLock("10.0.0.1", time.Now())
	assert.False(locked)
}

func TestCheckGlobalUserLock_NotLocked(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	lm := GetLockManager()
	locked := lm.CheckGlobalUserLock("nonexistent", time.Now())
	assert.False(locked)
}

func TestCheckGlobalUserLock_EmptyUsername(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	lm := GetLockManager()
	locked := lm.CheckGlobalUserLock("", time.Now())
	assert.False(locked)
}

func TestCheckLockState_NilState(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	lm := GetLockManager()
	locked := lm.CheckLockState(nil, time.Now(), 300)
	assert.False(locked)
}

func TestCheckLockState_Locked(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	lm := GetLockManager()

	state := &LockState{
		Locked:       true,
		FailureCount: 5,
		LastAttempt:  time.Now(),
		LockTime:     time.Now().Add(10 * time.Minute),
	}
	locked := lm.CheckLockState(state, time.Now(), 300)
	assert.True(locked)
}

func TestCheckLockState_Expired(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	lm := GetLockManager()

	state := &LockState{
		Locked:       true,
		FailureCount: 5,
		LastAttempt:  time.Now().Add(-10 * time.Minute),
		LockTime:     time.Now().Add(-1 * time.Minute),
	}
	locked := lm.CheckLockState(state, time.Now(), 300)
	assert.False(locked)
}

func TestCheckLockState_WindowExpired(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	lm := GetLockManager()

	state := &LockState{
		Locked:       false,
		FailureCount: 3,
		LastAttempt:  time.Now().Add(-10 * time.Minute),
	}
	locked := lm.CheckLockState(state, time.Now(), 60)
	assert.False(locked)
	assert.Equal(0, state.FailureCount)
}

// ========== RespData Test ==========

func TestRespData(t *testing.T) {
	assert := assert.New(t)
	w := httptest.NewRecorder()
	RespData(w, map[string]string{"key": "value"}, nil)
	assert.Equal(http.StatusOK, w.Code)
}

// ========== checkResetRateLimit Tests ==========

func TestCheckResetRateLimit(t *testing.T) {
	assert := assert.New(t)
	base.Test()

	ok := checkResetRateLimit("192.168.99.1")
	assert.True(ok)

	ok = checkResetRateLimit("192.168.99.1")
	assert.True(ok)
}

// ========== GetCertSetting Test ==========

func TestGetCertSetting(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/cert/setting", nil)
	GetCertSetting(w, r)
	assert.Equal(http.StatusOK, w.Code)
}

// ========== UserOtpQr Test ==========

func TestUserOtpQr_InvalidId(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/user/otp_qr?id=999&b64=0", nil)
	UserOtpQr(w, r)
	assert.Equal(http.StatusOK, w.Code)
}

func TestUserOtpQr_B64Mode(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/user/otp_qr?id=999&b64=1", nil)
	UserOtpQr(w, r)
	assert.Equal(http.StatusOK, w.Code)
}

func TestPolicySet_EmptyUsername(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	policy := dbdata.Policy{Username: "", Status: 1}
	body, _ := json.Marshal(policy)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/policy/set", bytes.NewReader(body))
	PolicySet(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespInternalErr, resp.Code)
}

func TestSetAuditList_WithSearch(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	search := `{"username":"test","sort":1}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/set/audit/list?page=1&search="+url.QueryEscape(search), nil)
	SetAuditList(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespSuccess, resp.Code)
}

func TestSetAuditExport_WithSearch(t *testing.T) {
	assert := assert.New(t)
	base.Test()
	cleanup := setupTestDB(t)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/set/audit/export?search="+url.QueryEscape(`{"username":"nobody"}`), nil)
	SetAuditExport(w, r)
	assert.Equal(http.StatusOK, w.Code)
	resp := parseResp(t, w)
	assert.Equal(RespParamErr, resp.Code)
}

// ========== CleanupExpiredLocks Test ==========

func TestCleanupExpiredLocks(t *testing.T) {
	base.Test()
	base.Cfg.GlobalLockStateExpirationTime = 1
	base.Cfg.GlobalIPBanResetTime = 1
	base.Cfg.GlobalUserBanResetTime = 1
	base.Cfg.BanResetTime = 1
	lm := GetLockManager()
	lm.CleanupExpiredLocks()
}

// ========== InitLockManager Test ==========

func TestInitLockManager_Disabled(t *testing.T) {
	base.Test()
	base.Cfg.AntiBruteForce = false
	InitLockManager()
}

// ========== InitIPWhitelist Test ==========

func TestInitIPWhitelist_Empty(t *testing.T) {
	base.Test()
	base.Cfg.IPWhitelist = ""
	lm := GetLockManager()
	lm.InitIPWhitelist()
}

// ========== location Test ==========

func TestLocation(t *testing.T) {
	assert := assert.New(t)
	handler := location("/test")
	assert.NotNil(handler)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	handler(w, r)
	assert.Equal(http.StatusFound, w.Code)
	assert.Equal("/test", w.Header().Get("Location"))
}
