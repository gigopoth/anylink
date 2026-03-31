package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
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

	// Tamper with the token by modifying a character in the signature
	tampered := []byte(token)
	lastIdx := len(tampered) - 1
	if tampered[lastIdx] == 'a' {
		tampered[lastIdx] = 'b'
	} else {
		tampered[lastIdx] = 'a'
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
