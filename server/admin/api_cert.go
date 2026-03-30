package admin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/bjdgyc/anylink/base"
	"github.com/bjdgyc/anylink/dbdata"
)

func CustomCert(w http.ResponseWriter, r *http.Request) {
	// 限制证书上传总大小为 1MB
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	cert, _, err := r.FormFile("cert")
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	key, _, err := r.FormFile("key")
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	certFile, err := os.OpenFile(base.Cfg.CertFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600)
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	defer certFile.Close()
	if _, err := io.Copy(certFile, io.LimitReader(cert, 1<<20)); err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	keyFile, err := os.OpenFile(base.Cfg.CertKey, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600)
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	defer keyFile.Close()
	if _, err := io.Copy(keyFile, io.LimitReader(key, 1<<20)); err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	if tlscert, _, err := dbdata.ParseCert(); err != nil {
		RespError(w, RespInternalErr, fmt.Sprintf("证书不合法，请重新上传:%v", err))
		return
	} else {
		dbdata.LoadCertificate(tlscert)
	}
	RespSucess(w, "上传成功")
}
func GetCertSetting(w http.ResponseWriter, r *http.Request) {
	sess := dbdata.GetXdb().NewSession()
	defer sess.Close()
	data := &dbdata.SettingLetsEncrypt{}
	if err := dbdata.SettingGet(data); err != nil {
		dbdata.SettingSessAdd(sess, data)
		RespError(w, RespInternalErr, err)
	}
	userData := &dbdata.LegoUserData{}
	if err := dbdata.SettingGet(userData); err != nil {
		dbdata.SettingSessAdd(sess, userData)
	}
	RespSucess(w, data)
}
func CreatCert(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// 限制请求体大小为 1MB，防止内存耗尽攻击
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	defer r.Body.Close()
	config := &dbdata.SettingLetsEncrypt{}
	if err := json.Unmarshal(body, config); err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	if err := dbdata.SettingSet(config); err != nil {
		RespError(w, RespInternalErr, err)
		return
	}
	client := dbdata.LeGoClient{}
	if err := client.NewClient(config); err != nil {
		base.Error(err)
		RespError(w, RespInternalErr, fmt.Sprintf("获取证书失败:%v", err))
		return
	}
	if err := client.GetCert(config.Domain); err != nil {
		base.Error(err)
		RespError(w, RespInternalErr, fmt.Sprintf("获取证书失败:%v", err))
		return
	}
	RespSucess(w, "生成证书成功")
}
