package Plugins

import (
	"database/sql"
	"fmt"
	"github.com/AgonySec/fscan/Configs"
	_ "github.com/denisenkom/go-mssqldb"
	"strings"
	"time"
)

func MssqlScan(info *Configs.HostInfo) (tmperr error) {
	if Configs.IsBrute {
		return
	}
	starttime := time.Now().Unix()
	for _, user := range Configs.Userdict["mssql"] {
		for _, pass := range Configs.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := MssqlConn(info, user, pass)
			if flag == true && err == nil {
				return err
			} else {
				errlog := fmt.Sprintf("[-] mssql %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
				Configs.LogError(errlog)
				tmperr = err
				if Configs.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(Configs.Userdict["mssql"])*len(Configs.Passwords)) * Configs.Timeout) {
					return err
				}
			}
		}
	}
	return tmperr
}

func MssqlConn(info *Configs.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	dataSourceName := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%v;encrypt=disable;timeout=%v", Host, Username, Password, Port, time.Duration(Configs.Timeout)*time.Second)
	db, err := sql.Open("mssql", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(Configs.Timeout) * time.Second)
		db.SetConnMaxIdleTime(time.Duration(Configs.Timeout) * time.Second)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("[+] mssql %v:%v:%v %v", Host, Port, Username, Password)
			Configs.LogSuccess(result)
			flag = true
		}
	}
	return flag, err
}
