package Plugins

import (
	"database/sql"
	"fmt"
	"github.com/AgonySec/fscan/Configs"
	_ "github.com/sijms/go-ora/v2"
	"strings"
	"time"
)

func OracleScan(info *Configs.HostInfo) (tmperr error) {
	if Configs.IsBrute {
		return
	}
	starttime := time.Now().Unix()
	for _, user := range Configs.Userdict["oracle"] {
		for _, pass := range Configs.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := OracleConn(info, user, pass)
			if flag == true && err == nil {
				return err
			} else {
				errlog := fmt.Sprintf("[-] oracle %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
				Configs.LogError(errlog)
				tmperr = err
				if Configs.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(Configs.Userdict["oracle"])*len(Configs.Passwords)) * Configs.Timeout) {
					return err
				}
			}
		}
	}
	return tmperr
}

func OracleConn(info *Configs.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	dataSourceName := fmt.Sprintf("oracle://%s:%s@%s:%s/orcl", Username, Password, Host, Port)
	db, err := sql.Open("oracle", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(Configs.Timeout) * time.Second)
		db.SetConnMaxIdleTime(time.Duration(Configs.Timeout) * time.Second)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("[+] oracle %v:%v:%v %v", Host, Port, Username, Password)
			Configs.LogSuccess(result)
			flag = true
		}
	}
	return flag, err
}
