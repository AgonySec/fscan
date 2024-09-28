package Plugins

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/itchen-2002/fscan/Config"
	"strings"
	"time"
)

func MysqlScan(info *Config.HostInfo) (tmperr error) {
	if Config.IsBrute {
		return
	}
	starttime := time.Now().Unix()
	for _, user := range Config.Userdict["mysql"] {
		for _, pass := range Config.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := MysqlConn(info, user, pass)
			if flag == true && err == nil {
				return err
			} else {
				errlog := fmt.Sprintf("[-] mysql %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
				Config.LogError(errlog)
				tmperr = err
				if Config.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(Config.Userdict["mysql"])*len(Config.Passwords)) * Config.Timeout) {
					return err
				}
			}
		}
	}
	return tmperr
}

func MysqlConn(info *Config.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	dataSourceName := fmt.Sprintf("%v:%v@tcp(%v:%v)/mysql?charset=utf8&timeout=%v", Username, Password, Host, Port, time.Duration(Config.Timeout)*time.Second)
	db, err := sql.Open("mysql", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(Config.Timeout) * time.Second)
		db.SetConnMaxIdleTime(time.Duration(Config.Timeout) * time.Second)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("[+] mysql %v:%v:%v %v", Host, Port, Username, Password)
			Config.LogSuccess(result)
			flag = true
		}
	}
	return flag, err
}
