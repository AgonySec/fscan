package Plugins

import (
	"database/sql"
	"fmt"
	"github.com/itchen-2002/fscan/Config"
	_ "github.com/lib/pq"
	"strings"
	"time"
)

func PostgresScan(info *Config.HostInfo) (tmperr error) {
	if Config.IsBrute {
		return
	}
	starttime := time.Now().Unix()
	for _, user := range Config.Userdict["postgresql"] {
		for _, pass := range Config.Passwords {
			pass = strings.Replace(pass, "{user}", string(user), -1)
			flag, err := PostgresConn(info, user, pass)
			if flag == true && err == nil {
				return err
			} else {
				errlog := fmt.Sprintf("[-] psql %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
				Config.LogError(errlog)
				tmperr = err
				if Config.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(Config.Userdict["postgresql"])*len(Config.Passwords)) * Config.Timeout) {
					return err
				}
			}
		}
	}
	return tmperr
}

func PostgresConn(info *Config.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	dataSourceName := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=%v", Username, Password, Host, Port, "postgres", "disable")
	db, err := sql.Open("postgres", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(Config.Timeout) * time.Second)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("[+] Postgres:%v:%v:%v %v", Host, Port, Username, Password)
			Config.LogSuccess(result)
			flag = true
		}
	}
	return flag, err
}
