package Plugins

import (
	"fmt"
	"github.com/itchen-2002/fscan/Config"
	"github.com/jlaffaye/ftp"
	"strings"
	"time"
)

func FtpScan(info *Config.HostInfo) (tmperr error) {
	if Config.IsBrute {
		return
	}
	starttime := time.Now().Unix()
	flag, err := FtpConn(info, "anonymous", "")
	if flag && err == nil {
		return err
	} else {
		errlog := fmt.Sprintf("[-] ftp %v:%v %v %v", info.Host, info.Ports, "anonymous", err)
		Config.LogError(errlog)
		tmperr = err
		if Config.CheckErrs(err) {
			return err
		}
	}

	for _, user := range Config.Userdict["ftp"] {
		for _, pass := range Config.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := FtpConn(info, user, pass)
			if flag && err == nil {
				return err
			} else {
				errlog := fmt.Sprintf("[-] ftp %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
				Config.LogError(errlog)
				tmperr = err
				if Config.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(Config.Userdict["ftp"])*len(Config.Passwords)) * Config.Timeout) {
					return err
				}
			}
		}
	}
	return tmperr
}

func FtpConn(info *Config.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	conn, err := ftp.DialTimeout(fmt.Sprintf("%v:%v", Host, Port), time.Duration(Config.Timeout)*time.Second)
	if err == nil {
		err = conn.Login(Username, Password)
		if err == nil {
			flag = true
			result := fmt.Sprintf("[+] ftp %v:%v:%v %v", Host, Port, Username, Password)
			dirs, err := conn.List("")
			//defer conn.Logout()
			if err == nil {
				if len(dirs) > 0 {
					for i := 0; i < len(dirs); i++ {
						if len(dirs[i].Name) > 50 {
							result += "\n   [->]" + dirs[i].Name[:50]
						} else {
							result += "\n   [->]" + dirs[i].Name
						}
						if i == 5 {
							break
						}
					}
				}
			}
			Config.LogSuccess(result)
		}
	}
	return flag, err
}
