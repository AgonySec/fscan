package Plugins

import (
	"errors"
	"fmt"
	"github.com/itchen-2002/fscan/Config"
	"github.com/stacktitan/smb/smb"
	"strings"
	"time"
)

func SmbScan(info *Config.HostInfo) (tmperr error) {
	if Config.IsBrute {
		return nil
	}
	starttime := time.Now().Unix()
	for _, user := range Config.Userdict["smb"] {
		for _, pass := range Config.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := doWithTimeOut(info, user, pass)
			if flag == true && err == nil {
				var result string
				if Config.Domain != "" {
					result = fmt.Sprintf("[+] SMB %v:%v:%v\\%v %v", info.Host, info.Ports, Config.Domain, user, pass)
				} else {
					result = fmt.Sprintf("[+] SMB %v:%v:%v %v", info.Host, info.Ports, user, pass)
				}
				Config.LogSuccess(result)
				return err
			} else {
				errlog := fmt.Sprintf("[-] smb %v:%v %v %v %v", info.Host, 445, user, pass, err)
				errlog = strings.Replace(errlog, "\n", "", -1)
				Config.LogError(errlog)
				tmperr = err
				if Config.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(Config.Userdict["smb"])*len(Config.Passwords)) * Config.Timeout) {
					return err
				}
			}
		}
	}
	return tmperr
}

func SmblConn(info *Config.HostInfo, user string, pass string, signal chan struct{}) (flag bool, err error) {
	flag = false
	Host, Username, Password := info.Host, user, pass
	options := smb.Options{
		Host:        Host,
		Port:        445,
		User:        Username,
		Password:    Password,
		Domain:      Config.Domain,
		Workstation: "",
	}

	session, err := smb.NewSession(options, false)
	if err == nil {
		session.Close()
		if session.IsAuthenticated {
			flag = true
		}
	}
	signal <- struct{}{}
	return flag, err
}

func doWithTimeOut(info *Config.HostInfo, user string, pass string) (flag bool, err error) {
	signal := make(chan struct{})
	go func() {
		flag, err = SmblConn(info, user, pass, signal)
	}()
	select {
	case <-signal:
		return flag, err
	case <-time.After(time.Duration(Config.Timeout) * time.Second):
		return false, errors.New("time out")
	}
}
