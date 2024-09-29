package Plugins

import (
	"errors"
	"fmt"
	"github.com/AgonySec/fscan/Configs"
	"github.com/stacktitan/smb/smb"
	"strings"
	"time"
)

func SmbScan(info *Configs.HostInfo) (tmperr error) {
	if Configs.IsBrute {
		return nil
	}
	starttime := time.Now().Unix()
	for _, user := range Configs.Userdict["smb"] {
		for _, pass := range Configs.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := doWithTimeOut(info, user, pass)
			if flag == true && err == nil {
				var result string
				if Configs.Domain != "" {
					result = fmt.Sprintf("[+] SMB %v:%v:%v\\%v %v", info.Host, info.Ports, Configs.Domain, user, pass)
				} else {
					result = fmt.Sprintf("[+] SMB %v:%v:%v %v", info.Host, info.Ports, user, pass)
				}
				Configs.LogSuccess(result)
				return err
			} else {
				errlog := fmt.Sprintf("[-] smb %v:%v %v %v %v", info.Host, 445, user, pass, err)
				errlog = strings.Replace(errlog, "\n", "", -1)
				Configs.LogError(errlog)
				tmperr = err
				if Configs.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(Configs.Userdict["smb"])*len(Configs.Passwords)) * Configs.Timeout) {
					return err
				}
			}
		}
	}
	return tmperr
}

func SmblConn(info *Configs.HostInfo, user string, pass string, signal chan struct{}) (flag bool, err error) {
	flag = false
	Host, Username, Password := info.Host, user, pass
	options := smb.Options{
		Host:        Host,
		Port:        445,
		User:        Username,
		Password:    Password,
		Domain:      Configs.Domain,
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

func doWithTimeOut(info *Configs.HostInfo, user string, pass string) (flag bool, err error) {
	signal := make(chan struct{})
	go func() {
		flag, err = SmblConn(info, user, pass, signal)
	}()
	select {
	case <-signal:
		return flag, err
	case <-time.After(time.Duration(Configs.Timeout) * time.Second):
		return false, errors.New("time out")
	}
}
