package Plugins

import (
	"errors"
	"fmt"
	"github.com/AgonySec/fscan/Configs"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

func SshScan(info *Configs.HostInfo) (tmperr error) {
	if Configs.IsBrute {
		return
	}
	starttime := time.Now().Unix()
	for _, user := range Configs.Userdict["ssh"] {
		for _, pass := range Configs.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := SshConn(info, user, pass)
			if flag == true && err == nil {
				return err
			} else {
				errlog := fmt.Sprintf("[-] ssh %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
				Configs.LogError(errlog)
				tmperr = err
				if Configs.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(Configs.Userdict["ssh"])*len(Configs.Passwords)) * Configs.Timeout) {
					return err
				}
			}
			if Configs.SshKey != "" {
				return err
			}
		}
	}
	return tmperr
}

func SshConn(info *Configs.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	var Auth []ssh.AuthMethod
	if Configs.SshKey != "" {
		pemBytes, err := ioutil.ReadFile(Configs.SshKey)
		if err != nil {
			return false, errors.New("read key failed" + err.Error())
		}
		signer, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			return false, errors.New("parse key failed" + err.Error())
		}
		Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else {
		Auth = []ssh.AuthMethod{ssh.Password(Password)}
	}

	config := &ssh.ClientConfig{
		User:    Username,
		Auth:    Auth,
		Timeout: time.Duration(Configs.Timeout) * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", Host, Port), config)
	if err == nil {
		defer client.Close()
		session, err := client.NewSession()
		if err == nil {
			defer session.Close()
			flag = true
			var result string
			if Configs.Command != "" {
				combo, _ := session.CombinedOutput(Configs.Command)
				result = fmt.Sprintf("[+] SSH %v:%v:%v %v \n %v", Host, Port, Username, Password, string(combo))
				if Configs.SshKey != "" {
					result = fmt.Sprintf("[+] SSH %v:%v sshkey correct \n %v", Host, Port, string(combo))
				}
				Configs.LogSuccess(result)
			} else {
				result = fmt.Sprintf("[+] SSH %v:%v:%v %v", Host, Port, Username, Password)
				if Configs.SshKey != "" {
					result = fmt.Sprintf("[+] SSH %v:%v sshkey correct", Host, Port)
				}
				Configs.LogSuccess(result)
			}
		}
	}
	return flag, err

}
