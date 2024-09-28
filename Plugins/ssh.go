package Plugins

import (
	"errors"
	"fmt"
	"github.com/itchen-2002/fscan/Config"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

func SshScan(info *Config.HostInfo) (tmperr error) {
	if Config.IsBrute {
		return
	}
	starttime := time.Now().Unix()
	for _, user := range Config.Userdict["ssh"] {
		for _, pass := range Config.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := SshConn(info, user, pass)
			if flag == true && err == nil {
				return err
			} else {
				errlog := fmt.Sprintf("[-] ssh %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
				Config.LogError(errlog)
				tmperr = err
				if Config.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(Config.Userdict["ssh"])*len(Config.Passwords)) * Config.Timeout) {
					return err
				}
			}
			if Config.SshKey != "" {
				return err
			}
		}
	}
	return tmperr
}

func SshConn(info *Config.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	var Auth []ssh.AuthMethod
	if Config.SshKey != "" {
		pemBytes, err := ioutil.ReadFile(Config.SshKey)
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
		Timeout: time.Duration(Config.Timeout) * time.Second,
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
			if Config.Command != "" {
				combo, _ := session.CombinedOutput(Config.Command)
				result = fmt.Sprintf("[+] SSH %v:%v:%v %v \n %v", Host, Port, Username, Password, string(combo))
				if Config.SshKey != "" {
					result = fmt.Sprintf("[+] SSH %v:%v sshkey correct \n %v", Host, Port, string(combo))
				}
				Config.LogSuccess(result)
			} else {
				result = fmt.Sprintf("[+] SSH %v:%v:%v %v", Host, Port, Username, Password)
				if Config.SshKey != "" {
					result = fmt.Sprintf("[+] SSH %v:%v sshkey correct", Host, Port)
				}
				Config.LogSuccess(result)
			}
		}
	}
	return flag, err

}
