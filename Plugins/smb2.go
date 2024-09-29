package Plugins

import (
	"fmt"
	"github.com/AgonySec/fscan/Configs"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

func SmbScan2(info *Configs.HostInfo) (tmperr error) {
	if Configs.IsBrute {
		return nil
	}
	hasprint := false
	starttime := time.Now().Unix()
	if len(Configs.HashBytes) > 0 {
		for _, user := range Configs.Userdict["smb"] {
			for _, hash := range Configs.HashBytes {
				pass := ""
				flag, err, flag2 := Smb2Con(info, user, pass, hash, hasprint)
				if flag2 {
					hasprint = true
				}
				if flag == true {
					var result string
					if Configs.Domain != "" {
						result = fmt.Sprintf("[+] SMB2 %v:%v:%v\\%v ", info.Host, info.Ports, Configs.Domain, user)
					} else {
						result = fmt.Sprintf("[+] SMB2 %v:%v:%v ", info.Host, info.Ports, user)
					}
					if len(hash) > 0 {
						result += "hash: " + Configs.Hash
					} else {
						result += pass
					}
					Configs.LogSuccess(result)
					return err
				} else {
					var errlog string
					if len(Configs.Hash) > 0 {
						errlog = fmt.Sprintf("[-] smb2 %v:%v %v %v %v", info.Host, 445, user, Configs.Hash, err)
					} else {
						errlog = fmt.Sprintf("[-] smb2 %v:%v %v %v %v", info.Host, 445, user, pass, err)
					}
					errlog = strings.Replace(errlog, "\n", " ", -1)
					Configs.LogError(errlog)
					tmperr = err
					if Configs.CheckErrs(err) {
						return err
					}
					if time.Now().Unix()-starttime > (int64(len(Configs.Userdict["smb"])*len(Configs.HashBytes)) * Configs.Timeout) {
						return err
					}
				}
				if len(Configs.Hash) > 0 {
					break
				}
			}
		}
	} else {
		for _, user := range Configs.Userdict["smb"] {
			for _, pass := range Configs.Passwords {
				pass = strings.Replace(pass, "{user}", user, -1)
				hash := []byte{}
				flag, err, flag2 := Smb2Con(info, user, pass, hash, hasprint)
				if flag2 {
					hasprint = true
				}
				if flag == true {
					var result string
					if Configs.Domain != "" {
						result = fmt.Sprintf("[+] SMB2 %v:%v:%v\\%v ", info.Host, info.Ports, Configs.Domain, user)
					} else {
						result = fmt.Sprintf("[+] SMB2 %v:%v:%v ", info.Host, info.Ports, user)
					}
					if len(hash) > 0 {
						result += "hash: " + Configs.Hash
					} else {
						result += pass
					}
					Configs.LogSuccess(result)
					return err
				} else {
					var errlog string
					if len(Configs.Hash) > 0 {
						errlog = fmt.Sprintf("[-] smb2 %v:%v %v %v %v", info.Host, 445, user, Configs.Hash, err)
					} else {
						errlog = fmt.Sprintf("[-] smb2 %v:%v %v %v %v", info.Host, 445, user, pass, err)
					}
					errlog = strings.Replace(errlog, "\n", " ", -1)
					Configs.LogError(errlog)
					tmperr = err
					if Configs.CheckErrs(err) {
						return err
					}
					if time.Now().Unix()-starttime > (int64(len(Configs.Userdict["smb"])*len(Configs.Passwords)) * Configs.Timeout) {
						return err
					}
				}
				if len(Configs.Hash) > 0 {
					break
				}
			}
		}
	}

	return tmperr
}

func Smb2Con(info *Configs.HostInfo, user string, pass string, hash []byte, hasprint bool) (flag bool, err error, flag2 bool) {
	conn, err := net.DialTimeout("tcp", info.Host+":445", time.Duration(Configs.Timeout)*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	initiator := smb2.NTLMInitiator{
		User:   user,
		Domain: Configs.Domain,
	}
	if len(hash) > 0 {
		initiator.Hash = hash
	} else {
		initiator.Password = pass
	}
	d := &smb2.Dialer{
		Initiator: &initiator,
	}

	s, err := d.Dial(conn)
	if err != nil {
		return
	}
	defer s.Logoff()
	names, err := s.ListSharenames()
	if err != nil {
		return
	}
	if !hasprint {
		var result string
		if Configs.Domain != "" {
			result = fmt.Sprintf("[*] SMB2-shares %v:%v:%v\\%v ", info.Host, info.Ports, Configs.Domain, user)
		} else {
			result = fmt.Sprintf("[*] SMB2-shares %v:%v:%v ", info.Host, info.Ports, user)
		}
		if len(hash) > 0 {
			result += "hash: " + Configs.Hash
		} else {
			result += pass
		}
		result = fmt.Sprintf("%v shares: %v", result, names)
		Configs.LogSuccess(result)
		flag2 = true
	}
	fs, err := s.Mount("C$")
	if err != nil {
		return
	}
	defer fs.Umount()
	path := `Windows\win.ini`
	f, err := fs.OpenFile(path, os.O_RDONLY, 0666)
	if err != nil {
		return
	}
	defer f.Close()
	flag = true
	return
	//bs, err := ioutil.ReadAll(f)
	//if err != nil {
	//	return
	//}
	//fmt.Println(string(bs))
	//return

}

//if info.Path == ""{
//}
//path = info.Path
//f, err := fs.OpenFile(path, os.O_RDONLY, 0666)
//if err != nil {
//	return
//}
//flag = true
//_, err = f.Seek(0, io.SeekStart)
//if err != nil {
//	return
//}
//bs, err := ioutil.ReadAll(f)
//if err != nil {
//	return
//}
//fmt.Println(string(bs))
//return
//f, err := fs.Create(`Users\Public\Videos\hello.txt`)
//if err != nil {
//	return
//}
//flag = true
//
//_, err = f.Write([]byte("Hello world!"))
//if err != nil {
//	return
//}
//
//_, err = f.Seek(0, io.SeekStart)
//if err != nil {
//	return
//}
//bs, err := ioutil.ReadAll(f)
//if err != nil {
//	return
//}
//fmt.Println(string(bs))
//return
