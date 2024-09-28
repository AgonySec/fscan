package Plugins

import (
	"fmt"
	"github.com/itchen-2002/fscan/Config"
	"github.com/itchen-2002/fscan/WebScan/lib"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

func Scan(info Config.HostInfo) {
	//fmt.Println("start infoscan")
	WaitCheckHosts, err := Config.ParseIP(info.Host, Config.HostFile, Config.NoHosts)
	if err != nil {
		fmt.Println("len(hosts)==0", err)
		return
	}
	lib.Inithttp()
	var ch = make(chan struct{}, Config.Threads)
	var wg = sync.WaitGroup{}
	//将获取到的整数端口号转换为字符串存储到web变量。
	web := strconv.Itoa(Config.PORTList["web"])
	//ms17010 := 1000001
	ms17010 := strconv.Itoa(Config.PORTList["ms17010"])

	var aliveHosts []string
	var aliveAddr []string
	//存活主机扫描
	if len(WaitCheckHosts) > 0 {
		//当执行参数NOPing为false 和扫描ip数量大于1时，执行ICMP存活扫描
		if Config.NoPing == false && len(WaitCheckHosts) > 1 || Config.Scantype == "icmp" {
			//主机存活扫描
			aliveHosts = CheckLive(WaitCheckHosts, Config.Ping)
			//fmt.Println("[*] Icmp alive hosts len is:", len(Hosts))
			//tips := fmt.Sprintf("[*] Icmp alive hosts len is: %d", len(Hosts))
			//Config.LogSuccess(tips)
		}
		if Config.Scantype == "icmp" {
			Config.LogWG.Wait()
			return
		}
	}
	// 存活主机端口扫描
	if len(aliveHosts) > 0 {
		if Config.Scantype == "webonly" || Config.Scantype == "webpoc" {
			aliveAddr = NoPortScan(aliveHosts, Config.Ports)
		} else if Config.Scantype == "hostname" {
			Config.Ports = "139"
			aliveAddr = NoPortScan(aliveHosts, Config.Ports)
		} else {
			aliveAddr = PortScan(aliveHosts, Config.Ports, Config.Timeout)
			fmt.Println("[*] alive ports len is:", len(aliveAddr))
			if Config.Scantype == "portscan" {

				Config.LogWG.Wait()
				return
			}
		}
		if len(Config.HostPort) > 0 {
			aliveAddr = append(aliveAddr, Config.HostPort...)
			aliveAddr = Config.RemoveDuplicate(aliveAddr)
			Config.HostPort = nil
			fmt.Println("[*] AlivePorts len is:", len(aliveAddr))
			fmt.Println("---------------------------------------------")

		}
		var severports []string //severports := []string{"21","22","135"."445","1433","3306","5432","6379","9200","11211","27017"...}
		for _, port := range Config.PORTList {
			severports = append(severports, strconv.Itoa(port))
		}
		//打印信息
		fmt.Println("[*] start vulscan")

		for _, targetIP := range aliveAddr {
			info.Host, info.Ports = strings.Split(targetIP, ":")[0], strings.Split(targetIP, ":")[1]
			if Config.Scantype == "all" || Config.Scantype == "main" {
				switch {
				case info.Ports == "135":
					AddScan(info.Ports, info, &ch, &wg) //findnet
					if Config.IsWmi {
						AddScan("1000005", info, &ch, &wg) //wmiexec
					}
				case info.Ports == "445":
					AddScan(ms17010, info, &ch, &wg) //ms17010
					//AddScan(info.Ports, info, ch, &wg)  //smb
					//AddScan("1000002", info, ch, &wg) //smbghost
				case info.Ports == "9000":
					AddScan(web, info, &ch, &wg)        //http
					AddScan(info.Ports, info, &ch, &wg) //fcgiscan
				case IsContain(severports, info.Ports):
					AddScan(info.Ports, info, &ch, &wg) //plugins scan
				default:
					AddScan(web, info, &ch, &wg) //webtitle
				}
			} else {
				scantype := strconv.Itoa(Config.PORTList[Config.Scantype])
				AddScan(scantype, info, &ch, &wg)
			}
		}
	}
	for _, url := range Config.Urls {
		info.Url = url
		AddScan(web, info, &ch, &wg)
	}
	wg.Wait()
	Config.LogWG.Wait()
	close(Config.Results)
	fmt.Printf("已完成 %v/%v\n", Config.End, Config.Num)
	// 源代码逻辑
	//if len(WaitCheckHosts) > 0 || len(Config.HostPort) > 0 {
	//	//当执行参数NOPing为false 和扫描ip数量大于1时，执行ICMP存活扫描
	//	if Config.NoPing == false && len(WaitCheckHosts) > 1 || Config.Scantype == "icmp" {
	//		//主机存活扫描
	//		aliveHosts = CheckLive(WaitCheckHosts, Config.Ping)
	//		//fmt.Println("[*] Icmp alive hosts len is:", len(Hosts))
	//		//tips := fmt.Sprintf("[*] Icmp alive hosts len is: %d", len(Hosts))
	//		//Config.LogSuccess(tips)
	//	}
	//	if Config.Scantype == "icmp" {
	//		Config.LogWG.Wait()
	//		return
	//	}
	//	var AlivePorts []string
	//	if Config.Scantype == "webonly" || Config.Scantype == "webpoc" {
	//		AlivePorts = NoPortScan(aliveHosts, Config.Ports)
	//	} else if Config.Scantype == "hostname" {
	//		Config.Ports = "139"
	//		AlivePorts = NoPortScan(aliveHosts, Config.Ports)
	//	} else if len(aliveHosts) > 0 {
	//		//端口扫描
	//		AlivePorts = PortScan(aliveHosts, Config.Ports, Config.Timeout)
	//		//fmt.Println("[*] alive ports len is:", len(AlivePorts))
	//		//fmt.Println("---------------------------------------------")
	//		if Config.Scantype == "portscan" {
	//			Config.LogWG.Wait()
	//			return
	//		}
	//	}
	//	if len(Config.HostPort) > 0 {
	//		AlivePorts = append(AlivePorts, Config.HostPort...)
	//		AlivePorts = Config.RemoveDuplicate(AlivePorts)
	//		Config.HostPort = nil
	//		fmt.Println("[*] AlivePorts len is:", len(AlivePorts))
	//		fmt.Println("---------------------------------------------")
	//
	//	}
	//	var severports []string //severports := []string{"21","22","135"."445","1433","3306","5432","6379","9200","11211","27017"...}
	//	for _, port := range Config.PORTList {
	//		severports = append(severports, strconv.Itoa(port))
	//	}
	//	//打印信息
	//	fmt.Println("[*] start vulscan")
	//
	//	for _, targetIP := range AlivePorts {
	//		info.Host, info.Ports = strings.Split(targetIP, ":")[0], strings.Split(targetIP, ":")[1]
	//		if Config.Scantype == "all" || Config.Scantype == "main" {
	//			switch {
	//			case info.Ports == "135":
	//				AddScan(info.Ports, info, &ch, &wg) //findnet
	//				if Config.IsWmi {
	//					AddScan("1000005", info, &ch, &wg) //wmiexec
	//				}
	//			case info.Ports == "445":
	//				AddScan(ms17010, info, &ch, &wg) //ms17010
	//				//AddScan(info.Ports, info, ch, &wg)  //smb
	//				//AddScan("1000002", info, ch, &wg) //smbghost
	//			case info.Ports == "9000":
	//				AddScan(web, info, &ch, &wg)        //http
	//				AddScan(info.Ports, info, &ch, &wg) //fcgiscan
	//			case IsContain(severports, info.Ports):
	//				AddScan(info.Ports, info, &ch, &wg) //plugins scan
	//			default:
	//				AddScan(web, info, &ch, &wg) //webtitle
	//			}
	//		} else {
	//			scantype := strconv.Itoa(Config.PORTList[Config.Scantype])
	//			AddScan(scantype, info, &ch, &wg)
	//		}
	//	}
	//}

}

// 声明创建了一个同步互斥锁
var Mutex = &sync.Mutex{}

func AddScan(scantype string, info Config.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	*ch <- struct{}{}
	wg.Add(1)
	go func() {
		Mutex.Lock()
		Config.Num += 1
		Mutex.Unlock()
		ConvertFunc(&scantype, &info)
		Mutex.Lock()
		Config.End += 1
		Mutex.Unlock()
		wg.Done()
		<-*ch
	}()
}

func ConvertFunc(name *string, info *Config.HostInfo) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("[-] %v:%v scan error: %v\n", info.Host, info.Ports, err)
		}
	}()
	// 通过 reflect.ValueOf 获取名为 PluginList[*name] 的值的反射对象。
	f := reflect.ValueOf(PluginList[*name])
	infoSlice := []reflect.Value{reflect.ValueOf(info)}
	f.Call(infoSlice)
}

func IsContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}
