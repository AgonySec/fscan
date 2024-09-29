package Plugins

import (
	"fmt"
	"github.com/AgonySec/fscan/Configs"
	"github.com/AgonySec/fscan/WebScan/lib"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

func Scan(info Configs.HostInfo) {
	//fmt.Println("start infoscan")
	WaitCheckHosts, err := Configs.ParseIP(info.Host, Configs.HostFile, Configs.NoHosts)
	if err != nil {
		fmt.Println("len(hosts)==0", err)
		return
	}
	lib.Inithttp()
	var ch = make(chan struct{}, Configs.Threads)
	var wg = sync.WaitGroup{}
	//将获取到的整数端口号转换为字符串存储到web变量。
	web := strconv.Itoa(Configs.PORTList["web"])
	//ms17010 := 1000001
	ms17010 := strconv.Itoa(Configs.PORTList["ms17010"])

	var aliveHosts []string
	var aliveAddr []string
	//存活主机扫描
	if len(WaitCheckHosts) > 0 {
		//当执行参数NOPing为false 和扫描ip数量大于1时，执行ICMP存活扫描
		if Configs.NoPing == false || Configs.Scantype == "icmp" {
			//主机存活扫描
			aliveHosts = CheckLive(WaitCheckHosts, Configs.Ping)
			//fmt.Println("[*] Icmp alive hosts len is:", len(Hosts))
			//tips := fmt.Sprintf("[*] Icmp alive hosts len is: %d", len(Hosts))
			//Configs.LogSuccess(tips)
		}
		if Configs.Scantype == "icmp" {
			Configs.LogWG.Wait()
			return
		}
	}
	// 存活主机端口扫描
	if len(aliveHosts) > 0 {
		if Configs.Scantype == "webonly" || Configs.Scantype == "webpoc" {
			aliveAddr = NoPortScan(aliveHosts, Configs.Ports)
		} else if Configs.Scantype == "hostname" {
			Configs.Ports = "139"
			aliveAddr = NoPortScan(aliveHosts, Configs.Ports)
		} else {
			aliveAddr = PortScan(aliveHosts, Configs.Ports, Configs.Timeout)
			//fmt.Println("[*] alive ports len is:", len(aliveAddr))
			if Configs.Scantype == "portscan" {

				Configs.LogWG.Wait()
				return
			}
		}
		if len(Configs.HostPort) > 0 {
			aliveAddr = append(aliveAddr, Configs.HostPort...)
			aliveAddr = Configs.RemoveDuplicate(aliveAddr)
			Configs.HostPort = nil
			fmt.Println("[*] AlivePorts len is:", len(aliveAddr))
			fmt.Println("---------------------------------------------")

		}
		var severports []string //severports := []string{"21","22","135"."445","1433","3306","5432","6379","9200","11211","27017"...}
		for _, port := range Configs.PORTList {
			severports = append(severports, strconv.Itoa(port))
		}
		//打印信息
		fmt.Println("[*] start vulscan")

		for _, targetIP := range aliveAddr {
			info.Host, info.Ports = strings.Split(targetIP, ":")[0], strings.Split(targetIP, ":")[1]
			if Configs.Scantype == "all" || Configs.Scantype == "main" {
				switch {
				case info.Ports == "135":
					AddScan(info.Ports, info, &ch, &wg) //findnet
					if Configs.IsWmi {
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
				scantype := strconv.Itoa(Configs.PORTList[Configs.Scantype])
				AddScan(scantype, info, &ch, &wg)
			}
		}
	}
	for _, url := range Configs.Urls {
		info.Url = url
		AddScan(web, info, &ch, &wg)
	}
	wg.Wait()
	Configs.LogWG.Wait()
	close(Configs.Results)
	fmt.Printf("已完成 %v/%v\n", Configs.End, Configs.Num)
	// 源代码逻辑
	//if len(WaitCheckHosts) > 0 || len(Configs.HostPort) > 0 {
	//	//当执行参数NOPing为false 和扫描ip数量大于1时，执行ICMP存活扫描
	//	if Configs.NoPing == false && len(WaitCheckHosts) > 1 || Configs.Scantype == "icmp" {
	//		//主机存活扫描
	//		aliveHosts = CheckLive(WaitCheckHosts, Configs.Ping)
	//		//fmt.Println("[*] Icmp alive hosts len is:", len(Hosts))
	//		//tips := fmt.Sprintf("[*] Icmp alive hosts len is: %d", len(Hosts))
	//		//Configs.LogSuccess(tips)
	//	}
	//	if Configs.Scantype == "icmp" {
	//		Configs.LogWG.Wait()
	//		return
	//	}
	//	var AlivePorts []string
	//	if Configs.Scantype == "webonly" || Configs.Scantype == "webpoc" {
	//		AlivePorts = NoPortScan(aliveHosts, Configs.Ports)
	//	} else if Configs.Scantype == "hostname" {
	//		Configs.Ports = "139"
	//		AlivePorts = NoPortScan(aliveHosts, Configs.Ports)
	//	} else if len(aliveHosts) > 0 {
	//		//端口扫描
	//		AlivePorts = PortScan(aliveHosts, Configs.Ports, Configs.Timeout)
	//		//fmt.Println("[*] alive ports len is:", len(AlivePorts))
	//		//fmt.Println("---------------------------------------------")
	//		if Configs.Scantype == "portscan" {
	//			Configs.LogWG.Wait()
	//			return
	//		}
	//	}
	//	if len(Configs.HostPort) > 0 {
	//		AlivePorts = append(AlivePorts, Configs.HostPort...)
	//		AlivePorts = Configs.RemoveDuplicate(AlivePorts)
	//		Configs.HostPort = nil
	//		fmt.Println("[*] AlivePorts len is:", len(AlivePorts))
	//		fmt.Println("---------------------------------------------")
	//
	//	}
	//	var severports []string //severports := []string{"21","22","135"."445","1433","3306","5432","6379","9200","11211","27017"...}
	//	for _, port := range Configs.PORTList {
	//		severports = append(severports, strconv.Itoa(port))
	//	}
	//	//打印信息
	//	fmt.Println("[*] start vulscan")
	//
	//	for _, targetIP := range AlivePorts {
	//		info.Host, info.Ports = strings.Split(targetIP, ":")[0], strings.Split(targetIP, ":")[1]
	//		if Configs.Scantype == "all" || Configs.Scantype == "main" {
	//			switch {
	//			case info.Ports == "135":
	//				AddScan(info.Ports, info, &ch, &wg) //findnet
	//				if Configs.IsWmi {
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
	//			scantype := strconv.Itoa(Configs.PORTList[Configs.Scantype])
	//			AddScan(scantype, info, &ch, &wg)
	//		}
	//	}
	//}

}

// 声明创建了一个同步互斥锁
var Mutex = &sync.Mutex{}

func AddScan(scantype string, info Configs.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	*ch <- struct{}{}
	wg.Add(1)
	go func() {
		Mutex.Lock()
		Configs.Num += 1
		Mutex.Unlock()
		ConvertFunc(&scantype, &info)
		Mutex.Lock()
		Configs.End += 1
		Mutex.Unlock()
		wg.Done()
		<-*ch
	}()
}

func ConvertFunc(name *string, info *Configs.HostInfo) {
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
