package Plugins

import (
	"fmt"
	"github.com/itchen-2002/fscan/WebScan/lib"
	"github.com/itchen-2002/fscan/common"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

func Scan(info common.HostInfo) {
	//fmt.Println("start infoscan")
	WaitCheckHosts, err := common.ParseIP(info.Host, common.HostFile, common.NoHosts)
	if err != nil {
		fmt.Println("len(hosts)==0", err)
		return
	}
	lib.Inithttp()
	var ch = make(chan struct{}, common.Threads)
	var wg = sync.WaitGroup{}
	//将获取到的整数端口号转换为字符串存储到web变量。
	web := strconv.Itoa(common.PORTList["web"])
	//ms17010 := 1000001
	ms17010 := strconv.Itoa(common.PORTList["ms17010"])

	var aliveHosts []string
	var aliveAddr []string
	//存活主机扫描
	if len(WaitCheckHosts) > 0 {
		//当执行参数NOPing为false 和扫描ip数量大于1时，执行ICMP存活扫描
		if common.NoPing == false || common.Scantype == "icmp" {
			//主机存活扫描
			aliveHosts = CheckLive(WaitCheckHosts, common.Ping)
			//fmt.Println("[*] Icmp alive hosts len is:", len(Hosts))
			//tips := fmt.Sprintf("[*] Icmp alive hosts len is: %d", len(Hosts))
			//common.LogSuccess(tips)
		}
		if common.Scantype == "icmp" {
			common.LogWG.Wait()
			return
		}
	}
	// 存活主机端口扫描
	if len(aliveHosts) > 0 {
		if common.Scantype == "webonly" || common.Scantype == "webpoc" {
			aliveAddr = NoPortScan(aliveHosts, common.Ports)
		} else if common.Scantype == "hostname" {
			common.Ports = "139"
			aliveAddr = NoPortScan(aliveHosts, common.Ports)
		} else {
			aliveAddr = PortScan(aliveHosts, common.Ports, common.Timeout)
			//fmt.Println("[*] alive ports len is:", len(aliveAddr))
			if common.Scantype == "portscan" {

				common.LogWG.Wait()
				return
			}
		}
		if len(common.HostPort) > 0 {
			aliveAddr = append(aliveAddr, common.HostPort...)
			aliveAddr = common.RemoveDuplicate(aliveAddr)
			common.HostPort = nil
			fmt.Println("[*] AlivePorts len is:", len(aliveAddr))
			fmt.Println("---------------------------------------------")

		}
		var severports []string //severports := []string{"21","22","135"."445","1433","3306","5432","6379","9200","11211","27017"...}
		for _, port := range common.PORTList {
			severports = append(severports, strconv.Itoa(port))
		}
		//打印信息
		fmt.Println("[*] start vulscan")

		for _, targetIP := range aliveAddr {
			info.Host, info.Ports = strings.Split(targetIP, ":")[0], strings.Split(targetIP, ":")[1]
			if common.Scantype == "all" || common.Scantype == "main" {
				switch {
				case info.Ports == "135":
					AddScan(info.Ports, info, &ch, &wg) //findnet
					if common.IsWmi {
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
				scantype := strconv.Itoa(common.PORTList[common.Scantype])
				AddScan(scantype, info, &ch, &wg)
			}
		}
	}
	for _, url := range common.Urls {
		info.Url = url
		AddScan(web, info, &ch, &wg)
	}
	wg.Wait()
	common.LogWG.Wait()
	close(common.Results)
	fmt.Printf("已完成 %v/%v\n", common.End, common.Num)
	// 源代码逻辑
	//if len(WaitCheckHosts) > 0 || len(common.HostPort) > 0 {
	//	//当执行参数NOPing为false 和扫描ip数量大于1时，执行ICMP存活扫描
	//	if common.NoPing == false && len(WaitCheckHosts) > 1 || common.Scantype == "icmp" {
	//		//主机存活扫描
	//		aliveHosts = CheckLive(WaitCheckHosts, common.Ping)
	//		//fmt.Println("[*] Icmp alive hosts len is:", len(Hosts))
	//		//tips := fmt.Sprintf("[*] Icmp alive hosts len is: %d", len(Hosts))
	//		//common.LogSuccess(tips)
	//	}
	//	if common.Scantype == "icmp" {
	//		common.LogWG.Wait()
	//		return
	//	}
	//	var AlivePorts []string
	//	if common.Scantype == "webonly" || common.Scantype == "webpoc" {
	//		AlivePorts = NoPortScan(aliveHosts, common.Ports)
	//	} else if common.Scantype == "hostname" {
	//		common.Ports = "139"
	//		AlivePorts = NoPortScan(aliveHosts, common.Ports)
	//	} else if len(aliveHosts) > 0 {
	//		//端口扫描
	//		AlivePorts = PortScan(aliveHosts, common.Ports, common.Timeout)
	//		//fmt.Println("[*] alive ports len is:", len(AlivePorts))
	//		//fmt.Println("---------------------------------------------")
	//		if common.Scantype == "portscan" {
	//			common.LogWG.Wait()
	//			return
	//		}
	//	}
	//	if len(common.HostPort) > 0 {
	//		AlivePorts = append(AlivePorts, common.HostPort...)
	//		AlivePorts = common.RemoveDuplicate(AlivePorts)
	//		common.HostPort = nil
	//		fmt.Println("[*] AlivePorts len is:", len(AlivePorts))
	//		fmt.Println("---------------------------------------------")
	//
	//	}
	//	var severports []string //severports := []string{"21","22","135"."445","1433","3306","5432","6379","9200","11211","27017"...}
	//	for _, port := range common.PORTList {
	//		severports = append(severports, strconv.Itoa(port))
	//	}
	//	//打印信息
	//	fmt.Println("[*] start vulscan")
	//
	//	for _, targetIP := range AlivePorts {
	//		info.Host, info.Ports = strings.Split(targetIP, ":")[0], strings.Split(targetIP, ":")[1]
	//		if common.Scantype == "all" || common.Scantype == "main" {
	//			switch {
	//			case info.Ports == "135":
	//				AddScan(info.Ports, info, &ch, &wg) //findnet
	//				if common.IsWmi {
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
	//			scantype := strconv.Itoa(common.PORTList[common.Scantype])
	//			AddScan(scantype, info, &ch, &wg)
	//		}
	//	}
	//}

}

// 声明创建了一个同步互斥锁
var Mutex = &sync.Mutex{}

func AddScan(scantype string, info common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	*ch <- struct{}{}
	wg.Add(1)
	go func() {
		Mutex.Lock()
		common.Num += 1
		Mutex.Unlock()
		ConvertFunc(&scantype, &info)
		Mutex.Lock()
		common.End += 1
		Mutex.Unlock()
		wg.Done()
		<-*ch
	}()
}

func ConvertFunc(name *string, info *common.HostInfo) {
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
