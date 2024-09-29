package Plugins

import (
	"fmt"
	"github.com/itchen-2002/fscan/common"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Addr struct {
	ip   string
	port int
}

// 优化端口扫描输出，优化后，将扫描结果按照IP分组，并输出为如下格式：
func MapIPToPorts(ipPortList []string) {
	common.LogSuccess("[*] start port scan")

	ipToPorts := make(map[string][]int)
	// 遍历列表，解析IP和端口，并将端口添加到对应IP的列表中
	for _, ipPort := range ipPortList {
		parts := strings.Split(ipPort, ":")
		ip := parts[0]
		port, _ := strconv.Atoi(parts[1])
		ipToPorts[ip] = append(ipToPorts[ip], port)
	}

	for ip, ports := range ipToPorts {
		sort.Ints(ports)
		result := fmt.Sprintf(" %s: %v", ip, ports)
		common.LogSuccess(result)
	}
	tips := fmt.Sprintf("[*] alive ports len is:%d", len(ipPortList))
	common.LogSuccess(tips)
	common.LogSuccess("-------------------------------------------------------------------------")

}

/*
*
端口扫描
*/
func PortScan(hostslist []string, ports string, timeout int64) []string {
	//tips := fmt.Sprintf("[*] start port scan")

	// 存活地址
	var AliveAddress []string
	// 需要扫描端口列表
	probePorts := common.ParsePort(ports)
	if len(probePorts) == 0 {
		fmt.Printf("[-] parse port %s error, please check your port format\n", ports)
		return AliveAddress
	}
	// 将不需要扫描的端口过滤掉
	noPorts := common.ParsePort(common.NoPorts)
	if len(noPorts) > 0 {
		temp := map[int]struct{}{}
		for _, port := range probePorts {
			temp[port] = struct{}{}
		}

		for _, port := range noPorts {
			delete(temp, port)
		}

		var newDatas []int
		for port := range temp {
			newDatas = append(newDatas, port)
		}
		probePorts = newDatas
		sort.Ints(probePorts)
	}
	// 默认扫描线程数为600
	workers := common.Threads
	// 创建了两个Go语言的通道（chan）缓冲区大小为100。这两个通道用于在并发 goroutine 之间安全地传递数据，而不需要显式地使用锁。
	Addrs := make(chan Addr, 100)
	results := make(chan string, 100)

	// sync.WaitGroup 用于同步多个 goroutine，确保所有子任务完成后再继续执行主程序
	var wg sync.WaitGroup

	//接收结果
	go func() {
		for found := range results {
			AliveAddress = append(AliveAddress, found)
			wg.Done()
		}
	}()

	//多线程扫描 ，因为（chan）具有异步通信的能力，所以添加扫描目标可以放到后面
	for i := 0; i < workers; i++ {
		go func() {
			for addr := range Addrs {
				PortConnect(addr, results, timeout, &wg)
				wg.Done()
			}
		}()
	}

	//添加扫描目标
	for _, port := range probePorts {
		for _, host := range hostslist {
			wg.Add(1)
			Addrs <- Addr{host, port}
		}
	}

	wg.Wait()
	close(Addrs)
	close(results)

	//优化端口扫描输出
	MapIPToPorts(AliveAddress)

	return AliveAddress
}

/*
*
建立端口连接
*/
func PortConnect(addr Addr, respondingHosts chan<- string, adjustedTimeout int64, wg *sync.WaitGroup) {
	host, port := addr.ip, addr.port
	conn, err := common.WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%v", host, port), time.Duration(adjustedTimeout)*time.Second)
	if err == nil {
		defer conn.Close()
		address := host + ":" + strconv.Itoa(port)
		//result := fmt.Sprintf("%s open", address)
		//common.LogSuccess(result)
		wg.Add(1)
		respondingHosts <- address
	}
}

func NoPortScan(hostslist []string, ports string) (AliveAddress []string) {
	probePorts := common.ParsePort(ports)
	noPorts := common.ParsePort(common.NoPorts)
	if len(noPorts) > 0 {
		temp := map[int]struct{}{}
		for _, port := range probePorts {
			temp[port] = struct{}{}
		}

		for _, port := range noPorts {
			delete(temp, port)
		}

		var newDatas []int
		for port, _ := range temp {
			newDatas = append(newDatas, port)
		}
		probePorts = newDatas
		sort.Ints(probePorts)
	}
	for _, port := range probePorts {
		for _, host := range hostslist {
			address := host + ":" + strconv.Itoa(port)
			AliveAddress = append(AliveAddress, address)
		}
	}
	return
}
