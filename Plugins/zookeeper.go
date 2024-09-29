package Plugins

import (
	"fmt"
	"github.com/AgonySec/fscan/Configs"
	"github.com/samuel/go-zookeeper/zk"
	"time"
)

func ZookeeperConn(info *Configs.HostInfo) {
	x := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	s := []string{x}
	_, _, err := zk.Connect(s, time.Second*5)
	//defer conn.Close()
	if err != nil {
		fmt.Println(err)
	} else {
		Configs.LogSuccess(fmt.Sprintf("unauthorized zookeeper %s", fmt.Sprintf("%v:%v", info.Host, info.Ports)))
		//fmt.Println("zookeeper 连接成功！")
	}
}
