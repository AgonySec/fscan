package main

import (
	"fmt"
	"github.com/itchen-2002/fscan/Config"
	"github.com/itchen-2002/fscan/Plugins"
	"time"
)

func main() {
	start := time.Now()

	var Info Config.HostInfo
	// 接收输入的参数
	Config.Flag(&Info)
	// 解析参数
	Config.Parse(&Info)
	Plugins.Scan(Info)
	fmt.Printf("[*] 扫描结束,耗时: %s\n", time.Since(start))
}
