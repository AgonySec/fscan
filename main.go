package main

import (
	"fmt"
	"github.com/AgonySec/fscan/Configs"
	"github.com/AgonySec/fscan/Plugins"
	"time"
)

func main() {
	start := time.Now()

	var Info Configs.HostInfo
	// 接收输入的参数
	Configs.Flag(&Info)
	// 解析参数
	Configs.Parse(&Info)
	// 开始扫描
	Plugins.Scan(Info)

	fmt.Printf("[*] 扫描结束,耗时: %s\n", time.Since(start))
}
