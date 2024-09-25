package main

import (
	"fmt"
	"github.com/itchen-2002/fscan/Plugins"
	"github.com/itchen-2002/fscan/common"
	"time"
)

func main() {
	start := time.Now()

	var Info common.HostInfo

	// 接收输入的参数
	common.Flag(&Info)

	// 解析参数
	common.Parse(&Info)

	Plugins.Scan(Info)

	fmt.Printf("[*] 扫描结束,耗时: %s\n", time.Since(start))
}
