// go build -buildmode=c-shared -o fscan.dll main.go
package main

import "C"

import (
	"fmt"
	"github.com/AgonySec/fscan/Configs"
	"github.com/AgonySec/fscan/Plugins"
	"time"
)

//export DllCanUnloadNow
func DllCanUnloadNow() {}

//export DllGetClassObject
func DllGetClassObject() {}

//export DllRegisterServer
func DllRegisterServer() {}

//export DllUnregisterServer
func DllUnregisterServer() {}

// 由于init函数，在go语言中，为包首次调用的时候会被执行；Go 编写的 DLL 被 C 程序调用时，
// init 函数会在 DLL 加载到内存时执行，而 main 函数通常不适用于 DLL 并且不会被执行。
func init() {
	start := time.Now()
	var Info Configs.HostInfo
	Configs.Flag(&Info)
	Configs.Parse(&Info)
	Plugins.Scan(Info)
	t := time.Now().Sub(start)
	fmt.Printf("[*] 扫描结束,耗时: %s\n", t)
}

func main() {}
