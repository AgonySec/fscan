package WebScan

import (
	"embed"
	"fmt"
	"github.com/itchen-2002/fscan/Config"
	"github.com/itchen-2002/fscan/WebScan/lib"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed pocs
var Pocs embed.FS
var once sync.Once
var AllPocs []*lib.Poc

func WebScan(info *Config.HostInfo) {
	once.Do(initpoc)
	var pocinfo = Config.Pocinfo
	buf := strings.Split(info.Url, "/")
	pocinfo.Target = strings.Join(buf[:3], "/")

	if pocinfo.PocName != "" {
		Execute(pocinfo)
	} else {
		for _, infostr := range info.Infostr {
			pocinfo.PocName = lib.CheckInfoPoc(infostr)
			Execute(pocinfo)
		}
	}
}
func getRandomUserAgent() string {
	rand.Seed(time.Now().UnixNano())
	return Config.UASlice[rand.Intn(len(Config.UASlice))]
}
func Execute(PocInfo Config.PocInfo) {
	req, err := http.NewRequest("GET", PocInfo.Target, nil)
	if err != nil {
		errlog := fmt.Sprintf("[-] webpocinit %v %v", PocInfo.Target, err)
		Config.LogError(errlog)
		return
	}
	req.Header.Set("User-agent", getRandomUserAgent())
	req.Header.Set("Accept", Config.Accept)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	if Config.Cookie != "" {
		req.Header.Set("Cookie", Config.Cookie)
	}
	pocs := filterPoc(PocInfo.PocName)
	lib.CheckMultiPoc(req, pocs, Config.PocNum)
}

func initpoc() {
	if Config.PocPath == "" {
		entries, err := Pocs.ReadDir("pocs")
		if err != nil {
			fmt.Printf("[-] init poc error: %v", err)
			return
		}
		for _, one := range entries {
			path := one.Name()
			if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
				if poc, _ := lib.LoadPoc(path, Pocs); poc != nil {
					AllPocs = append(AllPocs, poc)
				}
			}
		}
	} else {
		fmt.Println("[+] load poc from " + Config.PocPath)
		err := filepath.Walk(Config.PocPath,
			func(path string, info os.FileInfo, err error) error {
				if err != nil || info == nil {
					return err
				}
				if !info.IsDir() {
					if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
						poc, _ := lib.LoadPocbyPath(path)
						if poc != nil {
							AllPocs = append(AllPocs, poc)
						}
					}
				}
				return nil
			})
		if err != nil {
			fmt.Printf("[-] init poc error: %v", err)
		}
	}
}

func filterPoc(pocname string) (pocs []*lib.Poc) {
	if pocname == "" {
		return AllPocs
	}
	for _, poc := range AllPocs {
		if strings.Contains(poc.Name, pocname) {
			pocs = append(pocs, poc)
		}
	}
	return
}
