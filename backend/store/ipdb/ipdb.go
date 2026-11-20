package ipdb

import (
	"bytes"
	"embed"
	"fmt"
	"strings"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"

	"github.com/chaitin/panda-wiki/config"
	"github.com/chaitin/panda-wiki/domain"
	"github.com/chaitin/panda-wiki/log"
)

//go:embed ip2region.xdb
var ipdbFiles embed.FS

// gitLFSPointerPrefix 是 Git LFS 指针文件的特征头。
// 如果构建时没有执行 git lfs pull，embed 进来的会是一个约 133 字节的文本指针，
// xdb  searcher 用这种数据查询会直接 panic（slice bounds out of range）导致进程崩溃。
var gitLFSPointerPrefix = []byte("version https://git-lfs.github.com/spec/")

// minXDBSize 真实 ip2region.xdb 约 11MB，远小于该阈值的文件必定是无效数据。
const minXDBSize = 1 << 20

type IPDB struct {
	searcher *xdb.Searcher
	logger   *log.Logger
}

// NewIPDB 加载 IP 地址库。数据库文件无效（如 LFS 指针）时降级为不可用状态并仅记录告警，
// 不返回 error，避免进程启动失败或运行时 panic；此时 Lookup 会返回错误，由上层兜底为"未知地址"。
func NewIPDB(config *config.Config, logger *log.Logger) (*IPDB, error) {
	ipdbLogger := logger.WithModule("store.ipdb")
	cBuff, err := xdb.LoadContentFromFS(ipdbFiles, "ip2region.xdb")
	if err != nil {
		return nil, fmt.Errorf("load xdb index failed: %w", err)
	}
	if bytes.HasPrefix(cBuff, gitLFSPointerPrefix) || len(cBuff) < minXDBSize {
		ipdbLogger.Warn("ip2region.xdb is invalid (looks like a Git LFS pointer file, run 'git lfs pull' and rebuild); IP geolocation is disabled",
			log.Int("size", len(cBuff)))
		return &IPDB{searcher: nil, logger: ipdbLogger}, nil
	}
	searcher, err := xdb.NewWithBuffer(cBuff)
	if err != nil {
		return nil, fmt.Errorf("new xdb reader failed: %w", err)
	}
	return &IPDB{searcher: searcher, logger: ipdbLogger}, nil
}

func (a *IPDB) Lookup(ip string) (addr *domain.IPAddress, err error) {
	if a.searcher == nil {
		return nil, fmt.Errorf("ip2region database is not available")
	}
	// 防御：xdb 内部对损坏数据的越界访问会 panic，这里兜底转换为 error，
	// 避免单个 IP 查询导致整个进程崩溃。
	defer func() {
		if r := recover(); r != nil {
			a.logger.Error("ip2region search panic recovered", log.Any("panic", r), log.String("ip", ip))
			addr = nil
			err = fmt.Errorf("ip2region search panic: %v", r)
		}
	}()
	region, err := a.searcher.SearchByStr(ip)
	if err != nil {
		return nil, fmt.Errorf("search ip failed: %w", err)
	}
	ipInfo := strings.Split(region, "|")
	if len(ipInfo) != 5 {
		return nil, fmt.Errorf("invalid ip info: %s", region)
	}
	country := ipInfo[0]
	province := ipInfo[2]
	city := ipInfo[3]
	if country == "0" {
		country = "未知"
	}
	if province == "0" {
		province = "未知"
	}
	if city == "0" {
		city = "未知"
	}
	return &domain.IPAddress{
		IP:       ip,
		Country:  country,
		Province: province,
		City:     city,
	}, nil
}
