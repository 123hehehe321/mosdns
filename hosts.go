/*
 * Copyright (C) 2020-2022, IrineSistiana
 * 编译命令： go build -ldflags="-s -w" -o mosdns ./main.go
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package hosts

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/IrineSistiana/mosdns/v5/pkg/hosts"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

const PluginType = "hosts"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

var _ sequence.Executable = (*Hosts)(nil)

// Args 配置参数
type Args struct {
	Entries     []string `yaml:"entries"`
	Files       []string `yaml:"files"`
	UpdateHours int      `yaml:"update_hours"` // 远程更新间隔（小时），0=不自动更新
	CacheDir    string   `yaml:"cache_dir"`    // 远程文件本地缓存目录
	OverrideIP  string   `yaml:"override_ip"`  // 新增：覆盖所有规则的目标IP，留空则使用文件原始IP
}

// remoteEntry 单个远程规则文件
type remoteEntry struct {
	url       string
	localPath string
	lastHash  [16]byte
}

// Hosts 插件主体
type Hosts struct {
	h           atomic.Pointer[hosts.Hosts] // 原子指针，查询路径零锁
	reloadMu    sync.Mutex                  // reload 互斥锁，防止并发构建
	entries     []string
	localFiles  []string
	remoteFiles []*remoteEntry
	updateHours int
	overrideIP  net.IP // 解析后的覆盖IP，nil表示不覆盖
	stopCh      chan struct{}
}

func Init(_ *coremain.BP, args any) (any, error) {
	return NewHosts(args.(*Args))
}

func NewHosts(args *Args) (*Hosts, error) {
	cacheDir := args.CacheDir
	if cacheDir == "" {
		cacheDir = "/root/mosdns/remote_cache"
	}
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache dir %s: %w", cacheDir, err)
	}

	plugin := &Hosts{
		entries:     args.Entries,
		localFiles:  []string{},
		remoteFiles: []*remoteEntry{},
		updateHours: args.UpdateHours,
		stopCh:      make(chan struct{}),
	}

	// 解析 override_ip
	if args.OverrideIP != "" {
		ip := net.ParseIP(args.OverrideIP)
		if ip == nil {
			return nil, fmt.Errorf("invalid override_ip: %s", args.OverrideIP)
		}
		plugin.overrideIP = ip
		mlog.S().Infof("[hosts] override_ip enabled: all rules will resolve to %s", args.OverrideIP)
	}

	// 分类本地文件和远程 URL
	for i, f := range args.Files {
		if strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://") {
			localPath := filepath.Join(cacheDir, fmt.Sprintf("remote_%d.txt", i))
			plugin.remoteFiles = append(plugin.remoteFiles, &remoteEntry{
				url:       f,
				localPath: localPath,
			})
		} else {
			plugin.localFiles = append(plugin.localFiles, f)
		}
	}

	// 第一步：从本地文件（含远程缓存）加载，保证无网络也能启动
	plugin.initFromLocal()

	// 第二步：异步拉取远程更新，不阻塞启动
	if len(plugin.remoteFiles) > 0 {
		go plugin.fetchAndReload()
	}

	// 第三步：启动定时更新
	if args.UpdateHours > 0 && len(plugin.remoteFiles) > 0 {
		go plugin.autoUpdate()
	}

	return plugin, nil
}

// initFromLocal 从本地文件（含已保存的远程缓存）初始化规则
func (h *Hosts) initFromLocal() {
	for _, rf := range h.remoteFiles {
		data, err := os.ReadFile(rf.localPath)
		if err == nil {
			rf.lastHash = md5.Sum(data)
		}
	}
	if err := h.reload(); err != nil {
		mlog.S().Warnf("[hosts] initial load failed: %v", err)
	} else {
		mlog.S().Infof("[hosts] initial load completed")
	}
}

// fetchAndReload 拉取所有远程文件，有变化则重载
func (h *Hosts) fetchAndReload() {
	changed := false

	for _, rf := range h.remoteFiles {
		data, err := fetchURL(rf.url)
		if err != nil {
			mlog.S().Warnf("[hosts] fetch failed %s: %v, using local cache", rf.url, err)
			continue
		}

		newHash := md5.Sum(data)
		if newHash == rf.lastHash {
			continue // 内容未变化
		}

		// 先写临时文件再 rename，保证写入原子性
		tmpPath := rf.localPath + ".tmp"
		if err := os.WriteFile(tmpPath, data, 0644); err != nil {
			mlog.S().Warnf("[hosts] write temp file failed %s: %v", tmpPath, err)
			continue
		}
		if err := os.Rename(tmpPath, rf.localPath); err != nil {
			mlog.S().Warnf("[hosts] rename failed %s -> %s: %v", tmpPath, rf.localPath, err)
			os.Remove(tmpPath)
			continue
		}

		rf.lastHash = newHash
		changed = true
		mlog.S().Infof("[hosts] remote rule updated: %s", rf.url)
	}

	if changed {
		if err := h.reload(); err != nil {
			mlog.S().Warnf("[hosts] reload after update failed: %v", err)
		} else {
			mlog.S().Infof("[hosts] rules reloaded successfully")
		}
	}
}

// reload 从所有本地文件重新构建规则并原子替换
func (h *Hosts) reload() error {
	h.reloadMu.Lock()
	defer h.reloadMu.Unlock()

	m := domain.NewMixMatcher[*hosts.IPs]()
	m.SetDefaultMatcher(domain.MatcherFull)

	// 1. 加载 entries
	for i, entry := range h.entries {
		if err := domain.Load[*hosts.IPs](m, entry, hosts.ParseIPs); err != nil {
			return fmt.Errorf("failed to load entry #%d %q: %w", i, entry, err)
		}
	}

	// 2. 加载本地规则文件
	for _, file := range h.localFiles {
		if err := h.loadFile(m, file); err != nil {
			return fmt.Errorf("failed to load local file %s: %w", file, err)
		}
	}

	// 3. 加载远程规则的本地缓存
	for _, rf := range h.remoteFiles {
		if err := h.loadFile(m, rf.localPath); err != nil {
			mlog.S().Infof("[hosts] remote cache not ready %s, skipping", rf.url)
			continue
		}
	}

	// 原子替换，零中断
	h.h.Store(hosts.NewHosts(m))
	return nil
}

// loadFile 从文件加载规则到 MixMatcher
// 如果配置了 override_ip，则对每一行替换其 IP 部分
func (h *Hosts) loadFile(m *domain.MixMatcher[*hosts.IPs], path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// 没有配置 override_ip，直接用原始文件内容
	if h.overrideIP == nil {
		return domain.LoadFromTextReader[*hosts.IPs](m, bytes.NewReader(b), hosts.ParseIPs)
	}

	// 有 override_ip，逐行处理替换IP后再加载
	processed := h.processWithOverrideIP(b)
	return domain.LoadFromTextReader[*hosts.IPs](m, bytes.NewReader(processed), hosts.ParseIPs)
}

// processWithOverrideIP 把规则文件中每行的 IP 部分替换为 override_ip
// 支持以下格式：
//   domain:example.com 1.2.3.4
//   domain:example.com          （无IP，直接追加）
//   regexp:^xxx\.com$ 1.2.3.4
//   # 注释行（原样保留）
//   空行（原样保留）
func (h *Hosts) processWithOverrideIP(data []byte) []byte {
	ipStr := h.overrideIP.String()
	var buf bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// 空行或注释行原样保留
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			buf.WriteString(line)
			buf.WriteByte('\n')
			continue
		}

		// 分割行内容
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			buf.WriteString(line)
			buf.WriteByte('\n')
			continue
		}

		// 取规则部分（第一个字段），替换或追加 IP
		// 输出格式：规则 IP
		buf.WriteString(fields[0])
		buf.WriteByte(' ')
		buf.WriteString(ipStr)
		buf.WriteByte('\n')
	}

	return buf.Bytes()
}

// autoUpdate 定时更新协程
func (h *Hosts) autoUpdate() {
	interval := time.Duration(h.updateHours) * time.Hour
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.fetchAndReload()
		case <-h.stopCh:
			return
		}
	}
}

// fetchURL 下载远程文件，限制 10MB，超时 30 秒
func fetchURL(url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
}

// Response 直接查询接口
func (h *Hosts) Response(q *dns.Msg) *dns.Msg {
	return h.h.Load().LookupMsg(q)
}

// Exec 查询执行入口（sequence.Executable 接口）
func (h *Hosts) Exec(_ context.Context, qCtx *query_context.Context) error {
	r := h.h.Load().LookupMsg(qCtx.Q())
	if r != nil {
		qCtx.SetResponse(r)
	}
	return nil
}

// Close 优雅停止定时更新协程
func (h *Hosts) Close() error {
	close(h.stopCh)
	return nil
}
