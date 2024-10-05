package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type ReplacementRule struct {
	Pattern     string `json:"pattern"`
	Replacement string `json:"replacement"`
}

type HostRules struct {
	Hosts         []string          `json:"hosts"`
	Replacements  []ReplacementRule  `json:"replacements"`
	DeleteHeaders []string          `json:"deleteHeaders"`
	AddHeaders    map[string]string  `json:"addHeaders"` // 新增字段用于添加请求头
}

type ServerConfig struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	SizeLimit int64  `json:"sizeLimit"`
}

type Config struct {
	Whitelist []string       `json:"whitelist"`
	Rules     []HostRules    `json:"rules"`
	Server    ServerConfig   `json:"server"`
}

var (
	defaultExps = []*regexp.Regexp{
		regexp.MustCompile(`^(?:https?://)?github\.com/([^/]+)/([^/]+)/(?:releases|archive)/.*$`),
		regexp.MustCompile(`^(?:https?://)?github\.com/([^/]+)/([^/]+)/(?:blob|raw)/.*$`),
		regexp.MustCompile(`^(?:https?://)?github\.com/([^/]+)/([^/]+)/(?:info|git-).*$`),
		regexp.MustCompile(`^(?:https?://)?raw\.githubusercontent\.com/([^/]+)/([^/]+)/.+?/.+$`),
		regexp.MustCompile(`^(?:https?://)?gist\.github\.com/([^/]+)/.+?/.+$`),
	}

	rules     = make([]HostRules, 0)
	whitelist = []*regexp.Regexp{}
	exps      = []*regexp.Regexp{}
	config    = &Config{
		Server: ServerConfig{
			Host:      "0.0.0.0",
			Port:      8888,
			SizeLimit: 1024 * 1024 * 1024, // 1 GB
		},
	}
)

func main() {
	gin.SetMode(gin.ReleaseMode)

	// 加载配置
	loadConfig("config.json")

	// 加载白名单
	loadWhitelist(config.Whitelist)

	// 合并默认的 exps 和白名单
	mergeExps()

	// 加载并合并规则
	loadAndMergeRules()

	router := gin.Default()

	router.GET("/", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte("Server is running..."))
	})

	router.GET("/favicon.ico", func(c *gin.Context) {
		c.Status(404)
	})

	router.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})

	router.NoRoute(handler)

	err := router.Run(fmt.Sprintf("%s:%d", config.Server.Host, config.Server.Port))
	if err != nil {
		fmt.Printf("Error starting server: %v\n", err)
	}
}

func loadConfig(file string) {
	configFile, err := os.Open(file)
	if os.IsNotExist(err) {
		return // 文件不存在，使用默认配置
	} else if err != nil {
		fmt.Println("Error opening config file:", err)
		return
	}
	defer configFile.Close()

	if err := json.NewDecoder(configFile).Decode(config); err != nil {
		fmt.Println("Error decoding config file:", err)
	}
}

func loadWhitelist(whitelistStr []string) {
	for _, pattern := range whitelistStr {
		re := regexp.MustCompile(pattern)
		whitelist = append(whitelist, re)
	}
}

func mergeExps() {
	uniqueExps := make(map[string]*regexp.Regexp)

	// 添加默认的 exps
	for _, exp := range defaultExps {
		uniqueExps[exp.String()] = exp
	}

	// 添加白名单中的正则表达式
	for _, re := range whitelist {
		uniqueExps[re.String()] = re
	}

	// 转换为切片
	for _, exp := range uniqueExps {
		exps = append(exps, exp)
	}
}

func loadAndMergeRules() {
	// 默认规则
	defaultRules := HostRules{
		Hosts: []string{"github.com", "gist.github.com", "raw.githubusercontent.com"},
		Replacements: []ReplacementRule{
			{
				Pattern:     "/blob/",
				Replacement: "/raw/",
			},
		},
		DeleteHeaders: []string{
			"Content-Security-Policy",
			"Referrer-Policy",
			"Strict-Transport-Security",
		},
		AddHeaders: map[string]string{
			"Authorization": "Bearer your_token", // 默认请求头
		},
	}
	rules = append(rules, defaultRules)

	// 加载配置中的规则
	for _, ruleSet := range config.Rules {
		mergeRuleSet(ruleSet)
	}
}

func mergeRuleSet(newRuleSet HostRules) {
	for i, ruleSet := range rules {
		for _, newHost := range newRuleSet.Hosts {
			for _, existingHost := range ruleSet.Hosts {
				if newHost == existingHost {
					// 覆盖现有规则
					rules[i] = newRuleSet
					return
				}
			}
		}
	}
	// 如果没有匹配，添加新规则
	rules = append(rules, newRuleSet)
}

func handler(c *gin.Context) {
	rawPath := strings.TrimPrefix(c.Request.URL.RequestURI(), "/")

	// 检查 URL 是否匹配合并后的正则表达式
	if strings.HasPrefix(rawPath, "https://") || strings.HasPrefix(rawPath, "http://") {
		rawPath = rawPath
	} else {
		rawPath = "https://" + rawPath // Prepend "https://" if missing
	}

	matches := checkURL(rawPath)
	if matches == nil {
		c.String(http.StatusForbidden, "Invalid input.")
		return
	}

	urlHost := extractHost(rawPath)

	// 检查是否在白名单中
	if !isInWhitelist(urlHost) {
		c.String(http.StatusForbidden, "Host not allowed.")
		return
	}

	// 获取对应的规则
	var ruleSet HostRules
	for _, r := range rules {
		for _, host := range r.Hosts {
			if host == urlHost {
				ruleSet = r
				break
			}
		}
	}

	// 应用替换规则和添加请求头
	for _, rule := range ruleSet.Replacements {
		re := regexp.MustCompile(rule.Pattern)
		rawPath = re.ReplaceAllString(rawPath, rule.Replacement)
	}

	for key, value := range ruleSet.AddHeaders {
		c.Request.Header.Set(key, value) // 设置或覆盖请求头
	}

	proxy(c, rawPath, ruleSet)
}

func checkURL(u string) []string {
	for _, exp := range exps {
		if matches := exp.FindStringSubmatch(u); matches != nil {
			return matches[1:]
		}
	}
	return nil
}

func proxy(c *gin.Context, u string, ruleSet HostRules) {
	req, err := http.NewRequest(c.Request.Method, u, c.Request.Body)
	if err != nil {
		c.String(http.StatusInternalServerError, fmt.Sprintf("server error %v", err))
		return
	}

	for key, values := range c.Request.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	req.Header.Del("Host")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.String(http.StatusInternalServerError, fmt.Sprintf("server error %v", err))
		return
	}
	defer resp.Body.Close()

	// 转换 SizeLimit 为 int
	if contentLength, ok := resp.Header["Content-Length"]; ok {
		if size, err := strconv.Atoi(contentLength[0]); err == nil && int64(size) > config.Server.SizeLimit {
			finalURL := resp.Request.URL.String()
			c.Redirect(http.StatusFound, finalURL)
			return
		}
	}

	// 设置响应头
	for key, values := range resp.Header {
		for _, value := range values {
			c.Header(key, value)
		}
	}

	// 删除指定头部
	deleteHeaders(c, ruleSet.DeleteHeaders)

	// 使用 io.Pipe 进行非阻塞写入
	pipeReader, pipeWriter := io.Pipe()
	go func() {
		defer pipeWriter.Close()
		if _, err := io.Copy(pipeWriter, resp.Body); err != nil {
			fmt.Printf("Error writing to pipe: %v\n", err)
		}
	}()

	if _, err := io.Copy(c.Writer, pipeReader); err != nil {
		fmt.Printf("Error writing to response: %v\n", err)
	}
}

func deleteHeaders(c *gin.Context, headers []string) {
	for _, header := range headers {
		c.Header(header, "") // 删除响应头
	}
}

func extractHost(u string) string {
	re := regexp.MustCompile(`^(?:https?://)?([^/]+)`)
	matches := re.FindStringSubmatch(u)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func isInWhitelist(host string) bool {
	for _, re := range whitelist {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}
