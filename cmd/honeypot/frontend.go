package main

import (
	"net/http"
	"os"
	"path/filepath"
)

// getFrontendFS 返回前端静态文件系统。
// 按优先级尝试:
//   1. web/dist/ (生产构建)
//   2. web/ (Vite 开发模式，可能不完整但可降级)
// 若均不存在返回 nil，API 服务器将提示用户构建前端。
func getFrontendFS(cfgDir string) http.FileSystem {
	// 优先使用生产构建产物
	distDir := filepath.Join(cfgDir, "web", "dist")
	if info, err := os.Stat(filepath.Join(distDir, "index.html")); err == nil && info != nil {
		return http.Dir(distDir)
	}
	// 降级：检查是否有 web/ 目录（至少有个 index.html）
	webDir := filepath.Join(cfgDir, "web")
	if info, err := os.Stat(filepath.Join(webDir, "index.html")); err == nil && info != nil {
		return http.Dir(webDir)
	}
	return nil
}
