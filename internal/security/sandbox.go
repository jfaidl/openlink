package security

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// SafePath joins rootDir+targetPath and validates the result stays within rootDir.
// targetPath must be relative.
func SafePath(rootDir, targetPath string) (string, error) {
	absRoot, err := filepath.EvalSymlinks(rootDir)
	if err != nil {
		absRoot, err = filepath.Abs(rootDir)
		if err != nil {
			return "", err
		}
	}
	joined := filepath.Join(absRoot, targetPath)
	// EvalSymlinks 解析符号链接；文件不存在时（新建场景）fallback 到 Abs
	absTarget, err := filepath.EvalSymlinks(joined)
	if err != nil {
		absTarget, err = filepath.Abs(joined)
		if err != nil {
			return "", err
		}
	}
	if !strings.HasPrefix(absTarget, absRoot+string(filepath.Separator)) && absTarget != absRoot {
		return "", errors.New("path outside sandbox")
	}
	return absTarget, nil
}

// SafeAbsPath validates an already-absolute (or ~-prefixed) path against one or more allowed roots.
func SafeAbsPath(targetPath string, allowedRoots ...string) (string, error) {
	if strings.HasPrefix(targetPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		targetPath = filepath.Join(home, targetPath[2:])
	}
	if !filepath.IsAbs(targetPath) {
		return "", errors.New("not an absolute path")
	}
	absTarget, err := filepath.EvalSymlinks(targetPath)
	if err != nil {
		absTarget, err = filepath.Abs(targetPath)
		if err != nil {
			return "", err
		}
	}
	for _, rootDir := range allowedRoots {
		absRoot, err := filepath.EvalSymlinks(rootDir)
		if err != nil {
			absRoot, err = filepath.Abs(rootDir)
			if err != nil {
				continue
			}
		}
		if strings.HasPrefix(absTarget, absRoot+string(filepath.Separator)) || absTarget == absRoot {
			return absTarget, nil
		}
	}
	return "", errors.New("path outside sandbox")
}

var DangerousCommands = []string{
	"rm -rf", "rm -fr", "mkfs", "dd", "format",
	"> /dev/", "curl", "wget", "nc", "netcat",
	"sudo", "chmod 777", "kill -9", "reboot", "shutdown",
}
// 预编译正则：匹配单词边界，避免子串误判
// 例如：\bdd\b 能匹配 "dd" 但不匹配 "add"
var dangerousPatterns []*regexp.Regexp

func init() {
	dangerousPatterns = make([]*regexp.Regexp, 0, len(DangerousCommands))
	for _, cmd := range DangerousCommands {
		// 对多词命令（如 "rm -rf"）做特殊处理：允许中间有任意空白
		// 将多个空格规范化为 \s+
		patternStr := strings.ReplaceAll(regexp.QuoteMeta(cmd), " ", "\\s+")
		// 添加单词边界：确保不是其他词的一部分
		// 注意：> /dev/ 这类含符号的命令，不能用 \b，改用前后非字母数字判断
		if strings.HasPrefix(cmd, ">") || strings.ContainsAny(cmd, "/") {
			// 对于含路径或重定向的命令，使用前后非 alphanumeric + 空白/开头结尾 来界定
			patternStr = "(?:^|\\s)" + patternStr + "(?:\\s|$)"
		} else {
			// 普通命令使用 \b 单词边界
			patternStr = "\\b" + patternStr + "\\b"
		}
		re, err := regexp.Compile("(?i)" + patternStr) // (?i) 表示忽略大小写
		if err != nil {
			// 理论上不会出错，因为 QuoteMeta 已转义
			continue
		}
		dangerousPatterns = append(dangerousPatterns, re)
	}
}

func IsDangerousCommand(cmd string) bool {
	for _, re := range dangerousPatterns {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}
