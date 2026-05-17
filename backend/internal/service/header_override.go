package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
)

// --- Context key for header override group ID ---

type headerOverrideGroupIDKey struct{}

// WithHeaderOverrideGroupID 将 groupID 注入 context，供 buildUpstreamRequest 查找渠道请求头覆盖。
func WithHeaderOverrideGroupID(ctx context.Context, groupID int64) context.Context {
	return context.WithValue(ctx, headerOverrideGroupIDKey{}, groupID)
}

// HeaderOverrideGroupIDFromContext 从 context 中提取请求头覆盖用的 groupID。
func HeaderOverrideGroupIDFromContext(ctx context.Context) (int64, bool) {
	v, ok := ctx.Value(headerOverrideGroupIDKey{}).(int64)
	return v, ok
}

// unsafePassthroughHeaders 通配符/正则透传时应跳过的不安全 header（全小写）。
// 显式覆盖（非透传）仍可设置这些 header（如 authorization）。
var unsafePassthroughHeaders = map[string]bool{
	"host":                      true,
	"content-length":            true,
	"transfer-encoding":         true,
	"connection":                true,
	"keep-alive":                true,
	"upgrade":                   true,
	"te":                        true,
	"trailer":                   true,
	"proxy-authenticate":        true,
	"proxy-authorization":       true,
	"cookie":                    true,
	"accept-encoding":           true,
	"authorization":             true,
	"x-api-key":                 true,
	"x-goog-api-key":            true,
	"sec-websocket-key":         true,
	"sec-websocket-version":     true,
	"sec-websocket-extensions":  true,
}

// headerOverrideEntry 解析后的单条请求头覆盖配置
type headerOverrideEntry struct {
	key        string         // header key 或 "*" 或 "re:<pattern>"
	value      string         // header 值模板（显式覆盖）
	isWildcard bool           // "*": true
	isRegex    bool           // "re:<pattern>": true 或 "regex:<pattern>": true
	regex      *regexp.Regexp // 编译后的正则（isRegex 为 true 时有效）
}

// HeaderOverrideConfig 解析后的请求头覆盖配置
type HeaderOverrideConfig struct {
	passthroughEntries []headerOverrideEntry // 通配符和正则透传条目
	overrideEntries    []headerOverrideEntry // 显式覆盖条目（优先级高于透传）
}

// ParseHeaderOverride 解析 header_override JSON 字符串。
// 返回 nil 表示输入为空或无效。
func ParseHeaderOverride(raw *string) *HeaderOverrideConfig {
	if raw == nil || *raw == "" {
		return nil
	}

	var rawMap map[string]interface{}
	if err := json.Unmarshal([]byte(*raw), &rawMap); err != nil {
		slog.Warn("header_override: failed to parse JSON", "error", err)
		return nil
	}
	if len(rawMap) == 0 {
		return nil
	}

	config := &HeaderOverrideConfig{}

	for key, value := range rawMap {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}

		// 通配符透传：{"*": true}
		if key == "*" {
			if boolVal, ok := value.(bool); ok && boolVal {
				config.passthroughEntries = append(config.passthroughEntries, headerOverrideEntry{
					key:        "*",
					isWildcard: true,
				})
			}
			continue
		}

		// 正则透传：{"re:<pattern>": true} 或 {"regex:<pattern>": true}
		lowerKey := strings.ToLower(key)
		if strings.HasPrefix(lowerKey, "re:") || strings.HasPrefix(lowerKey, "regex:") {
			if boolVal, ok := value.(bool); ok && boolVal {
				var pattern string
				if strings.HasPrefix(lowerKey, "regex:") {
					pattern = strings.TrimSpace(key[6:])
				} else {
					pattern = strings.TrimSpace(key[3:])
				}
				if pattern == "" {
					slog.Warn("header_override: empty regex pattern", "key", key)
					continue
				}
				compiled, err := regexp.Compile(pattern)
				if err != nil {
					slog.Warn("header_override: invalid regex pattern", "pattern", pattern, "error", err)
					continue
				}
				config.passthroughEntries = append(config.passthroughEntries, headerOverrideEntry{
					key:     key,
					isRegex: true,
					regex:   compiled,
				})
			}
			continue
		}

		// 显式覆盖：{"Header-Name": "value"}
		strValue, ok := value.(string)
		if !ok {
			slog.Warn("header_override: non-string value, skipping", "key", key, "value_type", fmt.Sprintf("%T", value))
			continue
		}
		config.overrideEntries = append(config.overrideEntries, headerOverrideEntry{
			key:   key,
			value: strValue,
		})
	}

	if len(config.passthroughEntries) == 0 && len(config.overrideEntries) == 0 {
		return nil
	}
	return config
}

// Apply 将请求头覆盖配置应用到上游请求。
// 处理顺序：先透传（低优先级），再显式覆盖（高优先级）。
//
// 参数：
//   - req: 出站上游 http.Request（直接修改 headers）
//   - apiKey: 上游账号凭据（用于 {api_key} 占位符）
//   - clientHeaders: 客户端原始请求 headers（用于 {client_header:X-Foo} 和通配符透传）
func (c *HeaderOverrideConfig) Apply(req *http.Request, apiKey string, clientHeaders http.Header) {
	if c == nil {
		return
	}

	// 阶段 1：透传（低优先级）
	passedHeaders := make(map[string]bool) // 记录已透传的 header（lowercase key）
	for _, entry := range c.passthroughEntries {
		if entry.isWildcard {
			// 通配符：透传所有客户端 headers（排除不安全 headers）
			for key, values := range clientHeaders {
				lowerKey := strings.ToLower(key)
				if unsafePassthroughHeaders[lowerKey] {
					continue
				}
				if !passedHeaders[lowerKey] {
					for _, v := range values {
						req.Header.Set(key, v)
					}
					passedHeaders[lowerKey] = true
				}
			}
		} else if entry.isRegex && entry.regex != nil {
			// 正则：透传匹配的客户端 headers
			for key, values := range clientHeaders {
				lowerKey := strings.ToLower(key)
				if unsafePassthroughHeaders[lowerKey] {
					continue
				}
				if entry.regex.MatchString(key) || entry.regex.MatchString(lowerKey) {
					if !passedHeaders[lowerKey] {
						for _, v := range values {
							req.Header.Set(key, v)
						}
						passedHeaders[lowerKey] = true
					}
				}
			}
		}
	}

	// 阶段 2：显式覆盖（高优先级，覆盖透传和之前设置的 headers）
	for _, entry := range c.overrideEntries {
		resolved := resolvePlaceholders(entry.value, apiKey, clientHeaders)
		if resolved == "" {
			// {client_header:X-Foo} 解析为空时跳过（不设置空 header）
			continue
		}
		req.Header.Set(entry.key, resolved)
		// 特殊处理 Host header
		if strings.EqualFold(entry.key, "Host") {
			req.Host = resolved
		}
	}
}

// resolvePlaceholders 展开值模板中的占位符。
// 支持的占位符：
//   - {api_key}: 替换为上游账号凭据
//   - {client_header:X-Foo}: 替换为客户端请求中名为 X-Foo 的 header 值
func resolvePlaceholders(value, apiKey string, clientHeaders http.Header) string {
	if !strings.Contains(value, "{") {
		return value
	}

	// {api_key}
	value = strings.ReplaceAll(value, "{api_key}", apiKey)

	// {client_header:X-Foo}
	for {
		start := strings.Index(value, "{client_header:")
		if start == -1 {
			break
		}
		end := strings.Index(value[start:], "}")
		if end == -1 {
			break
		}
		end += start

		placeholder := value[start : end+1]
		headerName := strings.TrimSpace(value[start+len("{client_header:") : end])
		headerValue := clientHeaders.Get(headerName)

		// 如果整个值就是一个 {client_header:...} 占位符且客户端没有该 header，返回空字符串
		if headerValue == "" && placeholder == value {
			return ""
		}

		value = strings.Replace(value, placeholder, headerValue, 1)
	}

	return value
}

// ApplyChannelHeaderOverrideFromContext 是通用的渠道请求头覆盖入口。
// 从 context 提取 groupID，通过 ChannelService 查找渠道，解析并应用请求头覆盖。
// 适用于所有网关服务（Anthropic / OpenAI / Bedrock）。
func ApplyChannelHeaderOverrideFromContext(ctx context.Context, channelService *ChannelService, req *http.Request, token string, clientHeaders http.Header) {
	if channelService == nil {
		return
	}

	groupID, ok := HeaderOverrideGroupIDFromContext(ctx)
	if !ok || groupID == 0 {
		return
	}

	ch, err := channelService.GetChannelForGroup(ctx, groupID)
	if err != nil || ch == nil || !ch.IsActive() {
		return
	}

	override := ParseHeaderOverride(ch.HeaderOverride)
	if override != nil {
		override.Apply(req, token, clientHeaders)
	}
}
