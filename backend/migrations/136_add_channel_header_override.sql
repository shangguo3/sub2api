-- 渠道请求头覆盖：允许管理员为每个渠道配置自定义上游请求 header
ALTER TABLE channels ADD COLUMN IF NOT EXISTS header_override TEXT DEFAULT '';
COMMENT ON COLUMN channels.header_override IS '渠道请求头覆盖配置（JSON 对象），用于自定义上游请求 header';
