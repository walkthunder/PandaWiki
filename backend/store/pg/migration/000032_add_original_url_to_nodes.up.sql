-- 添加 original_url 字段到 nodes 表
-- 用于存储从第三方网站导入的文档的原始链接

ALTER TABLE nodes ADD COLUMN IF NOT EXISTS original_url TEXT DEFAULT '';

-- 为 original_url 字段添加注释
COMMENT ON COLUMN nodes.original_url IS '第三方网站的原始链接';
