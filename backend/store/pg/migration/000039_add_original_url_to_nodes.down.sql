-- 回滚：删除 original_url 字段
-- 注意：这将永久删除该字段的所有数据

ALTER TABLE nodes DROP COLUMN IF EXISTS original_url;
