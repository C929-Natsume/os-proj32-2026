系统使用 SQLite 数据库，文件位于 logs/alerts/analysis.db（约 26.7 MB）。
包含 3 张表：
表名
events
anomalies
audit_results
查看数据示例：
# 查看所有表
sqlite3 logs/alerts/analysis.db ".tables"

# 查看表结构
sqlite3 logs/alerts/analysis.db ".schema"

# 查看行数统计
sqlite3 logs/alerts/analysis.db "SELECT 'events', COUNT(*) FROM events UNION ALL SELECT 'anomalies', COUNT(*) FROM anomalies UNION ALL SELECT 'audit_results', COUNT(*) FROM audit_results;"

# 查看最近的异常
sqlite3 -header -column logs/alerts/analysis.db "SELECT anomaly_id, rule, severity, pid, comm, reason FROM anomalies ORDER BY id DESC LIMIT 10;"

# 查看事件类型分布（事件类型码：1=execve, 3=open, 5=connect, 6=SSL读写等）
sqlite3 -header -column logs/alerts/analysis.db "SELECT event_type, COUNT(*) as cnt FROM events GROUP BY event_type ORDER BY event_type;"

# 查看审计结果
sqlite3 -header -column logs/alerts/analysis.db "SELECT pid, comm, rule, severity, json_extract(result_json, '$.decision') as decision FROM audit_results;"
