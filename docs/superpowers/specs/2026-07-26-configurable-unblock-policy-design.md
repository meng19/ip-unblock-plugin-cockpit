# 可配置解封策略设计

## 目标

将访问权限、每日解封额度与今日记录显示从 helper 的硬编码常量迁移到管理员管理的配置文件。

## 配置

安装路径为 `/etc/cockpit-ip-unblock.conf`，JSON 格式：

```json
{
  "access_mode": "sudo_only",
  "daily_unblock_limit": 5,
  "show_recent_history": true
}
```

- `access_mode` 仅允许 `all_users` 或 `sudo_only`。
- `daily_unblock_limit` 为非负整数；`0` 表示无限额。
- `show_recent_history` 为布尔值。

配置不存在、无法读取或字段无效时，使用安全默认值：仅 sudo 用户、每日 5 次、显示记录；同时写入审计日志。安装只在配置文件不存在时复制默认模板，绝不覆盖现有配置。

## 行为

Helper 在每次请求加载并校验配置。`sudo_only` 对非 sudo 用户返回结构化拒绝结果；额度使用配置值；无限额度不消耗状态。`list` 返回 `show_recent_history`，前端仅在该值为 true 时请求并显示完整的今日记录卡片。

## 验证

新增标准库单元测试覆盖缺失/无效配置的安全回退、两种访问模式、额度 0 与自定义额度、记录开关及安装脚本不覆盖配置。WSL 部署后以 mxy 验证默认策略和自定义策略。
