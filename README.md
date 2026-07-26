# Cockpit IP Unblock

Cockpit 插件：查看并安全解除 iptables、fail2ban、firewalld 与 UFW 的 IP 封禁。系统会自动检测可用来源。

## 管理员配置

安装后编辑 `/etc/cockpit-ip-unblock.conf`：

```json
{
  "access_mode": "sudo_only",
  "daily_unblock_limit": 5,
  "show_recent_history": true
}
```

- `access_mode`: `sudo_only` 或 `all_users`。
- `daily_unblock_limit`: 普通用户每日额度；`0` 不限额。sudo 用户始终不限额。
- `show_recent_history`: 是否显示今日解封记录。

安装脚本仅在配置不存在时创建默认配置，不会覆盖现有设置。
