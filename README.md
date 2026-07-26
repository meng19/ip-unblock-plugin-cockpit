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

## 批量解封

获授权用户可在页面中勾选多个 IP 并按当前来源批量解封。普通用户每成功解封一个 IP 消耗一次每日额度；额度耗尽时，插件会停止并报告未处理的 IP。sudo 用户不限额。

安装脚本仅在配置不存在时创建默认配置，不会覆盖现有设置。
