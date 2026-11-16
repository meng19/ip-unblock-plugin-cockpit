# Cockpit IP Unblock

Cockpit 插件：查看并安全解除 iptables、fail2ban、firewalld 与 UFW 的 IP 封禁。系统会自动检测可用来源。

## 服务器自助解封功能介绍

本功能用于在服务器触发 IP 封禁后，由用户通过 Cockpit 页面自助查看封禁来源并提交解封操作，减少人工工单处理。页面会汇总 iptables、fail2ban、firewalld 与 UFW 中可识别的精确 IP 封禁记录，并显示封禁来源、规则详情和位置信息。

访问入口需要放在受密码保护的页面或系统登录之后。不要在公开页面暴露 Cockpit 地址、服务器管理地址、访问密码或可直接执行解封的链接。推荐做法是将说明文章设置为密码保护，仅在文章中说明访问方式和使用规则；真正的解封操作仍由 Cockpit 登录、`allowed_users` 授权、每日额度和后端审计共同保护。

给用户发布使用说明时，应提示用户先访问 `https://ip.ustc.edu.cn` 确认当前公网 IP；如果该网络已经无法打开解封网站，需要切换到其他网络访问解封入口，例如手机热点、备用网络、VPN、堡垒机或管理员提供的备用访问路径。

权限行为：

- `allowed_users` 内的用户可以查看并解封，普通用户受每日额度限制。
- 不在 `allowed_users` 内且 `allow_readonly_view` 为 `true` 的用户只能查看封禁 IP，解封按钮置灰。
- `allow_readonly_view` 为 `false` 时，未授权用户不能查看封禁列表。
- sudo 组用户始终不限解封次数。

## 管理员配置

安装后编辑 `/etc/cockpit-ip-unblock.conf`：

```json
{
  "access_mode": "sudo_only",
  "allowed_users": ["alice", "bob"],
  "allow_readonly_view": true,
  "daily_unblock_limit": 5,
  "show_recent_history": true
}
```

- `access_mode`: `sudo_only` 或 `all_users`。
- `allowed_users`: 在 `sudo_only` 模式下额外授权的普通用户名列表；这些用户按每日额度限制使用。
- `allow_readonly_view`: `true` 时，未被授权解封的用户仍可查看封禁 IP，但解封按钮置灰；`false` 时未授权用户不能查看列表。
- `daily_unblock_limit`: 普通用户每日额度；`0` 不限额。sudo 用户始终不限额。
- `show_recent_history`: 是否显示今日解封记录。

## 批量解封

获授权用户可在页面中勾选多个 IP 并按当前来源批量解封。普通用户每成功解封一个 IP 消耗一次每日额度；额度耗尽时，插件会停止并报告未处理的 IP。sudo 用户不限额。

安装脚本仅在配置不存在时创建默认配置，不会覆盖现有设置。
