# 可配置解封策略 Implementation Plan

**Goal:** 用管理员 JSON 配置控制权限、每日额度和今日记录显示。

### Task 1: 配置加载与策略测试

- [ ] 在 `tests/test_cockpit_ip_unblock_helper.py` 先新增缺失/无效配置回退、自定义额度、无限额度、访问模式和记录开关的失败测试。
- [ ] 在 helper 新增 `CONFIG_FILE`、安全默认值和 `load_policy()`；严格校验 JSON 类型和值，配置错误审计并回退。
- [ ] 让授权、`get_quota`、`consume_quota`、`cmd_list`、`cmd_recent` 使用策略；后端返回 `show_recent_history`。
- [ ] 运行 `py -3 -m unittest discover -s tests -v` 与 `py -3 -m py_compile usr-local-bin/cockpit-ip-unblock-helper`。

### Task 2: 前端与安装部署

- [ ] 为 `show_recent_history` 写前端契约失败测试。
- [ ] 前端仅在开关为 true 时请求/展示完整记录卡片，否则隐藏卡片。
- [ ] 新增默认 `cockpit-ip-unblock.conf` 模板；安装脚本仅在 `/etc/cockpit-ip-unblock.conf` 不存在时安装它。
- [ ] 更新 README 配置说明；运行全量测试、`node --check`、`bash -n install.sh` 和 `git diff --check`。

### Task 3: WSL 验证

- [ ] 部署更新插件到 WSL，验证已有配置不被覆盖。
- [ ] 以 mxy 验证默认策略、自定义额度、记录隐藏和 `sudo_only` 拒绝路径。
