# 多来源 IP 解封 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** 支持安全、可选择的 iptables、fail2ban 与 firewalld IP 解封，并在 Cockpit 中显示跨来源结果。

**Architecture:** 保留单一特权 helper，将来源检测、列表和解封封装为适配器。统一编排层产出来源无关的 JSON；Cockpit 页面动态构建来源筛选器并呈现逐来源结果。

**Tech Stack:** Python 3 标准库（unittest、unittest.mock）、Cockpit JavaScript API、HTML/CSS。

## Global Constraints

- 仅在运行时命令和服务可用时支持 iptables、fail2ban-client、firewall-cmd。
- 每条命令必须使用 argv 数组，禁止 shell=True；来源只允许 all、iptables、fail2ban、firewalld。
- “全部”必须尝试每个可用来源；单一来源失败不得中断其他来源。
- 禁止清空链、reload 防火墙、删除 jail 或删除非精确 IP 的规则。
- 非 sudo 用户只有在至少成功删除一个封禁时消耗一次配额。
- 保持中英文同步，支持现有深色和移动端布局。

---

### Task 1: 建立可测试的命令执行器和 iptables 适配器

**Files:**

- Create: tests/test_cockpit_ip_unblock_helper.py
- Modify: usr-local-bin/cockpit-ip-unblock-helper:15-212

**Interfaces:**

- Produces: CommandResult(ok, stdout, stderr, unavailable) 和 run_command(argv)。
- Produces: IptablesAdapter.is_available()、list_blocks()、unblock(ip)。
- Produces: 统一记录 {"source", "ip", "rule", "target", "scope"}。

- [ ] **Step 1: 先写会失败的 iptables 测试**

~~~python
def test_iptables_lists_only_ip_specific_drop_or_reject(helper):
    output = "Chain INPUT\nnum target prot opt source destination\n1 DROP all -- 203.0.113.7 0.0.0.0/0\n"
    with mock.patch.object(helper, "run_command", return_value=ok(output)):
        records = helper.IptablesAdapter().list_blocks()
    assert records == [{"source": "iptables", "ip": "203.0.113.7",
                        "rule": "INPUT: DROP", "target": "DROP", "scope": "runtime"}]

def test_missing_iptables_is_not_available(helper):
    with mock.patch.object(helper, "run_command", return_value=unavailable("iptables")):
        assert helper.IptablesAdapter().is_available() is False
~~~

- [ ] **Step 2: 运行测试，确认因适配器不存在而失败**

Run: python3 -m unittest tests.test_cockpit_ip_unblock_helper.IptablesAdapterTests -v

Expected: AttributeError: IptablesAdapter。

- [ ] **Step 3: 实现最小命令执行器和 iptables 适配器**

~~~python
@dataclass
class CommandResult:
    ok: bool
    stdout: str = ""
    stderr: str = ""
    unavailable: bool = False

def run_command(argv):
    try:
        result = subprocess.run(argv, text=True, capture_output=True,
                                timeout=10, check=False)
    except FileNotFoundError:
        return CommandResult(False, stderr=f"command unavailable: {argv[0]}",
                             unavailable=True)
    except subprocess.TimeoutExpired:
        return CommandResult(False, stderr=f"command timed out: {argv[0]}")
    return CommandResult(result.returncode == 0, result.stdout, result.stderr)
~~~

使用 iptables -S INPUT 获取规则；保留精确删除 argv，例如 ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]，而非依赖会变化的行号。

- [ ] **Step 4: 验证绿色并提交**

Run: python3 -m unittest tests.test_cockpit_ip_unblock_helper.IptablesAdapterTests -v; python3 -m unittest discover -s tests -v

Expected: PASS.

~~~bash
git add tests/test_cockpit_ip_unblock_helper.py usr-local-bin/cockpit-ip-unblock-helper
git commit -m "refactor: add unblock source adapter foundation"
~~~

### Task 2: 用测试驱动 fail2ban 与 firewalld 适配器

**Files:**

- Modify: tests/test_cockpit_ip_unblock_helper.py
- Modify: usr-local-bin/cockpit-ip-unblock-helper

**Interfaces:**

- Consumes: Task 1 的 CommandResult、run_command 与适配器约定。
- Produces: Fail2banAdapter、FirewalldAdapter，结果为 {"source", "status", "removed", "detail"}。

- [ ] **Step 1: 写 fail2ban 跨 jail 解封的失败测试**

~~~python
def test_fail2ban_unblocks_matching_ip_in_every_jail(helper):
    responses = {
      ("fail2ban-client", "status"): ok("Status\n|- Jail list: sshd, nginx-auth\n"),
      ("fail2ban-client", "status", "sshd"): ok("Banned IP list: 203.0.113.7\n"),
      ("fail2ban-client", "status", "nginx-auth"): ok("Banned IP list: 203.0.113.7 2001:db8::1\n"),
      ("fail2ban-client", "set", "sshd", "unbanip", "203.0.113.7"): ok("1"),
      ("fail2ban-client", "set", "nginx-auth", "unbanip", "203.0.113.7"): ok("1"),
    }
    with mock.patch.object(helper, "run_command", side_effect=lambda argv: responses[tuple(argv)]):
        result = helper.Fail2banAdapter().unblock("203.0.113.7")
    assert result["status"] == "success"
    assert result["removed"] == 2
~~~

- [ ] **Step 2: 写 firewalld runtime/permanent rich rule 解封的失败测试**

~~~python
def test_firewalld_removes_matching_runtime_and_permanent_rich_rules(helper):
    rule = 'rule family="ipv4" source address="203.0.113.7" drop'
    with mock.patch.object(helper, "run_command",
        side_effect=[ok("running\n"), ok(rule+"\n"), ok(""), ok(rule+"\n"), ok("")]):
        result = helper.FirewalldAdapter().unblock("203.0.113.7")
    assert result["status"] == "success"
    assert result["removed"] == 2
~~~

- [ ] **Step 3: 运行并确认红灯**

Run: python3 -m unittest tests.test_cockpit_ip_unblock_helper.Fail2banAdapterTests tests.test_cockpit_ip_unblock_helper.FirewalldAdapterTests -v

Expected: AttributeError，因为两个适配器尚未实现。

- [ ] **Step 4: 实现两个适配器**

fail2ban：以 fail2ban-client status 枚举 jail，解析每个 status <jail> 的 Banned IP list，只对匹配 IP 执行 set <jail> unbanip <ip>。

firewalld：检查 firewall-cmd --state，分别读取 --list-rich-rules 与 --permanent --list-rich-rules，只接受 source address 精确等于 IP 且动作为 drop 或 reject 的 rich rule；用相同原文调用 --remove-rich-rule 删除。缺失命令或停止服务返回 unavailable，零匹配返回 not_found。

- [ ] **Step 5: 验证绿色并提交**

Run: python3 -m unittest discover -s tests -v; python3 -m py_compile usr-local-bin/cockpit-ip-unblock-helper

Expected: PASS.

~~~bash
git add tests/test_cockpit_ip_unblock_helper.py usr-local-bin/cockpit-ip-unblock-helper
git commit -m "feat: support fail2ban and firewalld unblocks"
~~~

### Task 3: 统一列表、跨来源结果、配额和 CLI

**Files:**

- Modify: tests/test_cockpit_ip_unblock_helper.py
- Modify: usr-local-bin/cockpit-ip-unblock-helper:219-361

**Interfaces:**

- Produces: list JSON：available_sources 与统一 blocked_ips。
- Produces: unblock <ip> --source <all|iptables|fail2ban|firewalld> JSON：result、source_results、rules_removed 和配额字段。

- [ ] **Step 1: 写统一列表及部分成功只扣一次配额的失败测试**

~~~python
def test_list_reports_available_sources_and_combines_records(helper):
    with mock.patch.object(helper, "get_adapters",
        return_value=[fake_adapter("iptables", True, [block("iptables")]),
                      fake_adapter("fail2ban", False, []),
                      fake_adapter("firewalld", True, [block("firewalld")])]):
        payload = helper.build_list_payload("alice")
    assert payload["available_sources"] == ["iptables", "firewalld"]
    assert [row["source"] for row in payload["blocked_ips"]] == ["iptables", "firewalld"]

def test_partial_all_source_success_consumes_one_quota(helper):
    with mock.patch.object(helper, "get_adapters",
        return_value=[success_adapter("iptables", 1), failed_adapter("fail2ban")]), mock.patch.object(helper, "consume_quota") as consume:
        payload = helper.unblock_ip("alice", "203.0.113.7", "all")
    assert payload["result"] == "partial"
    assert payload["rules_removed"] == 1
    consume.assert_called_once_with("alice")
~~~

- [ ] **Step 2: 运行并确认红灯**

Run: python3 -m unittest tests.test_cockpit_ip_unblock_helper.MultiSourceCommandTests -v

Expected: AttributeError，因为 build_list_payload 与 unblock_ip 尚未实现。

- [ ] **Step 3: 实现编排层并收紧 CLI**

实现 get_adapters()、build_list_payload(user)、unblock_ip(user, ip, source, force=False) 和固定 VALID_SOURCES。每个可用来源均要执行，收集 success、not_found、unavailable、failed。有任意删除为成功；有删除且存在失败为部分成功。只有删除数大于零时调用一次 consume_quota 和 record_history。更新 usage 和参数解析，拒绝未知、重复或缺少值的 --source。

- [ ] **Step 4: 验证绿色并提交**

Run: python3 -m unittest discover -s tests -v; python3 -m py_compile usr-local-bin/cockpit-ip-unblock-helper

Expected: PASS.

~~~bash
git add tests/test_cockpit_ip_unblock_helper.py usr-local-bin/cockpit-ip-unblock-helper
git commit -m "feat: add all-source unblock orchestration"
~~~

### Task 4: 改造 Cockpit 页面为来源感知的交互

**Files:**

- Modify: usr-share-cockpit-ip-unblock/index.html
- Modify: usr-share-cockpit-ip-unblock/ip-unblock.js
- Modify: usr-share-cockpit-ip-unblock/ip-unblock.css
- Modify: tests/test_cockpit_ip_unblock_helper.py

**Interfaces:**

- Consumes: available_sources、带 source/rule 的 blocked_ips 和 source_results。
- Produces: unblock <ip> --source <selectedSource>，并显示每个来源的结果。

- [ ] **Step 1: 写前端静态契约失败测试**

~~~python
def test_page_has_source_selector_and_columns():
    html = Path("usr-share-cockpit-ip-unblock/index.html").read_text()
    assert 'id="source-filter"' in html
    assert 'data-i18n="blockSource"' in html
    assert 'data-i18n="ruleDetail"' in html

def test_script_passes_source_and_keeps_history_immutable():
    script = Path("usr-share-cockpit-ip-unblock/ip-unblock.js").read_text()
    assert '"--source", selectedSource' in script
    assert "history.slice().reverse()" in script
~~~

- [ ] **Step 2: 运行并确认红灯**

Run: python3 -m unittest tests.test_cockpit_ip_unblock_helper.FrontendContractTests -v

Expected: FAIL，因为选择框、来源列、不可变历史渲染尚不存在。

- [ ] **Step 3: 以最小改动实现 UI 行为**

在卡片 header 增加有标签的 source-filter select。根据 available_sources 动态填充全部和可用来源；筛选 table；增加来源徽标和规则详情列；确认框显示实际来源；调用 helper 时追加 ["--source", selectedSource]；解析并按成功、部分成功、失败显示 source_results；将 history.reverse() 替换为 history.slice().reverse()。

补齐 zh/en 的来源、全部来源确认、规则详情、部分成功和各来源结果文案。将当前 iptables 专属副标题、空状态和确认文案替换成来源中立文案。

- [ ] **Step 4: 添加视觉和响应式样式**

添加 .source-filter、.source-badge、三个来源颜色、.msg-warning 及其暗色版本；小屏时让筛选、搜索、刷新控件换行，给宽表提供可水平滚动容器。

- [ ] **Step 5: 验证绿色并提交**

Run: python3 -m unittest discover -s tests -v; git diff --check

Expected: PASS.

~~~bash
git add tests/test_cockpit_ip_unblock_helper.py usr-share-cockpit-ip-unblock/index.html usr-share-cockpit-ip-unblock/ip-unblock.js usr-share-cockpit-ip-unblock/ip-unblock.css
git commit -m "feat: add source-aware unblock interface"
~~~

### Task 5: 完成安装与文档，并全量验证

**Files:**

- Modify: install.sh
- Modify: README.md
- Modify: usr-share-cockpit-ip-unblock/manifest.json
- Modify: tests/test_cockpit_ip_unblock_helper.py

**Interfaces:**

- Consumes: Tasks 1-4 的 CLI/UI 协议。
- Produces: 安装输出、关键词与文档均准确说明可选的多来源支持。

- [ ] **Step 1: 写安装与文档契约失败测试**

~~~python
def test_installer_and_readme_document_optional_backends():
    installer = Path("install.sh").read_text()
    readme = Path("README.md").read_text()
    assert "fail2ban-client" in installer
    assert "firewall-cmd" in installer
    assert "--source all|iptables|fail2ban|firewalld" in readme
~~~

- [ ] **Step 2: 运行并确认红灯**

Run: python3 -m unittest tests.test_cockpit_ip_unblock_helper.DocumentationContractTests -v

Expected: FAIL，因为当前安装与文档只说明 iptables。

- [ ] **Step 3: 更新安装、说明与菜单关键词**

让安装脚本逐一检测 iptables、fail2ban-client、firewall-cmd，缺失时仅提示，不强制安装。README 说明检测规则、筛选器、“全部”部分成功语义、CLI 示例、权限和 firewalld 仅支持精确 source rich rule 的限制。manifest 加入 fail2ban 与 firewalld 关键词。

- [ ] **Step 4: 全量验证、检查安全边界并提交**

Run: python3 -m unittest discover -s tests -v; python3 -m py_compile usr-local-bin/cockpit-ip-unblock-helper; bash -n install.sh; git diff --check

Expected: 全部退出码为 0。

Run: git diff HEAD -- usr-local-bin/cockpit-ip-unblock-helper install.sh usr-share-cockpit-ip-unblock

Expected: 所有系统调用均为 argv；没有 shell=True、flush、reload 或宽泛删除命令。

~~~bash
git add README.md install.sh usr-share-cockpit-ip-unblock/manifest.json tests/test_cockpit_ip_unblock_helper.py
git commit -m "docs: document multi-source unblock support"
~~~

