/*
 * ip-unblock.js — Cockpit plugin: self-service multi-source IP unblock.
 */
(function () {
    "use strict";

    var PAGE_SIZE = 15;
    var HELPER = "/usr/local/bin/cockpit-ip-unblock-helper";

    /* =================================================================
     *  i18n
     * ================================================================= */
    var LANG = {
        zh: {
            pageTitle: "IP 自助解封",
            pageSubtitle: "查看并解除多个防火墙来源中的 IP 封禁。",
            signedInAs: "当前用户：",
            unlimited: "不限次数",
            remainingUnblocks: "今日剩余解封次数：",
            blockedIPs: "已封禁的 IP 地址",
            refresh: "刷新",
            search: "查找 IP...",
            loading: "正在加载已封禁 IP 列表...",
            noBlocked: "暂无封禁 IP",
            noBlockedDesc: "当前可用来源中没有可自助解除的 IP 封禁。",
            noMatch: "没有匹配的 IP 地址",
            ruleNum: "序号",
            sourceIP: "来源 IP",
            blockSource: "封禁来源",
            allSources: "全部可用来源",
            ruleDetail: "规则详情",
            target: "动作",
            action: "操作",
            confirmTitle: "确认解封",
            confirmMsg1: "确定要解封 IP 地址",
            confirmMsg2: "吗？",
            confirmSource: "来源：",
            confirmMsg3: "这将移除所选来源中与该 IP 精确匹配的封禁规则。",
            cancel: "取消",
            confirm: "确认",
            unblockBtn: "解封",
            quotaExhausted: "已达每日解封上限",
            lastUnblock: "这是今天最后一次解封机会。",
            remainingAfter: "解封后今天还剩 {n} 次。",
            msgUnblockSuccess: "成功移除 IP {ip} 的 {count} 条封禁。剩余解封次数：{remain}/{limit}。",
            msgUnblockPartial: "IP {ip} 已部分解封（移除 {count} 条封禁）。{results}",
            msgUnblockNoChange: "未能解除 IP {ip} 的封禁。{results}",
            sourceResult: "{source}：{status}{detail}",
            sourceSuccess: "成功（{count}）",
            sourceNotFound: "未找到匹配项",
            sourceUnavailable: "不可用",
            sourceFailed: "失败",
            msgLoadFailed: "加载封禁 IP 列表失败：",
            msgUnblockFailed: "解封失败：",
            msgSudoFailed: "权限不足，请检查 sudo 配置。",
            showingAll: "共 {total} 条，显示第 {from} - {to} 条",
            prevPage: "上一页",
            nextPage: "下一页",
            jumpTo: "跳转到第",
            jumpGo: "页",
            goBtn: "跳转",
            recentUnblocks: "今日解封记录",
            noRecent: "暂无解封记录",
            switchTo: "English",
            switchLang: "en",
        },
        en: {
            pageTitle: "IP Unblock",
            pageSubtitle: "View and remove IP blocks across available firewall sources.",
            signedInAs: "Signed in as: ",
            unlimited: "Unlimited",
            remainingUnblocks: "Remaining unblocks today: ",
            blockedIPs: "Blocked IP Addresses",
            refresh: "Refresh",
            search: "Search IP...",
            loading: "Loading blocked IPs...",
            noBlocked: "No Blocked IPs",
            noBlockedDesc: "There are no self-service unblockable IP blocks in the available sources.",
            noMatch: "No matching IP addresses",
            ruleNum: "Rule #",
            sourceIP: "Source IP",
            blockSource: "Block source",
            allSources: "All available sources",
            ruleDetail: "Rule detail",
            target: "Target",
            action: "Action",
            confirmTitle: "Confirm Unblock",
            confirmMsg1: "Are you sure you want to unblock IP address",
            confirmMsg2: "?",
            confirmSource: "Source: ",
            confirmMsg3: "This removes only exact IP block rules from the selected source.",
            cancel: "Cancel",
            confirm: "Confirm",
            unblockBtn: "Unblock",
            quotaExhausted: "Daily unblock limit reached",
            lastUnblock: "This is your last unblock for today.",
            remainingAfter: "After this, {n} unblock(s) remaining today.",
            msgUnblockSuccess: "Successfully removed {count} rule(s) for IP {ip}. Remaining unblocks: {remain}/{limit}.",
            msgUnblockPartial: "IP {ip} was partially unblocked ({count} block(s) removed). {results}",
            msgUnblockNoChange: "No block could be removed for IP {ip}. {results}",
            sourceResult: "{source}: {status}{detail}",
            sourceSuccess: "success ({count})",
            sourceNotFound: "not found",
            sourceUnavailable: "unavailable",
            sourceFailed: "failed",
            msgLoadFailed: "Failed to load blocked IPs: ",
            msgUnblockFailed: "Unblock failed: ",
            msgSudoFailed: "Permission denied, check sudo configuration.",
            showingAll: "{total} total, showing {from} - {to}",
            prevPage: "Previous",
            nextPage: "Next",
            jumpTo: "Go to page",
            jumpGo: "",
            goBtn: "Go",
            recentUnblocks: "Today's Unblock Records",
            noRecent: "No unblock records",
            switchTo: "中文",
            switchLang: "zh",
        },
    };

    var curLang = "zh";

    function t(key, params) {
        var map = LANG[curLang] || LANG.zh;
        var s = map[key] !== undefined ? map[key] : key;
        if (params) {
            Object.keys(params).forEach(function (k) {
                s = s.replace("{" + k + "}", params[k]);
            });
        }
        return s;
    }

    /* =================================================================
     *  State
     * ================================================================= */
    var currentData = null;
    var recentData = null;
    var filtered = [];
    var currentPage = 1;
    var pendingUnblockIp = null;
    var pendingUnblockSource = "all";

    /* =================================================================
     *  Helpers
     * ================================================================= */
    function getEl(id) { return document.getElementById(id); }

    function selectedSource() {
        var select = getEl("source-filter");
        return select && select.value ? select.value : "all";
    }

    function sourceLabel(source) {
        return source === "all" ? t("allSources") : source;
    }

    /* =================================================================
     *  Messages
     * ================================================================= */
    function showMessage(type, text) {
        var area = getEl("message-area");
        var content = getEl("message-content");
        var textEl = getEl("message-text");
        var iconEl = getEl("message-icon");
        if (!area || !content || !textEl) return;
        area.classList.remove("msg-hidden");
        content.className = "msg-box msg-" + type;
        textEl.textContent = text;
        if (iconEl) {
            iconEl.innerHTML = type === "success" ? "&#10003;" : type === "error" ? "&#9888;" : "&#8505;";
        }
        if (type === "success") setTimeout(hideMessage, 6000);
    }

    function hideMessage() {
        var area = getEl("message-area");
        if (area) area.classList.add("msg-hidden");
    }

    /* =================================================================
     *  Backend
     * ================================================================= */
    function spawnHelper(args) {
        var fullArgs = ["sudo", "-n", HELPER];
        fullArgs = fullArgs.concat(args);
        return cockpit.spawn(fullArgs, { err: "message" });
    }

    /* =================================================================
     *  Search / filter
     * ================================================================= */
    function applyFilter() {
        var input = getEl("search-input");
        var query = input ? input.value.trim().toLowerCase() : "";
        var source = selectedSource();
        if (!currentData) {
            filtered = [];
        } else {
            filtered = (currentData.blocked_ips || []).filter(function (r) {
                return (source === "all" || r.source === source) &&
                    (!query || r.ip.toLowerCase().indexOf(query) !== -1);
            });
        }
        currentPage = 1;
    }

    function populateSourceFilter() {
        var select = getEl("source-filter");
        if (!select || !currentData) return;
        var previous = select.value || "all";
        select.textContent = "";
        ["all"].concat(currentData.available_sources || []).forEach(function (source) {
            var option = document.createElement("option");
            option.value = source;
            option.textContent = sourceLabel(source);
            select.appendChild(option);
        });
        select.value = Array.prototype.some.call(select.options, function (option) {
            return option.value === previous;
        }) ? previous : "all";
    }

    /* =================================================================
     *  Load
     * ================================================================= */
    function loadAll() {
        hideMessage();
        var loadingEl = getEl("loading-indicator");
        if (loadingEl) loadingEl.style.display = "block";
        ["empty-state", "no-match-state", "rules-table-wrap", "pagination"].forEach(function (id) {
            var el = getEl(id);
            if (el) el.style.display = "none";
        });

        // Load list and recent in parallel
        var p1 = spawnHelper(["list"]).then(function (raw) {
            currentData = JSON.parse(raw);
            applyFilter();
        });
        var p2 = spawnHelper(["recent"]).then(function (raw) {
            recentData = JSON.parse(raw);
        });

        Promise.all([p1, p2]).then(function () {
            renderAll();
        }).catch(function (err) {
            currentData = null;
            filtered = [];
            if (loadingEl) loadingEl.style.display = "none";
            showMessage("error", t("msgLoadFailed") + String(err.message || err));
        });
    }

    /* =================================================================
     *  Render
     * ================================================================= */
    function renderAll() {
        if (!currentData) return;
        var loadingEl = getEl("loading-indicator");
        if (loadingEl) loadingEl.style.display = "none";
        populateSourceFilter();
        applyFilter();
        renderQuota();
        renderTable();
        renderPagination();
        renderRecent();
        applyI18n();
    }

    function renderQuota() {
        var d = currentData;
        var userEl = getEl("current-user");
        var quotaEl = getEl("quota-remaining");
        if (userEl) userEl.textContent = d.user || "unknown";
        if (quotaEl) {
            if (d.unlimited) {
                quotaEl.textContent = t("unlimited");
                quotaEl.style.color = "#3e8635";
            } else {
                quotaEl.textContent = d.quota_remaining + " / " + d.quota_limit;
                quotaEl.style.color = d.quota_remaining === 0 ? "#c9190b" : d.quota_remaining <= 2 ? "#f0ab00" : "";
            }
        }
    }

    function renderTable() {
        var emptyEl = getEl("empty-state");
        var noMatchEl = getEl("no-match-state");
        var tableEl = getEl("rules-table-wrap");
        var tbody = getEl("rules-table-body");
        var searchBox = getEl("search-box");

        if (searchBox) searchBox.style.display = currentData.blocked_ips.length > 0 ? "flex" : "none";

        if (currentData.blocked_ips.length === 0) {
            if (emptyEl) emptyEl.style.display = "block";
            if (noMatchEl) noMatchEl.style.display = "none";
            if (tableEl) tableEl.style.display = "none";
            return;
        }

        var hasFilter = (getEl("search-input") && getEl("search-input").value.trim() !== "") || selectedSource() !== "all";
        if (filtered.length === 0 && hasFilter) {
            if (emptyEl) emptyEl.style.display = "none";
            if (noMatchEl) noMatchEl.style.display = "block";
            if (tableEl) tableEl.style.display = "none";
            return;
        }

        if (emptyEl) emptyEl.style.display = "none";
        if (noMatchEl) noMatchEl.style.display = "none";
        if (tableEl) tableEl.style.display = "";

        var totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
        if (currentPage > totalPages) currentPage = totalPages;
        var start = (currentPage - 1) * PAGE_SIZE;
        var page = filtered.slice(start, start + PAGE_SIZE);

        if (!tbody) return;
        tbody.innerHTML = "";

        var quota = currentData.quota_remaining;
        var unlimited = currentData.unlimited;

        page.forEach(function (rule, index) {
            var tr = document.createElement("tr");
            ["num", "ip"].forEach(function (f) {
                var td = document.createElement("td");
                var el = f === "ip"
                    ? (function () { var c = document.createElement("code"); c.textContent = rule[f]; return c; })()
                    : document.createTextNode(rule.num || (start + index + 1));
                td.appendChild(el);
                tr.appendChild(td);
            });

            var tdSource = document.createElement("td");
            var sourceBadge = document.createElement("span");
            sourceBadge.className = "badge source-badge source-" + rule.source;
            sourceBadge.textContent = rule.source;
            tdSource.appendChild(sourceBadge);
            tr.appendChild(tdSource);

            var tdRule = document.createElement("td");
            var ruleCode = document.createElement("code");
            ruleCode.textContent = rule.rule || "—";
            tdRule.appendChild(ruleCode);
            tr.appendChild(tdRule);

            var tdT = document.createElement("td");
            var badge = document.createElement("span");
            badge.className = "badge";
            if (rule.target === "DROP") badge.classList.add("badge-drop");
            else if (rule.target === "REJECT") badge.classList.add("badge-reject");
            badge.textContent = rule.target || rule.scope || "—";
            tdT.appendChild(badge);
            tr.appendChild(tdT);

            var tdA = document.createElement("td");
            var btn = document.createElement("button");
            btn.className = "btn btn-danger btn-sm";
            btn.textContent = t("unblockBtn");
            btn.setAttribute("data-ip", rule.ip);
            btn.setAttribute("data-source", rule.source);
            btn.addEventListener("click", function () {
                openConfirm(this.getAttribute("data-ip"), selectedSource(), unlimited ? -1 : quota);
            });
            if (!unlimited && quota <= 0) { btn.disabled = true; btn.title = t("quotaExhausted"); }
            tdA.appendChild(btn);
            tr.appendChild(tdA);

            tbody.appendChild(tr);
        });

        updatePaginationText();
    }

    function updatePaginationText() {
        var infoEl = getEl("pagination-info");
        if (!infoEl || filtered.length === 0) return;
        var total = filtered.length;
        var start = (currentPage - 1) * PAGE_SIZE + 1;
        var end = Math.min(start + PAGE_SIZE - 1, total);
        infoEl.textContent = t("showingAll", { total: total, from: start, to: end });
    }

    function renderPagination() {
        var pg = getEl("pagination");
        if (!pg) return;
        if (filtered.length <= PAGE_SIZE) { pg.style.display = "none"; return; }
        pg.style.display = "flex";

        var tp = Math.ceil(filtered.length / PAGE_SIZE);
        var prevBtn = getEl("btn-prev");
        var nextBtn = getEl("btn-next");
        var pageInfo = getEl("page-info");

        if (prevBtn) prevBtn.disabled = (currentPage <= 1);
        if (nextBtn) nextBtn.disabled = (currentPage >= tp);
        if (pageInfo) pageInfo.textContent = currentPage + " / " + tp;
        updatePaginationText();
    }

    /* ── Clickable page-info → input for jump ── */
    function setupPageJump() {
        var pageInfo = getEl("page-info");
        if (!pageInfo) return;

        pageInfo.style.cursor = "pointer";
        pageInfo.title = "点击跳转页码";

        pageInfo.addEventListener("click", function () {
            var tp = Math.ceil(filtered.length / PAGE_SIZE);
            if (!tp) return;

            var input = document.createElement("input");
            input.type = "number";
            input.min = "1";
            input.max = String(tp);
            input.value = String(currentPage);
            input.className = "jump-input";
            input.style.width = (String(tp).length * 14 + 20) + "px";

            pageInfo.style.display = "none";
            pageInfo.parentNode.insertBefore(input, pageInfo.nextSibling);

            input.focus();
            input.select();

            var done = false;

            function commit() {
                if (done) return;
                done = true;
                var n = parseInt(input.value, 10);
                if (!isNaN(n) && n >= 1 && n <= tp) {
                    currentPage = n;
                }
                input.remove();
                pageInfo.style.display = "";
                renderAll();
            }

            input.addEventListener("keydown", function (e) {
                if (e.key === "Enter") { e.preventDefault(); commit(); }
                if (e.key === "Escape") { e.preventDefault(); done = true; input.remove(); pageInfo.style.display = ""; }
            });
            input.addEventListener("blur", function () {
                // Small delay to let keydown fire first
                setTimeout(commit, 100);
            });
        });
    }

    /* =================================================================
     *  Recent records
     * ================================================================= */
    function renderRecent() {
        var section = getEl("recent-section");
        var table = getEl("recent-table");
        var body = getEl("recent-body");
        var empty = getEl("no-recent");
        if (!section || !body) return;
        if (!currentData || !currentData.show_recent_history) {
            section.style.display = "none";
            return;
        }

        var history = (recentData && recentData.history) ? recentData.history : [];

        if (history.length === 0) {
            section.style.display = "";
            if (table) table.style.display = "none";
            body.style.display = "none";
            if (empty) empty.style.display = "block";
            return;
        }

        section.style.display = "";
        if (table) table.style.display = "";
        body.style.display = "";
        if (empty) empty.style.display = "none";
        body.innerHTML = "";

        history.slice().reverse().forEach(function (rec) {
            var tr = document.createElement("tr");
            var tdTime = document.createElement("td");
            tdTime.textContent = rec.time;
            tr.appendChild(tdTime);
            var tdIp = document.createElement("td");
            var code = document.createElement("code");
            code.textContent = rec.ip;
            tdIp.appendChild(code);
            tr.appendChild(tdIp);
            body.appendChild(tr);
        });
    }

    /* =================================================================
     *  Confirm dialog
     * ================================================================= */
    function openConfirm(ip, source, remaining) {
        if (!ip) return;
        pendingUnblockIp = ip;
        pendingUnblockSource = source || selectedSource();
        var ipEl = getEl("confirm-ip");
        var sourceEl = getEl("confirm-source");
        var noteEl = getEl("confirm-quota-note");
        var overlay = getEl("confirm-overlay");
        if (ipEl) ipEl.textContent = ip;
        if (sourceEl) sourceEl.textContent = sourceLabel(pendingUnblockSource);
        if (noteEl) {
            if (remaining < 0) {
                noteEl.textContent = "";
            } else if (remaining <= 1) {
                noteEl.textContent = t("lastUnblock");
                noteEl.style.color = "#c9190b";
            } else {
                noteEl.textContent = t("remainingAfter", { n: remaining - 1 });
                noteEl.style.color = "";
            }
        }
        if (overlay) overlay.style.display = "flex";
    }

    function closeConfirm() {
        var overlay = getEl("confirm-overlay");
        if (overlay) overlay.style.display = "none";
    }

    /* =================================================================
     *  Unblock
     * ================================================================= */
    function describeSourceResults(results) {
        return (results || []).map(function (item) {
            var statusKey = item.status === "success" ? "sourceSuccess" :
                item.status === "not_found" ? "sourceNotFound" :
                item.status === "unavailable" ? "sourceUnavailable" : "sourceFailed";
            return t("sourceResult", {
                source: item.source,
                status: t(statusKey, { count: item.removed || 0 }),
                detail: item.detail ? " (" + item.detail + ")" : "",
            });
        }).join("; ");
    }

    function doUnblock(ip, source) {
        hideMessage();
        var selectedSource = source || "all";
        spawnHelper(["unblock", ip, "--source", selectedSource])
            .then(function (raw) {
                var result = JSON.parse(raw);
                var resultText = describeSourceResults(result.source_results);
                if (result.result === "success") {
                    showMessage("success", t("msgUnblockSuccess", {
                        ip: ip, count: result.rules_removed,
                        remain: result.quota_remaining < 0 ? "∞" : result.quota_remaining,
                        limit: result.quota_limit < 0 ? "∞" : result.quota_limit,
                    }) + (resultText ? " " + resultText : ""));
                } else if (result.result === "partial") {
                    showMessage("warning", t("msgUnblockPartial", {
                        ip: ip, count: result.rules_removed, results: resultText,
                    }));
                } else {
                    showMessage("error", t("msgUnblockNoChange", { ip: ip, results: resultText }));
                }
                pendingUnblockIp = null;
                pendingUnblockSource = "all";
                loadAll();
            })
            .catch(function (err) {
                pendingUnblockIp = null;
                pendingUnblockSource = "all";
                showMessage("error", t("msgUnblockFailed") + String(err.message || err));
                loadAll();
            });
    }

    /* =================================================================
     *  i18n
     * ================================================================= */
    function applyI18n() {
        var els = document.querySelectorAll("[data-i18n]");
        for (var i = 0; i < els.length; i++) {
            var el = els[i];
            if (!el.children.length) {
                el.textContent = t(el.getAttribute("data-i18n"));
            }
        }
        document.title = t("pageTitle");
        var langBtn = getEl("lang-toggle");
        if (langBtn) { langBtn.textContent = t("switchTo"); langBtn.title = t("switchTo"); }
        var searchInput = getEl("search-input");
        if (searchInput) searchInput.placeholder = t("search");
        updatePaginationText();
    }

    function switchLang(lang) {
        curLang = lang;
        try { localStorage.setItem("ip-unblock:lang", lang); } catch (e) {}
        applyI18n();
        renderAll();
    }

    /* =================================================================
     *  Bind events
     * ================================================================= */
    function bindEvents() {
        var el;

        el = getEl("refresh-btn");
        if (el) el.addEventListener("click", loadAll);

        el = getEl("lang-toggle");
        if (el) el.addEventListener("click", function () { switchLang(t("switchLang")); });

        el = getEl("message-close");
        if (el) el.addEventListener("click", hideMessage);

        el = getEl("confirm-cancel");
        if (el) el.addEventListener("click", function () { pendingUnblockIp = null; pendingUnblockSource = "all"; closeConfirm(); });

        el = getEl("confirm-ok");
        if (el) el.addEventListener("click", function () {
            var ip = pendingUnblockIp;
            if (!ip) return;
            closeConfirm();
            doUnblock(ip, pendingUnblockSource);
        });

        el = getEl("confirm-overlay");
        if (el) el.addEventListener("click", function (e) {
            if (e.target === el) { pendingUnblockIp = null; pendingUnblockSource = "all"; closeConfirm(); }
        });

        el = getEl("search-input");
        if (el) el.addEventListener("input", function () { applyFilter(); renderAll(); });

        el = getEl("source-filter");
        if (el) el.addEventListener("change", function () { applyFilter(); renderAll(); });

        el = getEl("btn-prev");
        if (el) el.addEventListener("click", function () { if (currentPage > 1) { currentPage--; renderAll(); } });

        el = getEl("btn-next");
        if (el) el.addEventListener("click", function () {
            var tp = Math.ceil(filtered.length / PAGE_SIZE);
            if (currentPage < tp) { currentPage++; renderAll(); }
        });

        // Page jump: click page-info to edit
        setupPageJump();

        document.addEventListener("keydown", function (e) {
            if (e.key === "Escape") { pendingUnblockIp = null; pendingUnblockSource = "all"; closeConfirm(); }
        });
    }

    /* =================================================================
     *  Init
     * ================================================================= */
    function init() {
        try {
            var saved = localStorage.getItem("ip-unblock:lang");
            if (saved === "en" || saved === "zh") curLang = saved;
        } catch (e) {}

        bindEvents();
        applyI18n();

        loadAll();
    }

    function onDomReady() {
        if (typeof cockpit !== "undefined" && cockpit.transport) {
            cockpit.transport.wait(init);
        } else {
            init();
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", onDomReady);
    } else {
        onDomReady();
    }
})();
