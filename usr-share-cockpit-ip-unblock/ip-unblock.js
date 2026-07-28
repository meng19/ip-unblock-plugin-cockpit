/*
 * ip-unblock.js — Cockpit plugin: self-service multi-source IP unblock.
 */
(function () {
    "use strict";

    var DEFAULT_PAGE_SIZE = 10;
    var PAGE_SIZE_OPTIONS = [10, 20, 50, 100];
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
            target: "位置信息",
            action: "操作",
            confirmTitle: "确认解封",
            confirmMsg1: "确定要解封 IP 地址",
            confirmMsg2: "吗？",
            confirmSource: "来源：",
            confirmMsg3: "这将移除所选来源中与该 IP 精确匹配的封禁规则。",
            cancel: "取消",
            confirm: "确认",
            unblockBtn: "解封",
            bulkUnblockBtn: "批量解封 ({n})",
            bulkConfirmTitle: "确认批量解封",
            bulkConfirmMsg: "确定要解封所选的 IP 地址吗？",
            bulkSelectedCount: "已选择：",
            bulkConfirmDetail: "每个 IP 都会单独处理；达到额度上限的剩余 IP 将不会处理。",
            msgBulkResult: "批量解封完成：成功 {success}，部分成功 {partial}，失败 {failure}，移除 {removed} 条规则。",
            msgBulkUnprocessed: "未处理 {count} 个 IP：{ips}",
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
            locationLoading: "查询中...",
            locationUnknown: "未知位置",
            locationReserved: "本地/保留地址",
            msgLoadFailed: "加载封禁 IP 列表失败：",
            msgUnblockFailed: "解封失败：",
            msgSudoFailed: "权限不足，请检查 sudo 配置。",
            showingAll: "共 {total} 条，显示第 {from} - {to} 条",
            firstPage: "第一页",
            prevPage: "上一页",
            nextPage: "下一页",
            lastPage: "最后一页",
            pageSize: "每页",
            pageSizeUnit: "条/页",
            jumpTo: "跳转到第",
            jumpGo: "页",
            goBtn: "跳转",
            recentUnblocks: "今日解封记录",
            recentTime: "时间",
            recentIp: "IP 地址",
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
            target: "Location",
            action: "Action",
            confirmTitle: "Confirm Unblock",
            confirmMsg1: "Are you sure you want to unblock IP address",
            confirmMsg2: "?",
            confirmSource: "Source: ",
            confirmMsg3: "This removes only exact IP block rules from the selected source.",
            cancel: "Cancel",
            confirm: "Confirm",
            unblockBtn: "Unblock",
            bulkUnblockBtn: "Unblock selected ({n})",
            bulkConfirmTitle: "Confirm Bulk Unblock",
            bulkConfirmMsg: "Are you sure you want to unblock the selected IP addresses?",
            bulkSelectedCount: "Selected:",
            bulkConfirmDetail: "Each IP is processed individually; IPs left after the quota is exhausted are not processed.",
            msgBulkResult: "Bulk unblock complete: {success} succeeded, {partial} partial, {failure} failed, and {removed} rule(s) removed.",
            msgBulkUnprocessed: "{count} IP(s) were not processed: {ips}",
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
            locationLoading: "Looking up...",
            locationUnknown: "Unknown location",
            locationReserved: "Local/reserved",
            msgLoadFailed: "Failed to load blocked IPs: ",
            msgUnblockFailed: "Unblock failed: ",
            msgSudoFailed: "Permission denied, check sudo configuration.",
            showingAll: "{total} total, showing {from} - {to}",
            firstPage: "First",
            prevPage: "Previous",
            nextPage: "Next",
            lastPage: "Last",
            pageSize: "Rows",
            pageSizeUnit: "rows/page",
            jumpTo: "Go to page",
            jumpGo: "",
            goBtn: "Go",
            recentUnblocks: "Today's Unblock Records",
            recentTime: "Time",
            recentIp: "IP Address",
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
    var pageSize = DEFAULT_PAGE_SIZE;
    var pendingUnblockIp = null;
    var pendingUnblockSource = "all";
    var selectedBulkIps = {};
    var locationCache = {};

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

    function bulkSelectionEnabled() {
        return !!(currentData && currentData.can_bulk_unblock);
    }

    function selectedBulkIpList() {
        return Object.keys(selectedBulkIps);
    }

    function pageCount() {
        return Math.max(1, Math.ceil(filtered.length / pageSize));
    }

    function currentPageRules() {
        var totalPages = pageCount();
        if (currentPage > totalPages) currentPage = totalPages;
        var start = (currentPage - 1) * pageSize;
        return filtered.slice(start, start + pageSize);
    }

    function currentPageIps() {
        var ips = {};
        currentPageRules().forEach(function (rule) { ips[rule.ip] = true; });
        return Object.keys(ips);
    }

    function selectedCurrentPageIpCount() {
        return currentPageIps().filter(function (ip) { return selectedBulkIps[ip]; }).length;
    }

    function setCurrentPageBulkSelection(checked) {
        if (!bulkSelectionEnabled()) return;
        currentPageIps().forEach(function (ip) {
            if (checked) selectedBulkIps[ip] = true;
            else delete selectedBulkIps[ip];
        });
        renderAll();
    }

    function toggleCurrentPageBulkSelection() {
        var ips = currentPageIps();
        if (!bulkSelectionEnabled() || ips.length === 0) return;
        setCurrentPageBulkSelection(selectedCurrentPageIpCount() !== ips.length);
    }

    function clearBulkSelection() {
        selectedBulkIps = {};
    }

    function reconcileBulkSelection() {
        var available = {};
        (currentData && currentData.blocked_ips || []).forEach(function (rule) {
            available[rule.ip] = true;
        });
        Object.keys(selectedBulkIps).forEach(function (ip) {
            if (!available[ip]) delete selectedBulkIps[ip];
        });
    }

    function hideRecentDuringLoad() {
        var section = getEl("recent-section");
        var table = getEl("recent-table");
        var body = getEl("recent-body");
        var empty = getEl("no-recent");
        if (section) section.style.display = "none";
        if (table) table.style.display = "none";
        if (body) {
            body.innerHTML = "";
            body.style.display = "none";
        }
        if (empty) empty.style.display = "none";
    }

    function ipv4Parts(ip) {
        var parts = String(ip || "").split(".");
        if (parts.length !== 4) return null;
        var nums = [];
        for (var i = 0; i < parts.length; i++) {
            if (!/^\d+$/.test(parts[i])) return null;
            var n = parseInt(parts[i], 10);
            if (n < 0 || n > 255) return null;
            nums.push(n);
        }
        return nums;
    }

    function isReservedIp(ip) {
        var v4 = ipv4Parts(ip);
        if (v4) {
            return v4[0] === 0 ||
                v4[0] === 10 ||
                v4[0] === 127 ||
                (v4[0] === 169 && v4[1] === 254) ||
                (v4[0] === 172 && v4[1] >= 16 && v4[1] <= 31) ||
                (v4[0] === 192 && v4[1] === 168) ||
                (v4[0] === 192 && v4[1] === 0 && v4[2] === 2) ||
                (v4[0] === 198 && v4[1] === 51 && v4[2] === 100) ||
                (v4[0] === 203 && v4[1] === 0 && v4[2] === 113) ||
                v4[0] >= 224;
        }

        var v6 = String(ip || "").toLowerCase();
        return v6 === "::" ||
            v6 === "::1" ||
            v6.indexOf("fe80:") === 0 ||
            v6.indexOf("fc") === 0 ||
            v6.indexOf("fd") === 0 ||
            v6.indexOf("2001:db8:") === 0;
    }

    function formatLocation(info) {
        var parts = [info.country, info.region, info.city].filter(function (part, index, arr) {
            return part && arr.indexOf(part) === index;
        });
        return parts.length ? parts.join(" · ") : t("locationUnknown");
    }

    function setLocationCells(ip, text) {
        var cells = document.querySelectorAll("[data-location-ip]");
        Array.prototype.forEach.call(cells, function (cell) {
            if (cell.getAttribute("data-location-ip") !== ip) return;
            cell.textContent = text;
            cell.classList.toggle("muted", text === t("locationLoading") || text === t("locationUnknown"));
        });
    }

    function ensureIpLocation(ip) {
        if (locationCache[ip]) return;
        if (isReservedIp(ip)) {
            locationCache[ip] = { text: t("locationReserved") };
            return;
        }
        locationCache[ip] = { text: t("locationLoading"), loading: true };

        spawnHelper(["locate-ip", ip, curLang])
            .then(function (raw) { return JSON.parse(raw); })
            .then(function (data) {
                var text = data && data.status === "success" ? data.text :
                    data && data.status === "reserved" ? t("locationReserved") : t("locationUnknown");
                locationCache[ip] = { text: text };
                setLocationCells(ip, text);
            })
            .catch(function () {
                locationCache[ip] = { text: t("locationUnknown") };
                setLocationCells(ip, t("locationUnknown"));
            });
    }

    function renderLocationCell(td, ip) {
        ensureIpLocation(ip);
        var cached = locationCache[ip];
        td.className = "ip-location-cell";
        td.setAttribute("data-location-ip", ip);
        td.textContent = cached ? cached.text : t("locationLoading");
        if (!cached || cached.loading || cached.text === t("locationUnknown")) td.classList.add("muted");
    }

    function appendSourceBadges(td, sourceText) {
        var sources = String(sourceText || "").split(",").map(function (source) {
            return source.trim();
        }).filter(Boolean);

        if (!sources.length) {
            td.textContent = "—";
            td.className = "muted";
            return;
        }

        sources.forEach(function (source) {
            var badge = document.createElement("span");
            badge.className = "badge source-badge source-" + source;
            badge.textContent = source;
            td.appendChild(badge);
        });
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
    function applyFilter(resetPage) {
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
        if (resetPage !== false) currentPage = 1;
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
    function loadAll(keepMessage) {
        if (!keepMessage) hideMessage();
        var loadingEl = getEl("loading-indicator");
        if (loadingEl) loadingEl.style.display = "block";
        ["empty-state", "no-match-state", "rules-table-wrap", "pagination"].forEach(function (id) {
            var el = getEl(id);
            if (el) el.style.display = "none";
        });
        hideRecentDuringLoad();

        // Load list and recent in parallel
        var p1 = spawnHelper(["list"]).then(function (raw) {
            currentData = JSON.parse(raw);
            reconcileBulkSelection();
            applyFilter(true);
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
        applyFilter(false);
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
        var selectAll = getEl("select-all-blocked");
        var selectColumn = getEl("bulk-select-column");
        var bulkButton = getEl("bulk-unblock-btn");
        var canBulk = bulkSelectionEnabled();
        var currentPageIpList = currentPageIps();

        if (selectColumn) selectColumn.style.display = canBulk ? "" : "none";
        if (bulkButton) {
            var selectedCount = selectedBulkIpList().length;
            bulkButton.style.display = canBulk ? "" : "none";
            bulkButton.disabled = selectedCount === 0;
            bulkButton.textContent = t("bulkUnblockBtn", { n: selectedCount });
        }
        if (selectAll) {
            var selectedOnPage = selectedCurrentPageIpCount();
            selectAll.checked = currentPageIpList.length > 0 && selectedOnPage === currentPageIpList.length;
            selectAll.indeterminate = selectedOnPage > 0 && selectedOnPage < currentPageIpList.length;
            selectAll.disabled = !canBulk || currentPageIpList.length === 0;
        }

        if (searchBox) searchBox.style.display = "flex";

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

        var totalPages = pageCount();
        if (currentPage > totalPages) currentPage = totalPages;
        var start = (currentPage - 1) * pageSize;
        var page = currentPageRules();

        if (!tbody) return;
        tbody.innerHTML = "";

        var quota = currentData.quota_remaining;
        var unlimited = currentData.unlimited;

        page.forEach(function (rule, index) {
            var tr = document.createElement("tr");
            if (canBulk) {
                var tdSelect = document.createElement("td");
                var checkbox = document.createElement("input");
                checkbox.type = "checkbox";
                checkbox.checked = !!selectedBulkIps[rule.ip];
                checkbox.setAttribute("aria-label", t("bulkSelectedCount") + " " + rule.ip);
                checkbox.addEventListener("change", function () {
                    if (this.checked) selectedBulkIps[rule.ip] = true;
                    else delete selectedBulkIps[rule.ip];
                    renderAll();
                });
                tdSelect.appendChild(checkbox);
                tdSelect.addEventListener("click", function (e) {
                    if (e.target !== checkbox) {
                        checkbox.checked = !checkbox.checked;
                        checkbox.dispatchEvent(new Event("change", { bubbles: true }));
                    }
                });
                tr.appendChild(tdSelect);
            }
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
            renderLocationCell(tdT, rule.ip);
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
        var start = (currentPage - 1) * pageSize + 1;
        var end = Math.min(start + pageSize - 1, total);
        infoEl.textContent = t("showingAll", { total: total, from: start, to: end });
    }

    function renderPagination() {
        var pg = getEl("pagination");
        if (!pg) return;
        if (filtered.length === 0) { pg.style.display = "none"; return; }
        pg.style.display = "flex";

        var tp = pageCount();
        var firstBtn = getEl("btn-first");
        var prevBtn = getEl("btn-prev");
        var nextBtn = getEl("btn-next");
        var lastBtn = getEl("btn-last");
        var pageInfo = getEl("page-info");
        var pageSizeSelect = getEl("page-size");

        if (firstBtn) firstBtn.disabled = (currentPage <= 1);
        if (prevBtn) prevBtn.disabled = (currentPage <= 1);
        if (nextBtn) nextBtn.disabled = (currentPage >= tp);
        if (lastBtn) lastBtn.disabled = (currentPage >= tp);
        if (pageInfo) pageInfo.textContent = currentPage + " / " + tp;
        if (pageSizeSelect) pageSizeSelect.value = String(pageSize);
        updatePaginationText();
    }

    /* ── Clickable page-info → input for jump ── */
    function setupPageJump() {
        var pageInfo = getEl("page-info");
        if (!pageInfo) return;

        pageInfo.style.cursor = "pointer";
        pageInfo.title = "点击跳转页码";

        pageInfo.addEventListener("click", function () {
            var tp = pageCount();
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
            hideRecentDuringLoad();
            return;
        }

        var history = (recentData && recentData.history) ? recentData.history : [];

        if (history.length === 0) {
            section.style.display = "";
            if (table) table.style.display = "none";
            body.innerHTML = "";
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
            var tdSource = document.createElement("td");
            appendSourceBadges(tdSource, rec.source);
            tr.appendChild(tdSource);
            var tdLocation = document.createElement("td");
            renderLocationCell(tdLocation, rec.ip);
            tr.appendChild(tdLocation);
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

    function openBulkConfirm() {
        var ips = selectedBulkIpList();
        if (!bulkSelectionEnabled() || ips.length === 0) return;
        var countEl = getEl("bulk-confirm-count");
        var sourceEl = getEl("bulk-confirm-source");
        var overlay = getEl("bulk-confirm-overlay");
        if (countEl) countEl.textContent = String(ips.length);
        if (sourceEl) sourceEl.textContent = sourceLabel(selectedSource());
        if (overlay) overlay.style.display = "flex";
    }

    function closeBulkConfirm() {
        var overlay = getEl("bulk-confirm-overlay");
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
                loadAll(true);
            })
            .catch(function (err) {
                pendingUnblockIp = null;
                pendingUnblockSource = "all";
                showMessage("error", t("msgUnblockFailed") + String(err.message || err));
                loadAll();
            });
    }

    function doBulkUnblock() {
        var ips = selectedBulkIpList();
        if (!bulkSelectionEnabled() || ips.length === 0) return;
        hideMessage();
        var source = selectedSource();
        spawnHelper(["bulk-unblock", "--source", source].concat(ips))
            .then(function (raw) {
                var result = JSON.parse(raw);
                var summary = result.summary || {};
                var unprocessed = result.unprocessed_ips || [];
                var processed = (result.results || []).map(function (item) { return item.ip; });
                processed.forEach(function (ip) { delete selectedBulkIps[ip]; });
                var message = t("msgBulkResult", {
                    success: summary.success || 0,
                    partial: summary.partial || 0,
                    failure: summary.failure || 0,
                    removed: summary.rules_removed || 0,
                });
                if (unprocessed.length) {
                    message += " " + t("msgBulkUnprocessed", {
                        count: unprocessed.length, ips: unprocessed.join(", "),
                    });
                }
                showMessage(unprocessed.length || summary.failure ? "warning" : "success", message);
                loadAll(true);
            })
            .catch(function (err) {
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
        locationCache = {};
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

        el = getEl("bulk-unblock-btn");
        if (el) el.addEventListener("click", openBulkConfirm);

        el = getEl("bulk-confirm-cancel");
        if (el) el.addEventListener("click", closeBulkConfirm);

        el = getEl("bulk-confirm-ok");
        if (el) el.addEventListener("click", function () { closeBulkConfirm(); doBulkUnblock(); });

        el = getEl("bulk-confirm-overlay");
        if (el) el.addEventListener("click", function (e) { if (e.target === el) closeBulkConfirm(); });

        el = getEl("select-all-blocked");
        if (el) el.addEventListener("change", function () {
            setCurrentPageBulkSelection(el.checked);
        });

        el = getEl("bulk-select-column");
        if (el) el.addEventListener("click", function (e) {
            if (e.target && e.target.id === "select-all-blocked") return;
            toggleCurrentPageBulkSelection();
        });

        el = getEl("search-input");
        if (el) el.addEventListener("input", function () { clearBulkSelection(); applyFilter(true); renderAll(); });

        el = getEl("source-filter");
        if (el) el.addEventListener("change", function () { clearBulkSelection(); applyFilter(true); renderAll(); });

        el = getEl("btn-first");
        if (el) el.addEventListener("click", function () { if (currentPage > 1) { currentPage = 1; renderAll(); } });

        el = getEl("btn-prev");
        if (el) el.addEventListener("click", function () { if (currentPage > 1) { currentPage--; renderAll(); } });

        el = getEl("btn-next");
        if (el) el.addEventListener("click", function () {
            var tp = pageCount();
            if (currentPage < tp) { currentPage++; renderAll(); }
        });

        el = getEl("btn-last");
        if (el) el.addEventListener("click", function () {
            var tp = pageCount();
            if (currentPage < tp) { currentPage = tp; renderAll(); }
        });

        el = getEl("page-size");
        if (el) el.addEventListener("change", function () {
            var n = parseInt(el.value, 10);
            if (PAGE_SIZE_OPTIONS.indexOf(n) === -1) n = DEFAULT_PAGE_SIZE;
            pageSize = n;
            currentPage = 1;
            try { localStorage.setItem("ip-unblock:pageSize", String(pageSize)); } catch (e) {}
            renderAll();
        });

        // Page jump: click page-info to edit
        setupPageJump();

        document.addEventListener("keydown", function (e) {
            if (e.key === "Escape") { pendingUnblockIp = null; pendingUnblockSource = "all"; closeConfirm(); closeBulkConfirm(); }
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
        try {
            var savedPageSize = parseInt(localStorage.getItem("ip-unblock:pageSize"), 10);
            if (PAGE_SIZE_OPTIONS.indexOf(savedPageSize) !== -1) pageSize = savedPageSize;
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
