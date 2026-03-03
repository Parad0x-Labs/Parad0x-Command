"""Tests for liquefy_desktop_viz.py — Galactic Desktop visualization."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import liquefy_desktop_viz as desktop_viz

from liquefy_desktop_viz import (
    _allowed_local_api_hosts,
    _agent_process_action_result,
    _billing_doctor_result,
    _browser_key_from_process_name,
    _validate_local_api_request,
    _build_activity_feed,
    _build_agent_ops_summary,
    _build_monitor_rows,
    _build_task_progress_summary,
    _build_threat_summary,
    _canonical_process_group,
    _classify_file,
    _gather_system_snapshot,
    _get_cpu_info,
    _get_browser_tabs,
    _browser_debug_ports_from_processes,
    _get_process_children_map,
    _get_disk_info,
    _get_gpu_info,
    _get_linux_browser_window_tabs,
    _get_memory_info,
    _get_network_info,
    _get_windows_browser_window_tabs,
    _get_windows_browser_ui_tabs,
    _get_firefox_session_tabs,
    _network_action_result,
    _get_processes,
    _get_safari_tabs,
    _expand_pid_tree,
    _group_process_action_result,
    _importance_score,
    _is_agent_related,
    _is_log_file,
    _is_sensitive,
    _load_history_guard_summary,
    _load_ai_usage_summary,
    _load_ai_billing_profile,
    _load_codex_session_entries,
    _parse_safari_tabs_json,
    _process_action_result,
    _resolve_background_image,
    _render_galactic_html,
    _render_live_html,
    _scan_directory,
    build_parser,
    cmd_render,
    cmd_scan,
)


def _ns(**kw):
    from types import SimpleNamespace
    defaults = {"json": False, "out": None, "max_files": 5000, "max_depth": 8}
    defaults.update(kw)
    return SimpleNamespace(**defaults)


def _mozlz4_literal_block(payload: bytes) -> bytes:
    out = bytearray(b"mozLz40\0")
    length = len(payload)
    token = min(length, 15) << 4
    out.append(token)
    if length >= 15:
        extra = length - 15
        while extra >= 255:
            out.append(255)
            extra -= 255
        out.append(extra)
    out.extend(payload)
    return bytes(out)


class TestClassifyFile:
    def test_python(self):
        assert _classify_file(Path("test.py")) == "python"

    def test_json_is_data(self):
        assert _classify_file(Path("config.json")) == "data"

    def test_env_is_secret(self):
        assert _classify_file(Path(".env")) == "secret"

    def test_vault(self):
        assert _classify_file(Path("archive.null")) == "vault"

    def test_unknown(self):
        assert _classify_file(Path("README")) == "unknown"

    def test_solidity(self):
        assert _classify_file(Path("Contract.sol")) == "solidity"


class TestSensitivity:
    def test_env_is_sensitive(self):
        assert _is_sensitive(Path(".env"))

    def test_pem_is_sensitive(self):
        assert _is_sensitive(Path("server.pem"))

    def test_password_in_name(self):
        assert _is_sensitive(Path("passwords.txt"))

    def test_normal_not_sensitive(self):
        assert not _is_sensitive(Path("README.md"))


class TestAgentRelated:
    def test_soul_md(self):
        assert _is_agent_related(Path("SOUL.md"))

    def test_heartbeat(self):
        assert _is_agent_related(Path("HEARTBEAT.md"))

    def test_liquefy_dir(self):
        assert _is_agent_related(Path(".liquefy/config.json"))

    def test_task_md(self):
        assert _is_agent_related(Path("task.md"))

    def test_normal_not_agent(self):
        assert not _is_agent_related(Path("utils.py"))


class TestImportance:
    def test_secret_file_high(self):
        score = _importance_score(Path(".env"), 100, "secret")
        assert score >= 80

    def test_normal_file_low(self):
        score = _importance_score(Path("readme.txt"), 50, "docs")
        assert score < 30

    def test_agent_file_medium(self):
        score = _importance_score(Path("SOUL.md"), 200, "docs")
        assert score >= 30

    def test_large_file_bonus(self):
        small = _importance_score(Path("data.json"), 100, "data")
        large = _importance_score(Path("data.json"), 50 * 1024 * 1024, "data")
        assert large > small


class TestScanDirectory:
    def test_scans_basic_tree(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.py").write_text("print('hello')")
        (tmp_path / "data.json").write_text("{}")
        (tmp_path / ".env").write_text("SECRET=x")

        graph = _scan_directory(tmp_path, max_files=100, max_depth=4)
        assert graph["root"] == str(tmp_path)
        assert len(graph["nodes"]) >= 4  # root + src + main.py + data.json + .env
        assert len(graph["edges"]) >= 3
        assert graph["stats"]["total_files"] >= 3
        assert graph["stats"]["sensitive_count"] >= 1

    def test_respects_max_depth(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c" / "d" / "e"
        deep.mkdir(parents=True)
        (deep / "deep.txt").write_text("x")

        graph = _scan_directory(tmp_path, max_files=100, max_depth=2)
        file_nodes = [n for n in graph["nodes"] if n["kind"] == "file"]
        deep_files = [n for n in file_nodes if "deep.txt" in n["label"]]
        assert len(deep_files) == 0

    def test_respects_max_files(self, tmp_path):
        for i in range(20):
            (tmp_path / f"file_{i}.txt").write_text(f"content {i}")

        graph = _scan_directory(tmp_path, max_files=5, max_depth=4)
        assert graph["stats"]["total_files"] == 5

    def test_skips_git_dir(self, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main")
        (tmp_path / "code.py").write_text("pass")

        graph = _scan_directory(tmp_path, max_files=100, max_depth=4)
        all_labels = [n["label"] for n in graph["nodes"]]
        assert "HEAD" not in all_labels
        assert ".git" not in all_labels

    def test_type_breakdown(self, tmp_path):
        (tmp_path / "a.py").write_text("x")
        (tmp_path / "b.py").write_text("y")
        (tmp_path / "c.json").write_text("{}")

        graph = _scan_directory(tmp_path, max_files=100, max_depth=4)
        assert graph["stats"]["type_breakdown"]["python"] == 2
        assert graph["stats"]["type_breakdown"]["data"] == 1


class TestRenderHTML:
    def test_produces_valid_html(self, tmp_path):
        (tmp_path / "test.py").write_text("pass")
        graph = _scan_directory(tmp_path, max_files=100, max_depth=4)
        html = _render_galactic_html(graph, "Test")
        assert "<!doctype html>" in html
        assert "canvas" in html
        assert "Galactic Desktop" in html
        assert "test.py" in html  # file should appear in embedded JSON


class TestCommands:
    def test_scan_json(self, tmp_path, capsys):
        (tmp_path / "hello.py").write_text("print(1)")
        rc = cmd_scan(_ns(path=str(tmp_path), json=True))
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["ok"]
        assert out["result"]["stats"]["total_files"] >= 1

    def test_render_creates_html(self, tmp_path, capsys):
        (tmp_path / "app.js").write_text("console.log(1)")
        out_html = tmp_path / "galaxy.html"
        rc = cmd_render(_ns(path=str(tmp_path), out=str(out_html), json=True))
        assert rc == 0
        assert out_html.exists()
        content = out_html.read_text()
        assert "canvas" in content
        assert "app.js" in content

    def test_scan_missing_dir(self, tmp_path, capsys):
        rc = cmd_scan(_ns(path=str(tmp_path / "nonexistent"), json=True))
        assert rc == 1


class TestSystemInfo:
    def test_cpu_info(self):
        cpu = _get_cpu_info()
        assert cpu["cores"] >= 1
        assert isinstance(cpu["usage_pct"], float)
        assert isinstance(cpu["model"], str)

    def test_memory_info(self):
        mem = _get_memory_info()
        assert mem["total_gb"] > 0
        assert mem["used_gb"] >= 0
        assert 0 <= mem["usage_pct"] <= 100

    def test_disk_info(self, tmp_path):
        disk = _get_disk_info(tmp_path)
        assert disk["total_gb"] > 0
        assert disk["free_gb"] >= 0
        assert 0 <= disk["usage_pct"] <= 100

    def test_network_info(self):
        net = _get_network_info()
        assert "interface" in net
        assert "type" in net
        assert "ip" in net

    def test_processes(self):
        procs = _get_processes()
        assert isinstance(procs, list)
        if procs:
            p = procs[0]
            assert "name" in p
            assert "cpu_pct" in p
            assert "mem_pct" in p
            assert "category" in p


class TestSystemSnapshot:
    def test_gather_snapshot(self, tmp_path):
        (tmp_path / "test.py").write_text("pass")
        snap = _gather_system_snapshot(tmp_path)
        assert "hardware" in snap
        assert len(snap["hardware"]) == 5
        assert "processes" in snap
        assert snap["hostname"]
        assert "gpu" in snap
        assert "net_stats" in snap
        assert "monitor_rows" in snap
        assert "ai_usage" in snap
        assert "browser_tabs" in snap

    def test_hardware_nodes_have_ids(self, tmp_path):
        snap = _gather_system_snapshot(tmp_path)
        hw_ids = {n["id"] for n in snap["hardware"]}
        assert "hw_cpu" in hw_ids
        assert "hw_gpu" in hw_ids
        assert "hw_ram" in hw_ids
        assert "hw_disk" in hw_ids
        assert "hw_net" in hw_ids


class TestLiveHTML:
    def test_produces_valid_live_html(self, tmp_path):
        (tmp_path / "app.py").write_text("pass")
        graph = _scan_directory(tmp_path, max_files=10, max_depth=2)
        snap = _gather_system_snapshot(tmp_path)
        html = _render_live_html(snap, graph, "Test", api_token="tok_test")
        assert "<!doctype html>" in html
        assert "PARAD0X COMMAND" in html
        assert "canvas" in html
        assert "pollStats" in html
        assert "/api/stats" in html
        assert 'const API_TOKEN = "tok_test"' in html
        assert '"X-Parad0x-Token": API_TOKEN' in html
        assert 'method: "POST"' in html
        assert "postJsonWithTimeout" in html
        assert "USAGE SURFACE" in html
        assert "AI LEDGER" in html
        assert "THREAT MONITOR" in html
        assert "COMMAND GUIDE" in html
        assert "alarm-overlay" in html
        assert "alarm-sound-toggle" in html
        assert "alarm-sound-select" in html
        assert "ACK / RESET" in html
        assert "toggleAlarmSound" in html
        assert "acknowledgeAlarm" in html
        assert "AGENT OPS" in html
        assert "TASK PROGRESS" in html
        assert "RECENT ACTIVITY" in html
        assert "Provider adapter" in html
        assert "Exact provider cost today" in html
        assert "/api/process-action" in html
        assert "/api/halt" in html
        assert "/api/network" in html
        assert "Force Close" in html
        assert "KILL AGENTS HARD" in html
        assert "HALT AGENTS" in html
        assert "WRITE HALT" in html
        assert "VERIFY HALT" in html
        assert "CUT NETWORK" in html
        assert "RESTORE NETWORK" in html
        assert "OPS LOG" in html
        assert "Threat controls" in html
        assert "System cards" in html
        assert "Nodes and actions" in html
        assert "Privacy and telemetry" in html
        assert "appSlotById" in html
        assert "APP_HUB_ID" in html
        assert "APPS" in html
        assert "groupX" in html
        assert "_appsGrouped" in html
        assert "orbitRadius" in html
        assert "homeX" in html
        assert "renderAgentOps" in html
        assert "renderTaskProgress" in html
        assert "renderActivityFeed" in html
        assert "syncProcessNodes" in html
        assert "removeNodeState" in html
        assert "staleIds.forEach(removeNodeState);" in html
        assert "const visibleMap = new Set(visibleTabs.map(t => browserTabNodeId(t)));" in html
        assert "delete edgeStrengthMap[edgeKey(allEdges[i])];" in html
        assert "syncSubprocessNodes" in html
        assert "clusterAppFollowers" in html
        assert "isAppFollower" in html
        assert "moveAttachedNodes" in html
        assert "setAttachedFixed" in html
        assert "kind: \"child-link\"" in html
        assert "syncAttachedNodeOrbits" in html
        assert "Sticky subprocess orbitals" in html
        assert "sticky orbital follower" in html
        assert ".panel-collapsed { display: none !important; }" in html
        assert "id=\"top-center\"" in html
        assert "id=\"panel-dock\"" in html
        assert "id=\"inspector-layer\"" in html
        assert "pendingActionKeys" in html
        assert "pollInFlight" in html
        assert "syncThreatButtonState" in html
        assert "processActionLabel" in html
        assert "panicActionLabel" in html
        assert "syncBrowserTabs" in html
        assert "openInspectors" in html
        assert "renderInspectorPanel" in html
        assert "refreshOpenInspectors" in html
        assert "processActionByNodeId" in html
        assert 'fetchJsonWithTimeout("/api/stats")' in html
        assert 'fetch("/api/stats").then(r => r.json())' not in html
        assert "/api/open-url" in html
        assert "browser_tab" in html
        assert "Open URL" in html
        assert "Traffic pulse:" in html

    def test_source_uses_threaded_http_server(self):
        source = (Path(__file__).resolve().parents[1] / "tools" / "liquefy_desktop_viz.py").read_text(encoding="utf-8")
        assert "ThreadingHTTPServer" in source
        assert "Access-Control-Allow-Origin" not in source


class TestLocalApiSecurity:
    def test_allowed_local_hosts_include_loopback(self):
        assert _allowed_local_api_hosts(8776) == {"127.0.0.1:8776", "localhost:8776"}

    def test_validate_local_api_request_accepts_expected_headers(self):
        headers = {
            "Host": "127.0.0.1:8776",
            "Origin": "http://127.0.0.1:8776",
            "Referer": "http://127.0.0.1:8776/",
            "X-Parad0x-Token": "tok",
        }
        assert _validate_local_api_request(headers, 8776, "tok") is None

    def test_validate_local_api_request_rejects_wrong_token(self):
        headers = {
            "Host": "127.0.0.1:8776",
            "X-Parad0x-Token": "bad",
        }
        assert _validate_local_api_request(headers, 8776, "tok") == "Invalid API token"

    def test_validate_local_api_request_rejects_wrong_origin(self):
        headers = {
            "Host": "127.0.0.1:8776",
            "Origin": "http://evil.example",
            "X-Parad0x-Token": "tok",
        }
        assert _validate_local_api_request(headers, 8776, "tok") == "Request origin rejected"

    def test_validate_local_api_request_rejects_wrong_host(self):
        headers = {
            "Host": "192.168.1.5:8776",
            "X-Parad0x-Token": "tok",
        }
        assert _validate_local_api_request(headers, 8776, "tok") == "Request host rejected"


class TestNetworkAction:
    def test_network_action_darwin_wifi_prefers_airportpower(self, monkeypatch):
        monkeypatch.setattr(desktop_viz.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(
            desktop_viz,
            "_get_network_info",
            lambda: {"interface": "en0", "type": "WiFi", "active": True},
        )
        monkeypatch.setattr(desktop_viz, "_macos_network_service_for_interface", lambda iface: "Wi-Fi")
        monkeypatch.setattr(desktop_viz.shutil, "which", lambda cmd: f"/usr/bin/{cmd}")
        called = []

        def fake_run_checked(cmd, timeout=8):
            called.append(cmd)
            return True, "ok"

        monkeypatch.setattr(desktop_viz, "_run_checked_cmd", fake_run_checked)
        result = _network_action_result("off")
        assert result["ok"] is True
        assert called
        assert called[0][:3] == ["networksetup", "-setairportpower", "en0"]
        assert called[0][-1] == "off"

    def test_network_action_linux_prefers_nmcli(self, monkeypatch):
        monkeypatch.setattr(desktop_viz.platform, "system", lambda: "Linux")
        monkeypatch.setattr(
            desktop_viz,
            "_get_network_info",
            lambda: {"interface": "wlan0", "type": "WiFi", "active": True},
        )

        def fake_which(cmd):
            if cmd == "nmcli":
                return "/usr/bin/nmcli"
            return None

        monkeypatch.setattr(desktop_viz.shutil, "which", fake_which)
        called = []

        def fake_run_checked(cmd, timeout=8):
            called.append(cmd)
            return True, "ok"

        monkeypatch.setattr(desktop_viz, "_run_checked_cmd", fake_run_checked)
        result = _network_action_result("off")
        assert result["ok"] is True
        assert called[0] == ["nmcli", "networking", "off"]

    def test_network_action_windows_quotes_interface_name(self, monkeypatch):
        monkeypatch.setattr(desktop_viz.platform, "system", lambda: "Windows")
        monkeypatch.setattr(
            desktop_viz,
            "_get_network_info",
            lambda: {"interface": "Wi-Fi", "type": "WiFi", "active": True},
        )
        monkeypatch.setattr(desktop_viz, "_NETWORK_PANIC_STATE", {})
        monkeypatch.setattr(desktop_viz, "_windows_is_admin", lambda: True)
        monkeypatch.setattr(
            desktop_viz,
            "_windows_wifi_profile_info",
            lambda iface: {"interface": iface, "state": "connected", "ssid": "OfficeNet", "profile": "OfficeNet"},
        )
        monkeypatch.setattr(
            desktop_viz,
            "_windows_network_interface_state",
            lambda iface: {"interface": iface, "type": "WiFi", "active": True, "admin_state": "Enabled", "state": "Connected"},
        )
        monkeypatch.setattr(desktop_viz.shutil, "which", lambda cmd: cmd)
        called = []

        def fake_run_checked(cmd, timeout=8):
            called.append(cmd)
            return True, "ok"

        monkeypatch.setattr(desktop_viz, "_run_checked_cmd", fake_run_checked)
        wifi_states = iter([
            {"interface": "Wi-Fi", "state": "connected", "ssid": "OfficeNet", "profile": "OfficeNet"},
            {"interface": "Wi-Fi", "state": "disconnected", "ssid": "", "profile": "OfficeNet"},
        ])
        monkeypatch.setattr(desktop_viz, "_windows_wifi_profile_info", lambda iface: next(wifi_states))
        result = _network_action_result("off")
        assert result["ok"] is True
        assert called[0] == ["netsh", "wlan", "disconnect", 'interface="Wi-Fi"']

    def test_network_action_windows_uses_elevated_fallback_when_not_admin(self, monkeypatch):
        monkeypatch.setattr(desktop_viz.platform, "system", lambda: "Windows")
        monkeypatch.setattr(
            desktop_viz,
            "_get_network_info",
            lambda: {"interface": "Ethernet", "type": "Ethernet", "active": True},
        )
        monkeypatch.setattr(desktop_viz, "_NETWORK_PANIC_STATE", {})
        monkeypatch.setattr(desktop_viz, "_windows_is_admin", lambda: False)
        monkeypatch.setattr(
            desktop_viz,
            "_windows_network_interface_state",
            lambda iface: {"interface": iface, "type": "Ethernet", "active": False, "admin_state": "Disabled", "state": "Disconnected"},
        )
        monkeypatch.setattr(desktop_viz.shutil, "which", lambda cmd: cmd)
        called = []

        def fake_run_checked(cmd, timeout=8):
            called.append(cmd)
            return True, "ok"

        monkeypatch.setattr(desktop_viz, "_run_checked_cmd", fake_run_checked)
        result = _network_action_result("off")
        assert result["ok"] is True
        assert called
        assert "Start-Process" in called[0][3]

    def test_network_action_restore_uses_saved_interface(self, monkeypatch):
        monkeypatch.setattr(desktop_viz.platform, "system", lambda: "Darwin")
        states = [
            {"interface": "en0", "type": "WiFi", "active": True},
            {"interface": "unknown", "type": "unknown", "active": False},
        ]
        monkeypatch.setattr(desktop_viz, "_get_network_info", lambda: states.pop(0))
        monkeypatch.setattr(desktop_viz, "_NETWORK_PANIC_STATE", {})
        monkeypatch.setattr(desktop_viz, "_macos_network_service_for_interface", lambda iface: "Wi-Fi")
        monkeypatch.setattr(desktop_viz.shutil, "which", lambda cmd: f"/usr/bin/{cmd}")
        called = []

        def fake_run_checked(cmd, timeout=8):
            called.append(cmd)
            return True, "ok"

        monkeypatch.setattr(desktop_viz, "_run_checked_cmd", fake_run_checked)
        off_result = _network_action_result("off")
        on_result = _network_action_result("on")
        assert off_result["ok"] is True
        assert on_result["ok"] is True
        assert called[0][:3] == ["networksetup", "-setairportpower", "en0"]
        assert called[0][-1] == "off"
        assert called[1][:3] == ["networksetup", "-setairportpower", "en0"]
        assert called[1][-1] == "on"

    def test_network_action_windows_restore_prefers_saved_wifi_over_current_ethernet(self, monkeypatch):
        monkeypatch.setattr(desktop_viz.platform, "system", lambda: "Windows")
        monkeypatch.setattr(
            desktop_viz,
            "_get_network_info",
            lambda: {"interface": "Ethernet", "type": "Ethernet", "active": False},
        )
        monkeypatch.setattr(
            desktop_viz,
            "_NETWORK_PANIC_STATE",
            {"system": "Windows", "interface": "Wi-Fi", "network_type": "WiFi", "service": "", "wifi_profile": "OfficeNet"},
        )
        monkeypatch.setattr(desktop_viz, "_windows_is_admin", lambda: True)
        monkeypatch.setattr(
            desktop_viz,
            "_windows_network_interface_state",
            lambda iface: {"interface": iface, "type": "WiFi", "active": True, "admin_state": "Enabled", "state": "Connected"},
        )
        monkeypatch.setattr(
            desktop_viz,
            "_windows_wifi_profile_info",
            lambda iface: {"interface": iface, "state": "connected", "ssid": "OfficeNet", "profile": "OfficeNet"},
        )
        monkeypatch.setattr(desktop_viz.shutil, "which", lambda cmd: cmd)
        called = []

        def fake_run_checked(cmd, timeout=8):
            called.append(cmd)
            return True, "ok"

        monkeypatch.setattr(desktop_viz, "_run_checked_cmd", fake_run_checked)
        result = _network_action_result("on")
        assert result["ok"] is True
        assert called[0] == ["netsh", "wlan", "connect", 'name="OfficeNet"', 'interface="Wi-Fi"']


class TestBrowserTabs:
    def test_parse_safari_tabs_json(self):
        raw = json.dumps(
            [
                {
                    "window": 1,
                    "index": 1,
                    "active": True,
                    "title": "OpenClaw Interface",
                    "url": "https://openclaw.example.local/ui",
                },
                {
                    "window": 1,
                    "index": 2,
                    "active": False,
                    "title": "Docs",
                    "url": "https://docs.example.com/path",
                },
            ]
        )
        rows = _parse_safari_tabs_json(raw)
        assert len(rows) == 2
        assert rows[0]["id"] == "safari_tab_1_1"
        assert rows[0]["browser"] == "safari"
        assert rows[0]["host"] == "openclaw.example.local"
        assert rows[0]["label"] == "OpenClaw Interface"
        assert rows[1]["host"] == "docs.example.com"

    def test_get_safari_tabs_uses_jxa_output(self, monkeypatch):
        monkeypatch.setattr("liquefy_desktop_viz.platform.system", lambda: "Darwin")
        monkeypatch.setattr(
            "liquefy_desktop_viz._run_cmd",
            lambda cmd, default="": json.dumps(
                [
                    {
                        "window": 2,
                        "index": 1,
                        "active": True,
                        "title": "OpenClaw",
                        "url": "https://openclaw.example.local",
                    }
                ]
            ),
        )
        rows = _get_safari_tabs()
        assert len(rows) == 1
        assert rows[0]["id"] == "safari_tab_2_1"
        assert rows[0]["host"] == "openclaw.example.local"

    def test_get_browser_tabs_combines_sources(self, monkeypatch):
        monkeypatch.setattr(
            "liquefy_desktop_viz._get_safari_tabs",
            lambda: [{"id": "safari_tab_1_1", "browser": "safari", "window": 1, "index": 1, "active": True, "title": "Safari", "url": "https://apple.example", "host": "apple.example", "label": "Safari"}],
        )
        monkeypatch.setattr(
            "liquefy_desktop_viz._get_chromium_tabs",
            lambda: [{"id": "chrome_tab_a", "browser": "chrome", "window": 1, "index": 1, "active": False, "title": "Chrome", "url": "https://chrome.example", "host": "chrome.example", "label": "Chrome"}],
        )
        rows = _get_browser_tabs()
        assert [row["browser"] for row in rows] == ["safari", "chrome"]

    def test_browser_debug_ports_from_windows_processes(self, monkeypatch):
        monkeypatch.setattr("liquefy_desktop_viz.platform.system", lambda: "Windows")
        monkeypatch.setattr(
            "liquefy_desktop_viz._load_json_cmd",
            lambda cmd, default=None: [
                {"Name": "chrome.exe", "ProcessId": 100, "CommandLine": r'"C:\Chrome\chrome.exe" --remote-debugging-port=9333'},
                {"Name": "msedge.exe", "ProcessId": 101, "CommandLine": r'"C:\Edge\msedge.exe" --remote-debugging-port 9444'},
            ],
        )
        assert _browser_debug_ports_from_processes() == [9333, 9444]

    def test_browser_key_from_process_name_handles_linux_browser_variants(self):
        assert _browser_key_from_process_name("google-chrome-stable") == "chrome"
        assert _browser_key_from_process_name("chromium-browser") == "chrome"
        assert _browser_key_from_process_name("brave-browser") == "chrome"
        assert _browser_key_from_process_name("firefox-esr") == "firefox"

    def test_canonical_process_group_normalizes_linux_browser_variants(self):
        assert _canonical_process_group("google-chrome-stable") == ("chrome", "Google Chrome")
        assert _canonical_process_group("chromium-browser") == ("chrome", "Google Chrome")
        assert _canonical_process_group("brave-browser") == ("chrome", "Google Chrome")
        assert _canonical_process_group("firefox-esr") == ("firefox", "Firefox")

    def test_get_browser_tabs_windows_falls_back_to_window_titles(self, monkeypatch):
        monkeypatch.setattr("liquefy_desktop_viz.platform.system", lambda: "Windows")
        monkeypatch.setattr("liquefy_desktop_viz._get_safari_tabs", lambda: [])
        monkeypatch.setattr("liquefy_desktop_viz._get_chromium_tabs", lambda: [])
        monkeypatch.setattr("liquefy_desktop_viz._get_windows_browser_ui_tabs", lambda: [])
        monkeypatch.setattr(
            "liquefy_desktop_viz._get_windows_browser_window_tabs",
            lambda: [
                {
                    "id": "chrome_window_123",
                    "browser": "chrome",
                    "window": 1,
                    "index": 1,
                    "active": False,
                    "title": "Docs",
                    "url": "",
                    "host": "",
                    "label": "Docs",
                    "fallback_window_title": True,
                }
            ],
        )
        rows = _get_browser_tabs()
        assert len(rows) == 1
        assert rows[0]["browser"] == "chrome"
        assert rows[0]["fallback_window_title"] is True

    def test_get_browser_tabs_windows_prefers_uia_when_it_finds_more_tabs(self, monkeypatch):
        monkeypatch.setattr("liquefy_desktop_viz.platform.system", lambda: "Windows")
        monkeypatch.setattr("liquefy_desktop_viz._get_safari_tabs", lambda: [])
        monkeypatch.setattr(
            "liquefy_desktop_viz._get_chromium_tabs",
            lambda: [
                {"id": "chrome_debug_1", "browser": "chrome", "window": 1, "index": 1, "active": True, "title": "Parad0x Command", "url": "http://127.0.0.1:8776", "host": "127.0.0.1", "label": "Parad0x Command"},
                {"id": "chrome_debug_2", "browser": "chrome", "window": 1, "index": 2, "active": False, "title": "Google Chrome", "url": "chrome://newtab", "host": "", "label": "Google Chrome"},
            ],
        )
        monkeypatch.setattr(
            "liquefy_desktop_viz._get_windows_browser_ui_tabs",
            lambda: [
                {"id": "chrome_uia_1", "browser": "chrome", "window": 1, "index": 1, "active": True, "title": "Parad0x Command", "url": "", "host": "", "label": "Parad0x Command", "fallback_window_title": True, "uia_tab_probe": True},
                {"id": "chrome_uia_2", "browser": "chrome", "window": 1, "index": 2, "active": False, "title": "Docs", "url": "", "host": "", "label": "Docs", "fallback_window_title": True, "uia_tab_probe": True},
                {"id": "chrome_uia_3", "browser": "chrome", "window": 1, "index": 3, "active": False, "title": "Mail", "url": "", "host": "", "label": "Mail", "fallback_window_title": True, "uia_tab_probe": True},
            ],
        )
        monkeypatch.setattr("liquefy_desktop_viz._get_windows_browser_window_tabs", lambda: [])
        rows = _get_browser_tabs()
        assert [row["id"] for row in rows] == ["chrome_uia_1", "chrome_uia_2", "chrome_uia_3"]

    def test_get_windows_browser_window_tabs_prefers_tasklist_verbose_titles(self, monkeypatch):
        monkeypatch.setattr("liquefy_desktop_viz.platform.system", lambda: "Windows")
        monkeypatch.setattr(
            "liquefy_desktop_viz._run_cmd",
            lambda cmd, default="": "\n".join(
                [
                    '"chrome.exe","123","Console","1","300,000 K","Running","user","0:10:00","Docs - Google Chrome"',
                    '"msedge.exe","124","Console","1","250,000 K","Running","user","0:09:00","Mail - Microsoft Edge"',
                ]
            ) if cmd[:3] == ["tasklist", "/v", "/fo"] else "",
        )
        rows = _get_windows_browser_window_tabs()
        assert [row["browser"] for row in rows] == ["chrome", "edge"]
        assert rows[0]["title"] == "Docs"
        assert rows[1]["title"] == "Mail"

    def test_get_windows_browser_ui_tabs_parses_uia_probe_rows(self, monkeypatch):
        monkeypatch.setattr("liquefy_desktop_viz.platform.system", lambda: "Windows")
        monkeypatch.setattr(
            "liquefy_desktop_viz._load_json_cmd",
            lambda cmd, default=None: [
                {"ProcessName": "chrome", "Id": 321, "Window": 1, "Index": 1, "Title": "Parad0x Command", "Active": True},
                {"ProcessName": "chrome", "Id": 321, "Window": 1, "Index": 2, "Title": "Docs", "Active": False},
            ],
        )
        rows = _get_windows_browser_ui_tabs()
        assert [row["title"] for row in rows] == ["Parad0x Command", "Docs"]
        assert rows[0]["uia_tab_probe"] is True

    def test_get_linux_browser_window_tabs_falls_back_to_xprop(self, monkeypatch):
        monkeypatch.setattr("liquefy_desktop_viz.platform.system", lambda: "Linux")

        def fake_which(cmd):
            if cmd == "xprop":
                return "/usr/bin/xprop"
            return None

        monkeypatch.setattr("liquefy_desktop_viz.shutil.which", fake_which)

        def fake_run_cmd(cmd, default=""):
            if cmd == ["xprop", "-root", "_NET_CLIENT_LIST_STACKING"]:
                return "_NET_CLIENT_LIST_STACKING(WINDOW): window id # 0x02a00007, 0x02a0000b"
            if cmd == ["xprop", "-id", "0x02a00007", "WM_CLASS", "_NET_WM_NAME", "WM_NAME"]:
                return '\n'.join([
                    'WM_CLASS(STRING) = "google-chrome", "Google-chrome"',
                    '_NET_WM_NAME(UTF8_STRING) = "Docs - Google Chrome"',
                ])
            if cmd == ["xprop", "-id", "0x02a0000b", "WM_CLASS", "_NET_WM_NAME", "WM_NAME"]:
                return '\n'.join([
                    'WM_CLASS(STRING) = "Navigator", "firefox"',
                    '_NET_WM_NAME(UTF8_STRING) = "Mail - Mozilla Firefox"',
                ])
            return default

        monkeypatch.setattr("liquefy_desktop_viz._run_cmd", fake_run_cmd)
        rows = _get_linux_browser_window_tabs()
        assert [row["browser"] for row in rows] == ["chrome", "firefox"]
        assert [row["title"] for row in rows] == ["Docs", "Mail"]

    def test_get_firefox_session_tabs_reads_recovery_jsonlz4(self, tmp_path, monkeypatch):
        profile_dir = tmp_path / "firefox" / "abcd.default-release"
        session_dir = profile_dir / "sessionstore-backups"
        session_dir.mkdir(parents=True)
        payload = {
            "windows": [
                {
                    "selected": 2,
                    "tabs": [
                        {"index": 1, "entries": [{"url": "https://docs.example.com/path", "title": "Docs"}]},
                        {"index": 1, "entries": [{"url": "https://mail.example.com", "title": "Mail"}]},
                    ],
                }
            ]
        }
        (session_dir / "recovery.jsonlz4").write_bytes(
            _mozlz4_literal_block(json.dumps(payload).encode("utf-8"))
        )
        monkeypatch.setattr("liquefy_desktop_viz._firefox_profile_dirs", lambda: [profile_dir])
        rows = _get_firefox_session_tabs()
        assert [row["title"] for row in rows] == ["Docs", "Mail"]
        assert rows[0]["browser"] == "firefox"
        assert rows[1]["active"] is True
        assert rows[1]["sessionstore_tab"] is True

    def test_get_browser_tabs_linux_uses_window_fallback(self, monkeypatch):
        monkeypatch.setattr("liquefy_desktop_viz.platform.system", lambda: "Linux")
        monkeypatch.setattr("liquefy_desktop_viz._get_safari_tabs", lambda: [])
        monkeypatch.setattr("liquefy_desktop_viz._get_chromium_tabs", lambda: [])
        monkeypatch.setattr("liquefy_desktop_viz._get_firefox_session_tabs", lambda: [])
        monkeypatch.setattr(
            "liquefy_desktop_viz._get_linux_browser_window_tabs",
            lambda: [
                {
                    "id": "chrome_window_1",
                    "browser": "chrome",
                    "window": 1,
                    "index": 1,
                    "active": False,
                    "title": "Docs",
                    "url": "",
                    "host": "",
                    "label": "Docs",
                    "fallback_window_title": True,
                }
            ],
        )
        rows = _get_browser_tabs()
        assert len(rows) == 1
        assert rows[0]["browser"] == "chrome"
        assert rows[0]["fallback_window_title"] is True

    def test_get_browser_tabs_linux_prefers_firefox_session_tabs(self, monkeypatch):
        monkeypatch.setattr("liquefy_desktop_viz.platform.system", lambda: "Linux")
        monkeypatch.setattr("liquefy_desktop_viz._get_safari_tabs", lambda: [])
        monkeypatch.setattr("liquefy_desktop_viz._get_chromium_tabs", lambda: [])
        monkeypatch.setattr(
            "liquefy_desktop_viz._get_firefox_session_tabs",
            lambda: [
                {
                    "id": "firefox_session_1",
                    "browser": "firefox",
                    "window": 1,
                    "index": 1,
                    "active": True,
                    "title": "Mail",
                    "url": "https://mail.example.com",
                    "host": "mail.example.com",
                    "label": "Mail",
                    "sessionstore_tab": True,
                },
                {
                    "id": "firefox_session_2",
                    "browser": "firefox",
                    "window": 1,
                    "index": 2,
                    "active": False,
                    "title": "Docs",
                    "url": "https://docs.example.com",
                    "host": "docs.example.com",
                    "label": "Docs",
                    "sessionstore_tab": True,
                },
            ],
        )
        monkeypatch.setattr(
            "liquefy_desktop_viz._get_linux_browser_window_tabs",
            lambda: [
                {
                    "id": "firefox_window_1",
                    "browser": "firefox",
                    "window": 1,
                    "index": 1,
                    "active": False,
                    "title": "Firefox",
                    "url": "",
                    "host": "",
                    "label": "Firefox",
                    "fallback_window_title": True,
                }
            ],
        )
        rows = _get_browser_tabs()
        assert [row["id"] for row in rows] == ["firefox_session_1", "firefox_session_2"]

    def test_snapshot_includes_browser_tabs(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "liquefy_desktop_viz._get_browser_tabs",
            lambda: [
                {
                    "id": "safari_tab_1_1",
                    "browser": "safari",
                    "window": 1,
                    "index": 1,
                    "active": True,
                    "title": "OpenClaw",
                    "url": "https://openclaw.example.local",
                    "host": "openclaw.example.local",
                    "label": "OpenClaw",
                }
            ],
        )
        snap = _gather_system_snapshot(tmp_path)
        assert snap["browser_tabs"][0]["id"] == "safari_tab_1_1"


class TestCommandDeckHelpers:
    def test_history_summary_disabled_without_workspace(self):
        summary = _load_history_guard_summary(None)
        assert summary["enabled"] is False
        assert summary["providers"] == []

    def test_history_summary_reads_workspace_state(self, tmp_path):
        ws = tmp_path / "ws"
        liq = ws / ".liquefy"
        liq.mkdir(parents=True)
        (liq / "history_guard.json").write_text(
            json.dumps(
                {
                    "providers": [
                        {"id": "gmail", "enabled": True, "type": "email"},
                        {"id": "telegram", "enabled": False, "type": "chat"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        (liq / "history_guard_state.json").write_text(
            json.dumps(
                {
                    "providers": {
                        "gmail": {
                            "last_pull_unix": 1700001000,
                            "last_ok": True,
                            "last_exported_bytes": 1234,
                        },
                        "telegram": {
                            "last_pull_unix": 1700000000,
                            "last_ok": False,
                            "last_error": "network timeout",
                        },
                    },
                    "actions": [
                        {
                            "ts": "2026-02-27T20:00:00Z",
                            "type": "gate-action",
                            "command": "echo delete old markers",
                            "risky": True,
                            "approval_ok": True,
                            "action_rc": 0,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        summary = _load_history_guard_summary(ws)
        assert summary["enabled"] is True
        assert summary["active_provider"] == "gmail"
        assert isinstance(summary["providers"], list)
        assert any("failed" in a or "timeout" in a for a in summary["alerts"])
        assert summary["last_action"]["type"] == "gate-action"

    def test_resolve_background_image_none(self, tmp_path):
        p = _resolve_background_image(tmp_path, "none", tmp_path)
        assert p is None

    def test_resolve_background_image_file(self, tmp_path):
        img = tmp_path / "bg.png"
        img.write_bytes(b"\x89PNG\r\n\x1a\n")
        p = _resolve_background_image(tmp_path, str(img), tmp_path)
        assert p == img.resolve()

    def test_monitor_rows_scores(self):
        rows = _build_monitor_rows(
            [{"pid": 12, "name": "Codex", "cpu_pct": 20.0, "mem_pct": 5.0, "category": "agent", "_group": "codex"}],
            "WiFi",
        )
        assert rows[0]["net_label"] == "WIFI"
        assert rows[0]["cpu"] == 20.0
        assert rows[0]["gpu"] >= 0

    def test_ai_usage_summary_disabled_without_data(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        summary = _load_ai_usage_summary(tmp_path / "ws")
        assert summary["enabled"] is False

    def test_codex_session_entries_use_last_token_usage(self, tmp_path, monkeypatch):
        sess = tmp_path / ".codex" / "sessions" / "2026" / "03" / "01"
        sess.mkdir(parents=True)
        sample = sess / "sample.jsonl"
        sample.write_text(
            json.dumps(
                {
                    "timestamp": "2026-03-01T10:00:00Z",
                    "type": "event_msg",
                    "payload": {
                        "type": "token_count",
                        "info": {
                            "total_token_usage": {
                                "input_tokens": 900000000,
                                "output_tokens": 1000000,
                                "total_tokens": 901000000,
                            },
                            "last_token_usage": {
                                "input_tokens": 1200,
                                "output_tokens": 300,
                                "total_tokens": 1500,
                            },
                        },
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        rows = _load_codex_session_entries(limit_files=10)
        assert len(rows) == 1
        assert rows[0]["total_tokens"] == 1500

    def test_codex_session_entries_total_usage_is_delta_not_cumulative(self, tmp_path, monkeypatch):
        sess = tmp_path / ".codex" / "sessions" / "2026" / "03" / "01"
        sess.mkdir(parents=True)
        sample = sess / "sample.jsonl"
        sample.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "timestamp": "2026-03-01T10:00:00Z",
                            "type": "event_msg",
                            "payload": {
                                "type": "token_count",
                                "info": {"total_token_usage": {"input_tokens": 100, "output_tokens": 20, "total_tokens": 120}},
                            },
                        }
                    ),
                    json.dumps(
                        {
                            "timestamp": "2026-03-01T10:01:00Z",
                            "type": "event_msg",
                            "payload": {
                                "type": "token_count",
                                "info": {"total_token_usage": {"input_tokens": 250, "output_tokens": 50, "total_tokens": 300}},
                            },
                        }
                    ),
                    json.dumps(
                        {
                            "timestamp": "2026-03-01T10:02:00Z",
                            "type": "event_msg",
                            "payload": {
                                "type": "token_count",
                                "info": {"total_token_usage": {"input_tokens": 300, "output_tokens": 70, "total_tokens": 370}},
                            },
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        rows = _load_codex_session_entries(limit_files=10)
        assert len(rows) == 2
        assert rows[0]["input_tokens"] == 150
        assert rows[0]["output_tokens"] == 30
        assert rows[0]["total_tokens"] == 180
        assert rows[1]["input_tokens"] == 50
        assert rows[1]["output_tokens"] == 20
        assert rows[1]["total_tokens"] == 70

    def test_codex_session_entries_extract_rate_limit_model(self, tmp_path, monkeypatch):
        sess = tmp_path / ".codex" / "sessions" / "2026" / "03" / "01"
        sess.mkdir(parents=True)
        sample = sess / "sample.jsonl"
        sample.write_text(
            json.dumps(
                {
                    "timestamp": "2026-03-01T10:00:00Z",
                    "type": "event_msg",
                    "payload": {
                        "type": "token_count",
                        "rate_limits": {"limit_name": "gpt-5.3-codex"},
                        "info": {
                            "last_token_usage": {
                                "input_tokens": 1000,
                                "output_tokens": 200,
                                "total_tokens": 1200,
                            },
                        },
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        rows = _load_codex_session_entries(limit_files=10)
        assert len(rows) == 1
        assert rows[0]["model"] == "gpt-5.3-codex"

    def test_codex_session_entries_inherit_turn_context_model_and_dedupe_pairs(self, tmp_path, monkeypatch):
        sess = tmp_path / ".codex" / "sessions" / "2026" / "03" / "01"
        sess.mkdir(parents=True)
        sample = sess / "sample.jsonl"
        sample.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "timestamp": "2026-03-01T10:00:00Z",
                            "type": "turn_context",
                            "payload": {"model": "gpt-5.3-codex"},
                        }
                    ),
                    json.dumps(
                        {
                            "timestamp": "2026-03-01T10:00:01Z",
                            "type": "event_msg",
                            "payload": {
                                "type": "token_count",
                                "info": {"last_token_usage": {"input_tokens": 500, "output_tokens": 50, "total_tokens": 550}},
                            },
                        }
                    ),
                    json.dumps(
                        {
                            "timestamp": "2026-03-01T10:00:02Z",
                            "type": "event_msg",
                            "payload": {
                                "type": "token_count",
                                "info": {"last_token_usage": {"input_tokens": 500, "output_tokens": 50, "total_tokens": 550}},
                            },
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        rows = _load_codex_session_entries(limit_files=10)
        assert len(rows) == 1
        assert rows[0]["model"] == "gpt-5.3-codex"
        assert rows[0]["total_tokens"] == 550

    def test_codex_session_entries_dedupes_across_files(self, tmp_path, monkeypatch):
        sess = tmp_path / ".codex" / "sessions" / "2026" / "03" / "01"
        arch = tmp_path / ".codex" / "archived_sessions" / "2026" / "03" / "01"
        sess.mkdir(parents=True)
        arch.mkdir(parents=True)
        payload = json.dumps(
            {
                "timestamp": "2026-03-01T10:00:00Z",
                "type": "event_msg",
                "payload": {
                    "type": "token_count",
                    "info": {"last_token_usage": {"input_tokens": 500, "output_tokens": 50, "total_tokens": 550}},
                },
            }
        ) + "\n"
        (sess / "a.jsonl").write_text(payload, encoding="utf-8")
        (arch / "b.jsonl").write_text(payload, encoding="utf-8")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        rows = _load_codex_session_entries(limit_files=10)
        assert len(rows) == 1

    def test_ai_usage_summary_top_models_are_counts(self, tmp_path, monkeypatch):
        sess = tmp_path / ".codex" / "sessions" / "2026" / "03" / "01"
        sess.mkdir(parents=True)
        sample = sess / "sample.jsonl"
        sample.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "timestamp": "2026-03-01T10:00:00Z",
                            "type": "event_msg",
                            "payload": {
                                "type": "token_count",
                                "rate_limits": {"limit_name": "gpt-5.3-codex"},
                                "info": {"last_token_usage": {"input_tokens": 100, "output_tokens": 20, "total_tokens": 120}},
                            },
                        }
                    ),
                    json.dumps(
                        {
                            "timestamp": "2026-03-01T11:00:00Z",
                            "type": "event_msg",
                            "payload": {
                                "type": "token_count",
                                "rate_limits": {"limit_name": "gpt-5.3-codex"},
                                "info": {"last_token_usage": {"input_tokens": 120, "output_tokens": 30, "total_tokens": 150}},
                            },
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        summary = _load_ai_usage_summary(tmp_path / "ws")
        assert summary["enabled"] is True
        assert summary["top_models"][0] == ("gpt-5.3-codex", 2)

    def test_ai_billing_profile_env_override(self, monkeypatch):
        monkeypatch.setenv("LIQUEFY_AI_BILLING_MODE", "quota")
        monkeypatch.setenv("LIQUEFY_AI_BILLING_LABEL", "OpenAI Pro")
        monkeypatch.setenv("LIQUEFY_AI_QUOTA_USED", "42")
        monkeypatch.setenv("LIQUEFY_AI_QUOTA_LIMIT", "100")
        monkeypatch.setenv("LIQUEFY_AI_BILLING_RESET_AT", "2026-03-31")
        profile = _load_ai_billing_profile(None)
        assert profile["mode"] == "quota"
        assert profile["label"] == "OpenAI Pro"
        assert profile["quota_used"] == 42.0
        assert profile["quota_limit"] == 100.0
        assert profile["reset_at"] == "2026-03-31"

    def test_ai_usage_summary_uses_billing_env(self, tmp_path, monkeypatch):
        sess = tmp_path / ".codex" / "sessions" / "2026" / "03" / "01"
        sess.mkdir(parents=True)
        sample = sess / "sample.jsonl"
        sample.write_text(
            json.dumps(
                {
                    "timestamp": "2026-03-01T10:00:00Z",
                    "type": "event_msg",
                    "payload": {
                        "type": "token_count",
                        "info": {"last_token_usage": {"input_tokens": 1000, "output_tokens": 200, "total_tokens": 1200}},
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setenv("LIQUEFY_AI_BILLING_MODE", "subscription")
        monkeypatch.setenv("LIQUEFY_AI_BILLING_LABEL", "ChatGPT Pro")
        summary = _load_ai_usage_summary(tmp_path / "ws")
        assert summary["billing_mode"] == "subscription"
        assert summary["billing_label"] == "ChatGPT Pro"
        assert summary["cost_confidence"] == "estimated"
        assert summary["requests_logged_today"] == summary["calls_today"]
        assert "Subscription remaining quota is not available" in summary["provider_plan_note"]
        assert summary["telemetry_label"] == "Token telemetry events today"
        assert summary["avg_tokens_label"] == "Avg tokens / event"

    def test_ai_usage_summary_quota_profile_fields(self, tmp_path, monkeypatch):
        ws = tmp_path / "ws"
        (ws / ".liquefy-tokens").mkdir(parents=True)
        (ws / ".liquefy-tokens" / "billing.json").write_text(
            json.dumps(
                {
                    "mode": "quota",
                    "label": "OpenAI Pro",
                    "quota_used": 25,
                    "quota_limit": 100,
                    "reset_at": "2026-03-31",
                }
            ),
            encoding="utf-8",
        )
        sess = tmp_path / ".codex" / "sessions" / "2026" / "03" / "01"
        sess.mkdir(parents=True)
        (sess / "sample.jsonl").write_text(
            json.dumps(
                {
                    "timestamp": "2026-03-01T10:00:00Z",
                    "type": "event_msg",
                    "payload": {
                        "type": "token_count",
                        "info": {"last_token_usage": {"input_tokens": 100, "output_tokens": 20, "total_tokens": 120}},
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        summary = _load_ai_usage_summary(ws)
        assert summary["billing_mode"] == "quota"
        assert summary["quota_pct"] == 25.0
        assert summary["quota_remaining"] == 75.0
        assert summary["billing_profile_source"].endswith("billing.json")
        assert summary["provider_plan_available"] is True

    def test_ai_usage_summary_merges_provider_adapter(self, tmp_path, monkeypatch):
        ws = tmp_path / "ws"
        sess = tmp_path / ".codex" / "sessions" / "2026" / "03" / "01"
        sess.mkdir(parents=True)
        (sess / "sample.jsonl").write_text(
            json.dumps(
                {
                    "timestamp": "2026-03-01T10:00:00Z",
                    "type": "event_msg",
                    "payload": {
                        "type": "token_count",
                        "info": {
                            "model": "gpt-5",
                            "last_token_usage": {"input_tokens": 120, "output_tokens": 30, "total_tokens": 150},
                        },
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(
            "liquefy_desktop_viz._load_provider_adapter_status",
            lambda workspace, ai_usage, profile: {
                "provider": "openai",
                "provider_api_status": "ok",
                "provider_api_note": "Exact OpenAI org usage/cost via admin endpoints.",
                "provider_exact_usage": True,
                "provider_exact_billing": True,
                "provider_exact_plan": False,
                "provider_requests_today": 3,
                "provider_input_tokens_today": 1000,
                "provider_output_tokens_today": 200,
                "provider_total_tokens_today": 1200,
                "provider_cost_usd_today": 1.5,
                "provider_month_cost_usd": 9.25,
                "provider_source": "openai_admin_api",
            },
        )
        summary = _load_ai_usage_summary(ws)
        assert summary["provider"] == "openai"
        assert summary["provider_api_status"] == "ok"
        assert summary["provider_exact_usage"] is True
        assert summary["provider_exact_billing"] is True
        assert summary["provider_requests_today"] == 3
        assert summary["provider_cost_usd_today"] == 1.5
        assert summary["provider_source"] == "openai_admin_api"

    def test_provider_adapter_status_gemini_partial(self):
        from liquefy_desktop_viz import _load_provider_adapter_status

        status = _load_provider_adapter_status(
            None,
            {"top_models": [("gemini-2.5-pro", 2)]},
            {"label": "Gemini Advanced", "quota_limit": 1000, "reset_at": "2026-03-31"},
        )
        assert status["provider"] == "gemini"
        assert status["provider_api_status"] == "partial"
        assert status["provider_exact_usage"] is False
        assert status["provider_exact_billing"] is False
        assert status["provider_exact_plan"] is True

    def test_provider_adapter_status_openai_subscription_downgrades_error(self, monkeypatch):
        from liquefy_desktop_viz import _load_provider_adapter_status

        monkeypatch.setattr(
            "liquefy_desktop_viz._fetch_openai_provider_status",
            lambda: {
                "provider": "openai",
                "provider_api_status": "error",
                "provider_api_note": "OpenAI provider API request failed or returned no data.",
                "provider_exact_usage": False,
                "provider_exact_billing": False,
                "provider_exact_plan": False,
            },
        )
        status = _load_provider_adapter_status(
            None,
            {"top_models": [("gpt-5.3-codex", 2)]},
            {"mode": "subscription", "label": "ChatGPT Pro"},
        )
        assert status["provider"] == "openai"
        assert status["provider_api_status"] == "unavailable"
        assert "subscription remaining is not exposed" in status["provider_api_note"].lower()

    def test_billing_doctor_result_reports_exactness(self, tmp_path, monkeypatch):
        sess = tmp_path / ".codex" / "sessions" / "2026" / "03" / "01"
        sess.mkdir(parents=True)
        (sess / "sample.jsonl").write_text(
            json.dumps(
                {
                    "timestamp": "2026-03-01T10:00:00Z",
                    "type": "event_msg",
                    "payload": {
                        "type": "token_count",
                        "info": {
                            "last_token_usage": {
                                "input_tokens": 100,
                                "output_tokens": 20,
                                "total_tokens": 120,
                            },
                        },
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        result = _billing_doctor_result(tmp_path / "ws")
        assert result["status"] == "ok"
        assert result["billing_exactness"] == "estimated"
        assert result["telemetry_source"] == "codex_sessions"
        assert any(item["provider"] == "openai" for item in result["supported_adapters"])

    def test_build_parser_accepts_billing_doctor(self):
        parser = build_parser()
        args = parser.parse_args(["billing-doctor", "--workspace", "/tmp/ws", "--json"])
        assert args.subcmd == "billing-doctor"
        assert args.workspace == "/tmp/ws"
        assert args.json is True

    def test_canonical_process_group_strips_helper_suffixes(self):
        key, display = _canonical_process_group("Spotify Helper (Renderer)")
        assert key == "spotify"
        assert display == "Spotify"

    def test_canonical_process_group_strips_windows_exe_suffix(self):
        key, display = _canonical_process_group("Cursor Helper.exe")
        assert key == "cursor"
        assert display == "Cursor"

    def test_get_processes_collapses_helper_groups(self, monkeypatch):
        monkeypatch.setattr("liquefy_desktop_viz.platform.system", lambda: "Darwin")
        monkeypatch.setattr(
            "liquefy_desktop_viz._run_cmd",
            lambda cmd: "\n".join(
                [
                    "  PID %CPU %MEM COMM",
                    "  101 2.0 1.0 /Applications/Spotify.app/Contents/MacOS/Spotify",
                    "  102 3.0 1.5 /Applications/Spotify.app/Contents/Frameworks/Spotify Helper (Renderer)",
                    "  103 1.0 0.5 /Applications/Discord.app/Contents/Frameworks/Discord Helper",
                ]
            ),
        )
        rows = _get_processes()
        spotify = next(p for p in rows if p["_group"] == "spotify")
        assert spotify["name"] == "Spotify"
        assert spotify["pid"] == 101
        assert spotify["instance_count"] == 2
        assert sorted(spotify["_pids"]) == [101, 102]
        assert pytest.approx(spotify["cpu_pct"], rel=1e-3) == 5.0

    def test_get_processes_prefers_primary_app_pid_over_helper(self, monkeypatch):
        monkeypatch.setattr("liquefy_desktop_viz.platform.system", lambda: "Darwin")
        monkeypatch.setattr(
            "liquefy_desktop_viz._run_cmd",
            lambda cmd: "\n".join(
                [
                    "  PID %CPU %MEM COMM",
                    "  111 1.0 0.5 /Applications/Spotify.app/Contents/Frameworks/Spotify Helper (Renderer)",
                    "  99 2.0 1.1 /Applications/Spotify.app/Contents/MacOS/Spotify",
                ]
            ),
        )
        rows = _get_processes()
        spotify = next(p for p in rows if p["_group"] == "spotify")
        assert spotify["name"] == "Spotify"
        assert spotify["pid"] == 99
        assert sorted(spotify["_pids"]) == [99, 111]
        assert spotify["instance_count"] == 2

    def test_get_processes_windows_tasklist_groups_helpers(self, monkeypatch):
        monkeypatch.setattr("liquefy_desktop_viz.platform.system", lambda: "Windows")
        monkeypatch.setattr("liquefy_desktop_viz._get_memory_info", lambda: {"total_gb": 16.0, "used_gb": 8.0, "usage_pct": 50.0})
        monkeypatch.setattr(
            "liquefy_desktop_viz._run_cmd",
            lambda cmd: "\n".join(
                [
                    '"Cursor.exe","111","Console","1","150,000 K"',
                    '"Cursor Helper.exe","112","Console","1","50,000 K"',
                    '"msedge.exe","211","Console","1","240,000 K"',
                ]
            ) if cmd[:2] == ["tasklist", "/fo"] else "",
        )
        rows = _get_processes()
        cursor = next(p for p in rows if p["_group"] == "cursor")
        edge = next(p for p in rows if p["_group"] == "edge")
        assert cursor["name"] == "Cursor"
        assert cursor["pid"] == 111
        assert cursor["instance_count"] == 2
        assert sorted(cursor["_pids"]) == [111, 112]
        assert edge["name"] == "Edge"

    def test_get_gpu_info_windows_uses_video_controller_name(self, monkeypatch):
        monkeypatch.setattr("liquefy_desktop_viz.platform.system", lambda: "Windows")
        monkeypatch.setattr(
            "liquefy_desktop_viz._run_cmd",
            lambda cmd, default="": "NVIDIA GeForce RTX 4070" if "Win32_VideoController" in " ".join(cmd) else "",
        )
        gpu = _get_gpu_info()
        assert gpu["model"] == "NVIDIA GeForce RTX 4070"

    def test_group_process_action_targets_all_pids(self, monkeypatch):
        called = []
        monkeypatch.setattr(
            "liquefy_desktop_viz._find_group_process",
            lambda group: {
                "pid": 99,
                "name": "Spotify",
                "_group": "spotify",
                "_pids": [99, 111, 112],
            },
        )
        monkeypatch.setattr("liquefy_desktop_viz._quit_app_result", lambda app: {"ok": True, "app": app})
        monkeypatch.setattr("liquefy_desktop_viz._expand_pid_tree", lambda pids: list(pids))
        monkeypatch.setattr("liquefy_desktop_viz.time.sleep", lambda _: None)
        monkeypatch.setattr(
            "liquefy_desktop_viz._process_action_result",
            lambda pid, action: called.append((pid, action)) or {"ok": True, "pid": pid, "action": action},
        )
        result = _group_process_action_result("spotify", "term")
        assert result["ok"] is True
        assert result["count"] == 3
        assert called == [(99, "term"), (111, "term"), (112, "term")]

    def test_group_process_action_term_returns_after_quit_if_group_disappears(self, monkeypatch):
        calls = {"n": 0}
        def _fake_find(group):
            calls["n"] += 1
            if calls["n"] == 1:
                return {"pid": 99, "name": "Spotify", "_group": "spotify", "_pids": [99, 111]}
            return None
        monkeypatch.setattr("liquefy_desktop_viz._find_group_process", _fake_find)
        monkeypatch.setattr("liquefy_desktop_viz._quit_app_result", lambda app: {"ok": True, "app": app})
        monkeypatch.setattr("liquefy_desktop_viz._expand_pid_tree", lambda pids: list(pids))
        monkeypatch.setattr("liquefy_desktop_viz.time.sleep", lambda _: None)
        monkeypatch.setattr("liquefy_desktop_viz._process_action_result", lambda pid, action: pytest.fail("should not fallback to pid kill"))
        result = _group_process_action_result("spotify", "term")
        assert result["ok"] is True
        assert result["count"] == 0
        assert result["quit_result"]["ok"] is True

    def test_group_process_action_kill_rescans_survivors(self, monkeypatch):
        calls = {"n": 0}
        def _fake_find(group):
            calls["n"] += 1
            if calls["n"] in {1, 2}:
                return {"pid": 99, "name": "Spotify", "_group": "spotify", "_pids": [99, 111]}
            if calls["n"] == 3:
                return {"pid": 111, "name": "Spotify", "_group": "spotify", "_pids": [111]}
            return None
        monkeypatch.setattr("liquefy_desktop_viz._find_group_process", _fake_find)
        monkeypatch.setattr("liquefy_desktop_viz._expand_pid_tree", lambda pids: list(pids))
        monkeypatch.setattr("liquefy_desktop_viz.time.sleep", lambda _: None)
        called = []
        monkeypatch.setattr(
            "liquefy_desktop_viz._process_action_result",
            lambda pid, action: called.append((pid, action)) or {"ok": True, "pid": pid, "action": action},
        )
        result = _group_process_action_result("spotify", "kill")
        assert result["ok"] is True
        assert result["count"] == 3
        assert called == [(99, "kill"), (111, "kill"), (111, "kill")]
        assert result["survivor_count"] == 0

    def test_agent_process_action_targets_grouped_agent_pids(self, monkeypatch):
        monkeypatch.setattr(
            "liquefy_desktop_viz._get_processes",
            lambda: [{
                "pid": 500,
                "name": "Codex",
                "category": "agent",
                "_group": "codex",
                "_pids": [500, 501],
            }],
        )
        called = []
        monkeypatch.setattr(
            "liquefy_desktop_viz._group_process_action_result",
            lambda group, action: called.append((group, action)) or {"ok": True, "group": group, "action": action, "count": 2},
        )
        result = _agent_process_action_result("kill")
        assert result["ok"] is True
        assert result["count"] == 2
        assert result["survivor_count"] == 0
        assert called == [("codex", "kill")]

    def test_agent_process_action_aggregates_survivors(self, monkeypatch):
        monkeypatch.setattr(
            "liquefy_desktop_viz._get_processes",
            lambda: [
                {"pid": 500, "name": "Codex", "category": "agent", "_group": "codex", "_pids": [500, 501]},
                {"pid": 700, "name": "Cursor", "category": "agent", "_group": "cursor", "_pids": [700]},
            ],
        )
        monkeypatch.setattr(
            "liquefy_desktop_viz._group_process_action_result",
            lambda group, action: (
                {"ok": True, "group": group, "action": action, "count": 2, "survivor_count": 1}
                if group == "codex"
                else {"ok": True, "group": group, "action": action, "count": 1, "survivor_count": 0}
            ),
        )
        result = _agent_process_action_result("kill")
        assert result["ok"] is True
        assert result["count"] == 3
        assert result["survivor_count"] == 1

    def test_get_process_children_map(self, monkeypatch):
        monkeypatch.setattr("liquefy_desktop_viz.platform.system", lambda: "Darwin")
        monkeypatch.setattr(
            "liquefy_desktop_viz._run_cmd",
            lambda cmd: "\n".join(
                [
                    "  PID  PPID COMM",
                    "  100    1 /App/Main",
                    "  101  100 /App/Helper",
                    "  102  100 /App/Renderer",
                    "  200    1 /Other/App",
                ]
            ),
        )
        children = _get_process_children_map()
        assert children[100] == [101, 102]
        assert children[1] == [100, 200]

    def test_expand_pid_tree_collects_descendants(self, monkeypatch):
        monkeypatch.setattr(
            "liquefy_desktop_viz._get_process_children_map",
            lambda: {
                10: [11, 12],
                11: [13],
                12: [14],
                99: [100],
            },
        )
        assert _expand_pid_tree([10]) == [10, 12, 14, 11, 13]

    def test_group_process_action_targets_process_tree(self, monkeypatch):
        called = []
        monkeypatch.setattr(
            "liquefy_desktop_viz._find_group_process",
            lambda group: {
                "pid": 99,
                "name": "Spotify",
                "_group": "spotify",
                "_pids": [99, 111],
            },
        )
        monkeypatch.setattr("liquefy_desktop_viz._quit_app_result", lambda app: {"ok": True, "app": app})
        monkeypatch.setattr("liquefy_desktop_viz.time.sleep", lambda _: None)
        monkeypatch.setattr("liquefy_desktop_viz._expand_pid_tree", lambda pids: [99, 150, 151, 111, 160])
        monkeypatch.setattr(
            "liquefy_desktop_viz._process_action_result",
            lambda pid, action: called.append((pid, action)) or {"ok": True, "pid": pid, "action": action},
        )
        result = _group_process_action_result("spotify", "kill")
        assert result["ok"] is True
        assert result["count"] == 10
        assert called == [
            (99, "kill"), (150, "kill"), (151, "kill"), (111, "kill"), (160, "kill"),
            (99, "kill"), (150, "kill"), (151, "kill"), (111, "kill"), (160, "kill"),
        ]

    def test_agent_ops_summary(self):
        summary = _build_agent_ops_summary(
            [
                {"name": "Codex", "pid": 123, "cpu_pct": 10.0, "mem_pct": 5.0, "category": "agent"},
                {"name": "Safari", "pid": 456, "cpu_pct": 3.0, "mem_pct": 2.0, "category": "browser"},
            ],
            {"providers": [{"enabled": True, "last_ok": True}], "active_provider": "gmail"},
            {"halt_present": False, "risky_actions_24h": 0},
        )
        assert summary["status"] == "CLEAR"
        assert summary["agent_count"] == 1
        assert summary["providers_enabled"] == 1
        assert summary["active_provider"] == "gmail"

    def test_task_progress_summary(self):
        summary = _build_task_progress_summary(
            {
                "providers": [{"enabled": True, "last_ok": True}],
                "active_provider": "gmail",
                "last_action": {"type": "pull-cycle", "command": "sync"},
            }
        )
        assert summary["phase"] == "pull-cycle"
        assert summary["sync_pct"] == 100.0

    def test_activity_feed(self):
        feed = _build_activity_feed(
            {"last_action": {"type": "gate-action", "command": "block risky", "ts": "2026-03-01T10:00:00Z"}},
            [{"name": "Codex", "cpu": 30.0, "ram": 4.0}, {"name": "Safari", "cpu": 10.0, "ram": 2.0}],
            {"alerts": ["provider gmail last pull failed"]},
        )
        assert feed[0]["kind"] == "history"
        assert any(item["kind"] == "hot" for item in feed)
        assert any(item["kind"] == "alert" for item in feed)

    def test_threat_summary_alarm(self):
        threat = _build_threat_summary(
            {"providers": [{"last_ok": False}, {"last_ok": False}], "risky_actions_24h": 2, "alerts": []},
            {"stats": {"sensitive_count": 3, "agent_related_count": 4}},
            {"estimated_cost_usd_today": 0.0},
            None,
        )
        assert threat["status"] == "ALARM"
        assert threat["level"] == "red"

    def test_threat_summary_does_not_alarm_on_unarmed_heartbeat(self):
        threat = _build_threat_summary(
            {"providers": [], "risky_actions_24h": 0, "alerts": []},
            {"stats": {"sensitive_count": 0, "agent_related_count": 0}},
            {"estimated_cost_usd_today": 1000.0, "source": "codex_sessions"},
            Path("/tmp/nowhere"),
        )
        assert "heartbeat missing" not in " ".join(threat["alerts"])

    def test_threat_summary_marks_halt_present(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / ".liquefy-halt").write_text("stop", encoding="utf-8")
        threat = _build_threat_summary(
            {"providers": [], "risky_actions_24h": 0, "alerts": []},
            {"stats": {"sensitive_count": 0, "agent_related_count": 0}},
            {"estimated_cost_usd_today": 0.0, "source": "workspace_ledger"},
            ws,
        )
        assert threat["halt_present"] is True
        assert "halt signal present" in " ".join(threat["alerts"])

    def test_process_action_invalid_pid(self):
        result = _process_action_result(0, "term")
        assert result["ok"] is False

    def test_agent_process_action_no_agents(self, monkeypatch):
        monkeypatch.setattr("liquefy_desktop_viz._get_processes", lambda: [])
        result = _agent_process_action_result("term")
        assert result["ok"] is False
