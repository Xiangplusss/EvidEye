"""受控 Playwright 浏览器封装 + 隔离层（§8.1 分级）。

L1（推荐）：Docker 容器隔离 —— 官方镜像 mcr.microsoft.com/playwright/python，
业务代码通过 CDP 远程驱动容器内浏览器（浏览器进程完全不在主机上运行），
证据目录通过挂载卷传出，每次分析用全新容器，用完销毁。

L2（降级）：受限浏览器配置 —— 只是进程级加固、不是沙箱；
禁下载/禁通知/禁地理定位、独立临时 user-data-dir、视口 1280×720。

运行级别自动探测（isolation: auto）并写入日志与报告脚注。
"""
from __future__ import annotations

import logging
import random
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

log = logging.getLogger(__name__)

_DOCKER_CDP_PORT = 9222


def _docker_daemon_ok() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        r = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                           capture_output=True, timeout=10, text=True)
        return r.returncode == 0 and r.stdout.strip() != ""
    except Exception:  # noqa: BLE001
        return False


def decide_isolation(cfg: dict) -> str:
    """auto 模式下探测 Docker；返回 'L1' 或 'L2'。"""
    mode = cfg.get("sandbox", {}).get("isolation", "auto")
    if mode == "l1":
        if not _docker_daemon_ok():
            raise RuntimeError("强制 L1 但 Docker 守护进程不可用")
        return "L1"
    if mode == "l2":
        return "L2"
    level = "L1" if _docker_daemon_ok() else "L2"
    if level == "L2":
        log.warning("Docker 不可用，降级为 L2 受限浏览器配置（非沙箱，仅加固）")
    return level


class SandboxBrowser:
    """统一封装：导航 / 截图 / 重定向链记录 / 受限配置。

    用法:
        with SandboxBrowser(cfg, evidence_dir) as b:
            b.page.goto(...)
    """

    def __init__(self, cfg: dict, evidence_dir: str):
        self.cfg = cfg
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.isolation = decide_isolation(cfg)
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        self.redirect_chain: list[str] = []
        self._container_name: str | None = None
        self._tmp_profile: tempfile.TemporaryDirectory | None = None
        self._cdp_wait_s = int(cfg.get("sandbox", {})
                               .get("cdp_wait_timeout_seconds", 120))
        self._cdp_rounds = int(cfg.get("sandbox", {})
                               .get("cdp_port_rotate_rounds", 5))
        self._cdp_probe_s = 15  # 单轮宿主机侧探测超时（快速失败换端口）

    # ---------- lifecycle ----------
    def __enter__(self) -> "SandboxBrowser":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def start(self) -> None:
        from playwright.sync_api import sync_playwright

        self.playwright = sync_playwright().start()
        sb = self.cfg.get("sandbox", {})
        vp = sb.get("browser", {})
        width, height = vp.get("viewport_width", 1280), vp.get("viewport_height", 720)
        timeout = (vp.get("navigation_timeout_seconds", 30)) * 1000

        if self.isolation == "L1":
            self._start_docker_browser(sb["docker"])
        else:
            self._start_local_browser()

        self.context = self.browser.new_context(
            viewport={"width": width, "height": height},
            # §8.2 通用约束 3：禁下载/禁通知/禁地理定位
            accept_downloads=False,
            permissions=[],
            locale="zh-CN",
        )
        self.context.set_default_navigation_timeout(timeout)
        self.page = self.context.new_page()
        self.page.on("popup", lambda p: self.redirect_chain.append(p.url))
        log.info("沙箱浏览器已启动，隔离级别=%s", self.isolation)

    def _start_docker_browser(self, dcfg: dict) -> None:
        """L1：拉起一次性容器，CDP 远程连接（含端口映射快速换端口重试）。

        背景：Chrome(131+) 新无头模式忽略 --remote-debugging-address，CDP 只
        绑容器内 127.0.0.1；Docker Desktop 的 -p 端口映射层偶发故障，且容器
        IP 对宿主机不可路由。策略：容器内起 TCP 转发器(0.0.0.0:9223→127.0.0.1:9222)，
        -p 映射随机宿主端口；容器内确认就绪后宿主机快速探测，不通则换端口
        重建容器（最多 5 轮）。
        """
        image = dcfg.get("image", "mcr.microsoft.com/playwright/python:v1.49.0-jammy")
        ev_container = dcfg.get("evidence_dir_container", "/data/evidence")
        ev_host = str(self.evidence_dir.resolve())

        # 镜像不存在则拉取（首次较慢）
        r = subprocess.run(["docker", "image", "inspect", image],
                           capture_output=True, timeout=30)
        if r.returncode != 0:
            log.info("拉取 Playwright 官方镜像 %s ...", image)
            subprocess.run(["docker", "pull", image], check=True, timeout=900)

        # TCP 转发器：不依赖 Chrome 的 CDP 绑定行为。
        # 写为容器内脚本文件执行，规避 shell 引号嵌套问题。
        forwarder_py = (
            "import socket,threading,time\n"
            'def pipe(a, b):\n'
            "    try:\n"
            "        while True:\n"
            "            d = a.recv(65536)\n"
            "            if not d:\n"
            "                break\n"
            "            b.sendall(d)\n"
            "    except Exception:\n"
            "        pass\n"
            "    finally:\n"
            "        try:\n"
            "            a.close()\n"
            "        except Exception:\n"
            "            pass\n"
            "        try:\n"
            "            b.close()\n"
            "        except Exception:\n"
            "            pass\n"
            "def handle(c):\n"
            "    u = socket.socket()\n"
            "    while True:\n"
            "        try:\n"
            '            u.connect(("127.0.0.1", 9222))\n'
            "            break\n"
            "        except Exception:\n"
            "            time.sleep(0.2)\n"
            "    threading.Thread(target=pipe, args=(c, u), daemon=True).start()\n"
            "    threading.Thread(target=pipe, args=(u, c), daemon=True).start()\n"
            "srv = socket.socket()\n"
            "srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            'srv.bind(("0.0.0.0", 9223))\n'
            "srv.listen(50)\n"
            "while True:\n"
            "    try:\n"
            "        c, _ = srv.accept()\n"
            "    except Exception:\n"
            "        time.sleep(0.1)\n"
            "        continue\n"
            "    threading.Thread(target=handle, args=(c,), daemon=True).start()\n"
        )
        # heredoc 写脚本，避免引号转义地狱。
        # 注意：各步骤用换行分隔而非 && 链——bash 的 & 优先级低于 &&，
        # 若写成 "mkdir && cat <<EOF && chrome ... & python3 fwd.py"，
        # 会把整条链（含写脚本）丢进后台，python3 在 fwd.py 落盘前就启动并
        # 秒退，导致容器 PID1 退出、容器终止，chrome 被一并杀死
        #（"容器内无 chrome 进程" 的根因）。
        container_cmd = (
            f"mkdir -p {ev_container}\n"
            "cat > /tmp/fwd.py <<'PYEOF'\n"
            f"{forwarder_py}"
            "PYEOF\n"
            "CHROME=$(ls /ms-playwright/chromium-*/chrome-linux/chrome | head -1)\n"
            "$CHROME --headless --no-sandbox --disable-gpu "
            "--disable-dev-shm-usage --remote-debugging-port=9222 "
            "--user-data-dir=/tmp/profile --lang=zh-CN > /tmp/chrome.log 2>&1 &\n"
            "python3 /tmp/fwd.py"
        )

        # 端口映射快速换端口重试：容器内确认就绪(docker exec，稳定)后，
        # 宿主机探测映射端口，不通则换随机端口重建容器，最多 _cdp_rounds 轮
        rounds = self._cdp_rounds
        last_err = "unknown"
        while rounds > 0:
            rounds -= 1
            self._container_name = f"fraud-sandbox-{uuid.uuid4().hex[:8]}"
            port = random.randint(9300, 9399)
            run = subprocess.run(
                ["docker", "run", "-d", "--rm", "--name", self._container_name,
                 "-p", f"127.0.0.1:{port}:9223",
                 "-v", f"{ev_host}:{ev_container}",
                 "--shm-size=1g", image,
                 "bash", "-c", container_cmd],
                capture_output=True, text=True, timeout=60,
            )
            if run.returncode != 0:
                raise RuntimeError(f"docker run 失败: {run.stderr[:300]}")
            try:
                # 1) 容器内侧确认 chrome+转发器就绪（docker exec，稳定可靠）
                self._wait_container_ready()
                # 2) 宿主机侧经端口映射探测（偶发故障点），短超时快速失败
                self._wait_cdp(port, timeout_s=self._cdp_probe_s)
                self.browser = self.playwright.chromium.connect_over_cdp(
                    f"http://127.0.0.1:{port}")
                self._cdp_port = port
                return
            except Exception as e:  # noqa: BLE001
                last_err = str(e)[:300]
                log.warning("第 %d 轮容器 CDP 连接失败: %s",
                            self._cdp_rounds - rounds, last_err)
                # 只销毁容器，保留 playwright 实例供下一轮重连
                self._destroy_container()
        raise RuntimeError(
            f"容器 CDP 连续 {self._cdp_rounds} 轮未就绪（含换端口重建），"
            f"最后错误: {last_err}")

    def _wait_container_ready(self, timeout_s: int = 90) -> None:
        """容器内侧确认：Chrome CDP(9222) 与转发器(9223) 均可连通。

        稳定性策略：
        - exec 探测失败区分「端口未就绪」与「exec 本身报错」；
        - 开始 45s 后若容器内连 chrome 进程都没有，判定容器僵死，
          提前失败重建（避免单轮傻等 90s）；
        - 最终超时时附带 docker logs，便于诊断 Chrome 启动失败原因。
        """
        probe = (
            "import socket\n"
            "s1=socket.socket(); s1.settimeout(2)\n"
            "s2=socket.socket(); s2.settimeout(2)\n"
            "a=s1.connect_ex(('127.0.0.1',9222))\n"
            "b=s2.connect_ex(('127.0.0.1',9223))\n"
            "exit(0 if a==0 and b==0 else 1)"
        )
        name = self._container_name or ""
        deadline = time.time() + timeout_s
        giveup_check_at = time.time() + 45
        last_note = ""
        while time.time() < deadline:
            r = subprocess.run(
                ["docker", "exec", name, "python3", "-c", probe],
                capture_output=True, timeout=20)
            if r.returncode == 0:
                return
            if r.returncode != 1:  # 非"未就绪"，exec 自身出错
                last_note = r.stderr.decode(errors="ignore")[:200]
            # 45s 后仍无 chrome 进程 → 容器僵死，提前放弃本轮
            if time.time() > giveup_check_at:
                t = subprocess.run(
                    ["docker", "top", name], capture_output=True,
                    text=True, timeout=15)
                if "chrome" not in (t.stdout or "").lower():
                    raise RuntimeError(
                        f"容器内无 chrome 进程（判定僵死，提前放弃）"
                        f" exec_note={last_note} top={t.stdout[:150]}")
            time.sleep(1)
        logs = subprocess.run(
            ["docker", "logs", "--tail", "15", name],
            capture_output=True, text=True, timeout=15)
        tail = (logs.stdout or "").strip()[-400:] or \
               (logs.stderr or "").strip()[-400:]
        raise RuntimeError(
            f"容器内 chrome/转发器在 {timeout_s}s 内未就绪"
            f" exec_note={last_note} container_logs={tail}")

    def _wait_cdp(self, port: int, timeout_s: int = 15) -> None:
        """宿主机经端口映射探测 CDP HTTP 端点。"""
        import httpx
        deadline = time.time() + timeout_s
        last_err = None
        while time.time() < deadline:
            try:
                r = httpx.get(f"http://127.0.0.1:{port}/json/version",
                              timeout=2)
                if r.status_code == 200:
                    return
            except Exception as e:  # noqa: BLE001
                last_err = e
            time.sleep(0.5)
        raise RuntimeError(f"宿主机经映射端口 {port} 探测 CDP 失败: {last_err}")

    def _start_local_browser(self) -> None:
        """L2：本机浏览器 + 加固参数（§8.1）。"""
        self._tmp_profile = tempfile.TemporaryDirectory(prefix="fraud-sandbox-")
        self.browser = self.playwright.chromium.launch(
            headless=True,
            args=[
                "--disable-features=Translate,BackForwardCache",
                "--disable-notifications",
                "--disable-geolocation",
                "--mute-audio",
                "--no-first-run",
                "--disable-remote-fonts",
            ],
            downloads_path=str(self._tmp_profile.name),
        )
        # Chromium 启动参数不含 profile，用 context 层确保隔离
        log.warning("运行于 L2 级别：受限浏览器配置不是沙箱，无法抵御针对"
                    "浏览器漏洞的 drive-by 攻击；测试集应避免已知活跃挂马站点")

    def _destroy_container(self) -> None:
        """仅销毁容器（重试轮次间使用，不动 playwright 实例）。"""
        try:
            if self.context:
                self.context.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            if self.browser:
                self.browser.close()
        except Exception:  # noqa: BLE001
            pass
        self.context = None
        self.browser = None
        if self._container_name:
            subprocess.run(["docker", "rm", "-f", self._container_name],
                           capture_output=True, timeout=30)
            log.info("已销毁一次性容器 %s", self._container_name)

    def stop(self) -> None:
        for closer in (self.context, self.browser):
            try:
                if closer:
                    closer.close()
            except Exception:  # noqa: BLE001
                pass
        try:
            if self.playwright:
                self.playwright.stop()
        except Exception:  # noqa: BLE001
            pass
        if self._container_name:
            subprocess.run(["docker", "rm", "-f", self._container_name],
                           capture_output=True, timeout=30)
            log.info("已销毁一次性容器 %s", self._container_name)
        if self._tmp_profile:
            self._tmp_profile.cleanup()
            self._tmp_profile = None
        log.info("沙箱浏览器已停止")

    # ---------- capabilities ----------
    def register_domain_allowlist(self, allowed_domains: list[str]) -> None:
        """§8.2 通用约束 1：仅允许目标域名 + 其静态资源域名出站。

        以 route 拦截方式在网络层实施：对不匹配 allowlist 的请求 abort。
        """
        import fnmatch
        patterns = ["*://" + d + "/*" for d in allowed_domains]

        def _guard(route):
            url = route.request.url
            host = url.split("//", 1)[-1].split("/", 1)[0].split(":")[0]
            for p in allowed_domains:
                if host == p or fnmatch.fnmatch(host, "*." + p):
                    return route.continue_()
            log.info("拦截越域请求: %s", url)
            route.abort()

        self.context.route("**/*", _guard)

    def screenshot(self, full_page: bool = True) -> str:
        path = self.evidence_dir / f"screenshot-{uuid.uuid4().hex[:8]}.png"
        self.page.screenshot(path=str(path), full_page=full_page)
        return str(path)

    def record_redirect(self, url: str) -> None:
        if url not in self.redirect_chain:
            self.redirect_chain.append(url)
