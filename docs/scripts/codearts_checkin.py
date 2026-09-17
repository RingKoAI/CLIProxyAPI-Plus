#!/usr/bin/env python3
"""
CodeArts（华为云 CodeArts Work 桌面端）每日签到脚本

调用 CodeArts 的「每日签到领积分」福利接口。接口与字段从桌面客户端
（Electron 渲染层 + agent-kernel）逆向提取，见 docs/codearts.md §7。

签到有两套体系，前端优先用 ①，失败退回 ②：

① 活动/福利体系（policyCenterDomain = snap-access）
  - 查询活动:  GET  {snap}/v1/ops/delivery?channel=DESKTOP
  - 执行签到:  POST {snap}/v1/ops/claim
       body {"campaignId": "...", "idempotentKey": "claim_<cid>_<ms>", "channel": "DESKTOP"}
  - 确认领取:  POST {snap}/v1/ops/confirm   body {"userBenefitId": "..."}
    注意：confirm 与官方客户端对齐只传 userBenefitId，且是尽力而为——积分在 claim
    成功时即已入账（实测 2026-09-17：confirm 返回 HDN.1000 但积分已到账、
    活动状态已置 CLAIMED；官方渲染层也不检查 confirm 返回值）。
  请求头：Agent-Type: PromptCenter, X-Language: zh-cn, Content-Type: application/json
  判定：code == 0 || code == 200 || data 存在
  data.items[] 字段：campaignId|campaign_id（数字！）, type(USER_LOGIN|...),
                     extra.triggerEvent(user.login = 每日签到),
                     benefitAmount, claimable, status(ELIGIBLE|CLAIMED|CONFIRMED|CONSUMED)

② 简单签到（benefitApiUrl = opengw.developer.huaweicloud.com）
  - 查询/执行:  GET/POST {benefit}/api/v1/benefit/claim   (POST body {})
  - 余额:       GET      {benefit}/api/v1/user/tokens/balance
  判定：error_code == "0000"，数据在 result

鉴权（与其它 CLIProxyAPI codearts 接口一致）：
  华为云 SDK-HMAC-SHA256 签名，使用 OAuth 登录拿到的临时 AK/SK/security_token。
  SignedHeaders = host;x-sdk-date;x-security-token（外加业务头按字典序并入）。

凭证来源（自动读取，也可手动传入）：
  CLIProxyAPI 的 codearts auth 文件（JSON，含 access_key/secret_key/security_token），
  默认在 data/auth_files/codearts-*.json 或 --auth-dir / --auth-file 指定。

用法:
  uv run codearts_checkin.py                          # 查询活动 + 签到（自动找凭证）
  uv run codearts_checkin.py status                   # 仅查询活动/签到状态
  uv run codearts_checkin.py balance                  # 仅查询积分余额
  uv run codearts_checkin.py --auth-file <FILE>       # 指定单个凭证文件
  uv run codearts_checkin.py --auth-dir <DIR>         # 对目录下所有 codearts*.json 签到
  uv run codearts_checkin.py --ak <AK> --sk <SK> --st <ST>   # 手动指定三元组
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from urllib.parse import quote, urlsplit

# ---------------------------------------------------------------- 常量
SNAP_ENGINE = "https://snap-access.cn-north-4.myhuaweicloud.com"
BENEFIT_API = "https://opengw.developer.huaweicloud.com"

WELFARE_DELIVERY_PATH = "/v1/ops/delivery"
WELFARE_CLAIM_PATH = "/v1/ops/claim"
WELFARE_CONFIRM_PATH = "/v1/ops/confirm"
BENEFIT_CLAIM_PATH = "/api/v1/benefit/claim"
BALANCE_PATH = "/api/v1/user/tokens/balance"

AGENT_TYPE = "PromptCenter"
ALGORITHM = "SDK-HMAC-SHA256"


# ---------------------------------------------------------------- 签名（SDK-HMAC-SHA256）
def _escape(value: str) -> str:
    """华为云 URI/查询转义：保留 A-Za-z0-9-_.~，其余大写百分号编码。"""
    return quote(value, safe="-_.~")


def _canonical_uri(path: str) -> str:
    if not path:
        return "/"
    encoded = "/".join(_escape(seg) for seg in path.split("/"))
    if not encoded.endswith("/"):
        encoded += "/"
    return encoded


def _canonical_query(query: str) -> str:
    if not query:
        return ""
    pairs = []
    for item in query.split("&"):
        if not item:
            continue
        if "=" in item:
            k, v = item.split("=", 1)
        else:
            k, v = item, ""
        pairs.append(f"{_escape(k)}={_escape(v)}")
    pairs.sort()
    return "&".join(pairs)


def sign_request(method: str, url: str, access_key: str, secret_key: str,
                 extra_headers: dict[str, str] | None = None,
                 body: bytes = b"") -> dict[str, str]:
    """返回签名后的请求头（含 Authorization / X-Sdk-Date / X-Security-Token 由调用方并入）。

    extra_headers 里应包含 X-Security-Token（若有）以及业务头（Agent-Type 等），
    这些头会并入 SignedHeaders。
    """
    headers: dict[str, str] = {}
    for k, v in (extra_headers or {}).items():
        headers[k] = v

    parts = urlsplit(url)
    sdk_date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    headers["host"] = parts.netloc
    headers["X-Sdk-Date"] = sdk_date

    # canonical headers（小写 key、trim value、按 key 排序）
    entries = sorted(
        ((k.strip().lower(), str(v).strip()) for k, v in headers.items()),
        key=lambda kv: kv[0],
    )
    canonical_headers = "".join(f"{k}:{v}\n" for k, v in entries)
    signed_headers = ";".join(k for k, _ in entries)

    payload_hash = hashlib.sha256(body).hexdigest()
    canonical_request = "\n".join([
        method.upper(),
        _canonical_uri(parts.path),
        _canonical_query(parts.query),
        canonical_headers,
        signed_headers,
        payload_hash,
    ])
    string_to_sign = "\n".join([
        ALGORITHM,
        sdk_date,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])
    signature = hmac.new(
        secret_key.encode("utf-8"), string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    headers["Authorization"] = (
        f"{ALGORITHM} Access={access_key}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return headers


# ---------------------------------------------------------------- HTTP
def _http(method: str, url: str, creds: dict, extra: dict[str, str],
          body: bytes = b"", timeout: int = 15) -> dict:
    """签名并发起一次请求，返回 {status, payload}。"""
    import urllib.error
    import urllib.request

    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise RuntimeError(f"拒绝非 http(s) 的 URL scheme: {parts.scheme!r}")

    headers_to_sign = dict(extra)
    if creds.get("security_token"):
        headers_to_sign["X-Security-Token"] = creds["security_token"]
    signed = sign_request(method, url, creds["access_key"], creds["secret_key"],
                          headers_to_sign, body)

    req_headers = {k: v for k, v in signed.items() if k.lower() != "host"}
    req_headers.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url, data=body if method.upper() != "GET" else None,
                                 headers=req_headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            text = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status = e.code
        text = e.read().decode("utf-8", "replace")
    except Exception as e:  # 网络错误
        return {"status": 0, "payload": {"error": str(e)}}

    try:
        payload = json.loads(text)
    except Exception:
        payload = {"raw": text}
    return {"status": status, "payload": payload}


# ---------------------------------------------------------------- 凭证
def load_credential(auth_file: Path) -> dict:
    """从 CLIProxyAPI codearts auth 文件读取签名三元组。"""
    try:
        data = json.loads(auth_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"凭证文件不存在: {auth_file}") from None
    except json.JSONDecodeError as e:
        raise SystemExit(f"凭证文件不是合法 JSON: {auth_file}: {e}") from None
    ak = data.get("access_key") or data.get("api_key")
    sk = data.get("secret_key")
    st = data.get("security_token") or ""
    if not ak or not sk:
        raise SystemExit(f"凭证文件 {auth_file} 缺少 access_key/secret_key。")
    return {
        "access_key": ak,
        "secret_key": sk,
        "security_token": st,
        "user_name": data.get("user_name") or "",
        "_path": str(auth_file),
    }


def _auth_dir_files(auth_dir: Path, prefix: str) -> list[Path]:
    if not auth_dir.is_dir():
        raise SystemExit(f"--auth-dir 指定的目录不存在: {auth_dir}")
    files = sorted(p for p in auth_dir.glob("*.json") if p.name.startswith(prefix))
    if not files:
        raise SystemExit(f"--auth-dir 下没有匹配的 {prefix}*.json: {auth_dir}")
    return files


def _default_auth_file() -> Path:
    """在常见位置找 codearts 凭证文件。"""
    env = os.environ.get("CODEARTS_AUTH_FILE")
    if env:
        return Path(env)
    candidates = [
        Path.cwd() / "data" / "auth_files",
        Path.cwd() / "auths",
        Path.home() / ".cli-proxy-api",
    ]
    for d in candidates:
        if d.is_dir():
            hits = sorted(d.glob("codearts-*.json"))
            if hits:
                return hits[0]
    raise SystemExit("未找到 codearts 凭证。请用 --auth-file/--auth-dir 指定，"
                     "或设置 CODEARTS_AUTH_FILE。")


# ---------------------------------------------------------------- 福利体系 ①
def list_activities(snap: str, creds: dict, timeout: int) -> list[dict]:
    url = f"{snap}{WELFARE_DELIVERY_PATH}?channel=DESKTOP"
    r = _http("GET", url, creds, {"Agent-Type": AGENT_TYPE, "X-Language": "zh-cn"}, timeout=timeout)
    if r["status"] != 200:
        raise RuntimeError(f"查询活动失败 HTTP {r['status']}: {json.dumps(r['payload'], ensure_ascii=False)}")
    p = r["payload"]
    code = p.get("code")
    if code not in (None, 0, 200):
        raise RuntimeError(f"查询活动返回错误 code={code}: {p.get('message')}")
    items = (p.get("data") or {}).get("items") or []
    out = []
    for it in items:
        extra = it.get("extra") or {}
        campaign_id = it.get("campaignId") or it.get("campaign_id") or ""
        out.append({
            "campaign_id": str(campaign_id),
            "type": (it.get("type") or "").strip().lower(),
            "title": it.get("title") or "",
            "benefit_amount": it.get("benefitAmount") or 0,
            "claimable": bool(it.get("claimable", True)),
            "status": (it.get("status") or "").strip().upper(),
            # triggerEvent 是判定「每日签到」的最可靠信号：user.login = 登录即签到。
            "trigger_event": (extra.get("triggerEvent") or "").strip().lower(),
        })
    return out


def _is_daily_checkin(activity: dict) -> bool:
    """判定一个活动是否为「每日签到」。

    实测（2026-09）：每日签到活动的 type 是 USER_LOGIN（不是文档里的 daily_claim），
    其 extra.triggerEvent 为 user.login。因此判据为：trigger_event == user.login，
    或 type ∈ {daily_claim, user_login}，或标题含「每日签到」。
    """
    if activity["trigger_event"] == "user.login":
        return True
    if activity["type"] in ("daily_claim", "user_login"):
        return True
    return "每日签到" in (activity.get("title") or "")


def _claimable_daily(activities: list[dict]) -> dict | None:
    for a in activities:
        if not _is_daily_checkin(a):
            continue
        if not a["claimable"]:
            continue
        if a["status"] in ("CLAIMED", "CONFIRMED", "CONSUMED"):
            continue
        return a
    return None


def claim_activity(snap: str, creds: dict, campaign_id: str, timeout: int) -> dict:
    url = f"{snap}{WELFARE_CLAIM_PATH}"
    body = json.dumps({
        "campaignId": campaign_id,
        "idempotentKey": f"claim_{campaign_id}_{int(time.time() * 1000)}",
        "channel": "DESKTOP",
    }).encode("utf-8")
    r = _http("POST", url, creds, {"Agent-Type": AGENT_TYPE, "X-Language": "zh-cn"},
              body=body, timeout=timeout)
    if r["status"] != 200:
        raise RuntimeError(f"签到失败 HTTP {r['status']}: {json.dumps(r['payload'], ensure_ascii=False)}")
    p = r["payload"]
    code = p.get("code")
    if code not in (None, 0, 200):
        raise RuntimeError(f"签到返回错误 code={code}: {p.get('message')}")
    data = p.get("data") or {}
    return {"user_benefit_id": str(data.get("id") or data.get("userBenefitId") or "")}


def confirm_activity(snap: str, creds: dict, user_benefit_id: str, timeout: int) -> None:
    """确认领取（尽力而为）。与官方客户端对齐：body 只传 userBenefitId。
    积分在 claim 成功时已入账，confirm 失败不影响签到结果（官方渲染层也不检查
    confirm 的返回值）。错误返回用 error_code/error_msg，与 claim 的 code/message 不同。"""
    url = f"{snap}{WELFARE_CONFIRM_PATH}"
    body = json.dumps({"userBenefitId": user_benefit_id}).encode("utf-8")
    r = _http("POST", url, creds, {"Agent-Type": AGENT_TYPE, "X-Language": "zh-cn"},
              body=body, timeout=timeout)
    p = r["payload"]
    code = p.get("code")
    ec = p.get("error_code")
    if r["status"] == 200 and code in (None, 0, 200) and ec in (None, "0000"):
        return
    raise RuntimeError(
        f"HTTP {r['status']} code={code} error_code={ec}: "
        f"{p.get('message') or p.get('error_msg')}"
    )


# ---------------------------------------------------------------- 简单体系 ②
def simple_benefit_claim(benefit: str, creds: dict, timeout: int) -> dict:
    url = f"{benefit}{BENEFIT_CLAIM_PATH}"
    r = _http("POST", url, creds, {"X-Language": "zh-cn"}, body=b"{}", timeout=timeout)
    p = r["payload"]
    ec = p.get("error_code")
    if r["status"] == 200 and ec in (None, "0000"):
        return {"ok": True, "result": p.get("result")}
    raise RuntimeError(f"简单签到失败 HTTP {r['status']} error_code={ec}: {p.get('error_msg')}")


def fetch_balance(benefit: str, creds: dict, timeout: int) -> dict:
    url = f"{benefit}{BALANCE_PATH}"
    r = _http("GET", url, creds, {"X-Language": "zh-cn"}, timeout=timeout)
    p = r["payload"]
    ec = p.get("error_code")
    if r["status"] == 200 and ec in (None, "0000"):
        return p.get("result") or {}
    raise RuntimeError(f"查询余额失败 HTTP {r['status']} error_code={ec}: {p.get('error_msg')}")


# ---------------------------------------------------------------- 编排
def _show_balance(benefit: str, creds: dict, timeout: int) -> None:
    try:
        bal = fetch_balance(benefit, creds, timeout)
    except Exception as e:
        print(f"[!] 查询余额失败: {e}")
        return
    print(f"[i] 积分余额: total={bal.get('total_balance')} / quota={bal.get('total_quota')}"
          f"  今日已用={bal.get('daily_tokens_used')}  累计已用={bal.get('used_amount')}")


def run_one(args: argparse.Namespace, creds: dict) -> int:
    name = creds.get("user_name") or creds.get("_path", "")
    print(f"[i] 账号: {name}")
    snap = args.snap_engine.rstrip("/")
    benefit = args.benefit_api.rstrip("/")

    if args.action == "balance":
        _show_balance(benefit, creds, args.timeout)
        return 0

    # ---- 查询活动状态
    try:
        activities = list_activities(snap, creds, args.timeout)
    except Exception as e:
        print(f"[!] 福利活动列表不可用: {e}")
        activities = []

    if args.action == "status":
        if not activities:
            print("[i] 无福利活动数据。")
        for a in activities:
            flag = "可领" if _claimable_daily([a]) else "已领/不可领"
            print(f"  - [{a['type']}] {a['title'] or a['campaign_id']}  "
                  f"金额={a['benefit_amount']}  状态={a['status']}  {flag}")
        _show_balance(benefit, creds, args.timeout)
        return 0

    # ---- 签到
    daily = _claimable_daily(activities)
    if daily is not None:
        print(f"[i] 发现可领每日签到活动: {daily['title'] or daily['campaign_id']}"
              f"（{daily['benefit_amount']} 积分）")
        try:
            claimed = claim_activity(snap, creds, daily["campaign_id"], args.timeout)
        except Exception as e:
            print(f"[!] 福利体系签到失败，尝试简单签到兜底: {e}")
        else:
            # claim 成功即签到成功（积分已入账）；confirm 仅尽力而为。
            ubi = claimed.get("user_benefit_id")
            if ubi:
                try:
                    confirm_activity(snap, creds, ubi, args.timeout)
                except Exception as e:
                    print(f"[!] 确认领取(confirm)未通过（不影响签到结果）: {e}")
            else:
                print("[i] claim 未返回 userBenefitId，跳过 confirm。")
            print(f"[✓] 签到成功，领取 {daily['benefit_amount']} 积分。")
            _show_balance(benefit, creds, args.timeout)
            return 0
    elif activities:
        # 有活动但无可领的每日签到 => 已签到
        print("[i] 今日已签到（或无可领的每日活动）。")
        _show_balance(benefit, creds, args.timeout)
        return 0

    # ---- 兜底：简单签到
    try:
        simple_benefit_claim(benefit, creds, args.timeout)
        print("[✓] 签到成功（简单签到通道）。")
    except Exception as e:
        print(f"[✗] 签到失败: {e}")
        return 1
    _show_balance(benefit, creds, args.timeout)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="CodeArts 每日签到")
    ap.add_argument("action", nargs="?", default="checkin",
                    choices=["status", "checkin", "balance"])
    ap.add_argument("--snap-engine", default=os.environ.get("CODEARTS_SNAP_ENGINE", SNAP_ENGINE),
                    help="活动/福利体系 host")
    ap.add_argument("--benefit-api", default=os.environ.get("CODEARTS_BENEFIT_API", BENEFIT_API),
                    help="简单签到/余额 host")
    ap.add_argument("--auth-file", type=Path, default=None, help="单个 codearts 凭证文件")
    ap.add_argument("--auth-dir", type=Path, default=None, help="对目录下所有 codearts*.json 签到")
    ap.add_argument("--prefix", default="codearts", help="配合 --auth-dir 的文件名前缀")
    ap.add_argument("--ak", default=None, help="手动 access_key")
    ap.add_argument("--sk", default=None, help="手动 secret_key")
    ap.add_argument("--st", default=None, help="手动 security_token")
    ap.add_argument("--timeout", type=int, default=15)
    args = ap.parse_args()

    if args.ak and args.sk:
        return run_one(args, {"access_key": args.ak, "secret_key": args.sk,
                              "security_token": args.st or "", "user_name": "(manual)"})

    if args.auth_dir:
        rc = 0
        for path in _auth_dir_files(args.auth_dir, args.prefix):
            print("\n" + "=" * 60)
            print(f"[i] 凭证文件: {path}")
            print("=" * 60)
            try:
                rc += run_one(args, load_credential(path))
            except SystemExit as e:
                print(f"[✗] 跳过: {e}")
                rc += 1
        return rc

    auth_file = args.auth_file or _default_auth_file()
    return run_one(args, load_credential(auth_file))


if __name__ == "__main__":
    raise SystemExit(main())
