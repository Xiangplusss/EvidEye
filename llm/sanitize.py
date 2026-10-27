"""LLM 输入脱敏层：风险词抽象 + URL defang。

背景：云端 LLM（DashScope 等）对请求输入做内容安全检查，诈骗/博彩页面的
原文（文本、表单字段、截图 OCR）会触发 data_inspection_failed 400，
导致模型拿不到任何页面信息。

原则（安全研究场景的标准 de-identification 做法，非绕过审核）：
- 不向云端传输违规原文，只传输「类别 + 出现次数」的结构化信号；
- 模型据此仍可判断页面主题与风险话术类别（博彩/色情/诈骗/违禁药品等）；
- 原始证据（未脱敏文本、截图路径）仍完整写入本地 SQLite 证据链，
  报告渲染与人工复核不受影响；
- 仅替换触发审核的高危词，其余文本（标题、布局描述、表单结构等）
  原样保留，最大限度保留分析价值。

开关：这是为「云端模型」准备的传输层适配，不是永久设计。
本地部署模型（Ollama / vLLM）没有内容审核，可设环境变量
EVIDEYE_SANITIZE=0 关闭本层，届时送入模型的是页面原文，
报告也可直接引用原文而无需以类别信号代替。
"""
from __future__ import annotations

import os
import re

# 本地模型部署后可关闭：EVIDEYE_SANITIZE=0 / false / off
_DISABLED = os.environ.get("EVIDEYE_SANITIZE", "1").strip().lower() in {
    "0", "false", "off", "no"}

# 高危词类别表：(编译后正则, 英文类别标签)
# 英文标签避免标签本身再次触发中文内容审核
_CATEGORY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"博彩|赌[场博位数球牌]|百家乐|六合彩|时时彩|北京赛车|"
                r"幸运飞艇|棋牌|现金网|威尼斯人|澳门[赌银]|"
                r"下注|注单|返水|水位|赔率|开奖|投注", re.I), "gambling"),
    (re.compile(r"色情|淫[秽乱]|做爱|援交|约炮|一夜情|外围女|处女|"
                r"激情[视电] |裸聊|福利[视频片]", re.I), "adult"),
    (re.compile(r"诈骗|欺诈|骗[子局]|反诈|刷单|兼职返利|杀猪盘|"
                r"冻结|解冻费|保证金|洗钱|公证费", re.I), "scam"),
    (re.compile(r"迷[奸魂药]|春药|催情|伟哥|壮阳|安眠药|后悔药", re.I), "drug"),
    (re.compile(r"木马|挂马|远控|键盘记录|勒索|病毒|盗号", re.I), "malware"),
    (re.compile(r"网警|网安|上门|报复|追杀|透露给第三方", re.I), "threat"),
]

# 诱导联系方式：保留平台类别，去掉账号原文
_CONTACT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?:TG|电报|飞机|t\.me/)[^\s，,。；;：:）)】]*", re.I),
     "[contact:telegram]"),
    (re.compile(r"(?:微信|威信|VX|V信|加V|wechat)\s*(?:号|ID)?\s*[:：]?\s*"
                r"(?:[A-Za-z][A-Za-z0-9_\-]{2,}|\d{4,})?", re.I),
     "[contact:wechat]"),
    (re.compile(r"(?:QQ|企鹅)[群号]?[:：\s]*\d{5,12}", re.I), "[contact:qq]"),
    (re.compile(r"(?:客服|联系)[^\s，,。]{0,6}[:：]?\s*[\w\-.]{4,}", re.I),
     "[contact:support]"),
]

_URL_RE = re.compile(r"(https?://)([^\s\"'<>）)】]+)", re.I)
_WS_RE = re.compile(r"[ \t]{2,}")

# 已生成的占位符（[flag:xxx] / [contact:xxx]），后续规则不得再次匹配其内容
_PLACEHOLDER_RE = re.compile(r"\[(?:flag|contact):[^\]\n]*\]")

# 露骨内容行级匹配：命中整行抽象（词级替换挡不住成段露骨描述）
_EXPLICIT_LINE_RE = re.compile(
    r"AV|口交|做爱|啪啪|强奸|迷奸|幼女|萝莉|偷拍|无码|乱伦|性爱|外流|"
    r"强上|破处|处破|援交|白嫖|换妻|群交|肛交|自慰|射精|高潮|"
    r"处女膜|私处|肉棒|淫|骚|裸聊|床戏|福利姬|极品身材|"
    r"校服|潜规则|打飞机|性对接|约炮|炮友| stimulated", re.I)


def _sub_count(text: str, pattern: re.Pattern, tag: str) -> str:
    """把 pattern 命中的原文替换为 [flag:tag]，连续命中合并计数。"""
    hits = len(pattern.findall(text))
    if not hits:
        return text
    return pattern.sub(f"[flag:{tag}]", text) + f" [flag:{tag} x{hits}]"


def _sub_keep_placeholders(text: str, pattern: re.Pattern, repl: str) -> str:
    """只在占位符之外的片段上做替换，避免二次匹配破坏已生成的占位符。"""
    parts = _PLACEHOLDER_RE.split(text)
    holes = _PLACEHOLDER_RE.findall(text)
    out: list[str] = []
    for i, seg in enumerate(parts):
        out.append(pattern.sub(repl, seg))
        if i < len(holes):
            out.append(holes[i])
    return "".join(out)


def defang_urls(text: str) -> str:
    """URL defang：http→hxxp，域名点号→[.]。保留可读性与可逆性。"""
    def _repl(m: re.Match) -> str:
        host_path = m.group(2)
        # 只 defang host 部分的点（第一个 / 之前）
        head, sep, tail = host_path.partition("/")
        return f"hxxp{m.group(1)[4:]}{head.replace('.', '[.]')}" + \
            (sep + tail if sep else "")
    return _URL_RE.sub(_repl, text)


def sanitize_for_llm(text: str) -> str:
    """对送入 LLM 的页面文本做风险词抽象与 URL defang。

    三层处理：露骨行整行抽象 → 类别词抽象 → URL defang。
    """
    if not text:
        return text
    if _DISABLED:
        # 本地模型部署模式：不过滤，原文直送（云端模式下不可关闭）
        return text
    # 1) 行级：露骨描述整行替换，保留行数统计（词级替换挡不住成段露骨内容）
    lines, explicit_hits = [], 0
    for line in text.splitlines():
        if _EXPLICIT_LINE_RE.search(line):
            explicit_hits += 1
            lines.append("[flag:adult-line]")
        else:
            lines.append(line)
    out = "\n".join(lines)
    if explicit_hits:
        out += f" [flag:adult-line x{explicit_hits}]"
    # 2) 词级 + 3) URL
    for pat, tag in _CATEGORY_PATTERNS:
        out = _sub_count(out, pat, tag)
    for pat, tag in _CONTACT_PATTERNS:
        out = _sub_keep_placeholders(out, pat, tag)
    out = defang_urls(out)
    return _WS_RE.sub(" ", out)


def profile_for_llm(text: str) -> str:
    """三级降级：从原文提炼统计画像（不含任何原句）。

    输出紧凑 JSON：类别命中计数、联系方式类型、外链域名、露骨行占比。
    不含违规原文，可稳定通过云审核，供 LLM 在原文被拦截时仍能完成
    内容维度研判。
    """
    import json
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    cats = {}
    for pat, tag in _CATEGORY_PATTERNS:
        n = len(pat.findall(text or ""))
        if n:
            cats[tag] = n
    explicit = sum(1 for ln in lines if _EXPLICIT_LINE_RE.search(ln))
    contacts = sorted({tag for pat, tag in _CONTACT_PATTERNS
                       if pat.search(text or "")})
    domains = sorted({m.group(2).split("/")[0]
                      for m in _URL_RE.finditer(text or "")})[:10]
    title = sanitize_for_llm(lines[0])[:80] if lines else ""
    return json.dumps({
        "page_title_sanitized": title,
        "category_hits": cats,
        "contact_types": contacts,
        "external_domains": [d.replace(".", "[.]") for d in domains],
        "lines_total": len(lines),
        "explicit_lines": explicit,
        "explicit_ratio": round(explicit / max(1, len(lines)), 2),
        "note": ("原文被云端内容审核拦截，以上为本地风险词统计画像；"
                 "explicit_ratio 高说明页面以成人/违规内容为主"),
    }, ensure_ascii=False)


def sanitize_signals(obj, _depth: int = 0) -> object:
    """递归脱敏信号结构（dict/list/str），供综合研判 JSON 使用。

    只处理字符串值；深度超限或非字符串原样返回。
    """
    if _depth > 8:
        return obj
    if isinstance(obj, str):
        return sanitize_for_llm(obj)
    if isinstance(obj, dict):
        return {k: sanitize_signals(v, _depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize_signals(v, _depth + 1) for v in obj]
    return obj
