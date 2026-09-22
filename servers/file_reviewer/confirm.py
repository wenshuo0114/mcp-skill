"""确认词：编号选项 + 模糊命中 + 命中多个就缩小再问。

用户输入经常卡住、打不全，一字不差的确认词太苛刻。规则：
- 回编号（"1"、"选2"）→ 命中。
- 回原话 → 命中。
- 回几个关键字（"是我的，有权限"、"给予"打成"继续"也行）→ 按关键字打分命中。
- 同时能对上两个选项 → 不猜，把这几个选项缩小后再问一次。
- 含否定/停止词（"不是"、"停"、"别人的"）→ 一律按"停止"选项处理，安全优先。
- 什么都对不上 → 原样列出全部选项。
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field


@dataclass
class Option:
    编号: int
    键: str                       # 原话（一字不差也能命中）
    说明: str
    关键字: list[str] = field(default_factory=list)      # 命中任一即得分
    区分词: list[str] = field(default_factory=list)      # 只有这个选项才有的词；命中则优先于共有关键字
    否定优先: bool = False        # 停止/拒绝类选项：命中即胜出，不参与模糊比较
    值: object = None             # 命中后交给调用方的值


@dataclass
class Match:
    命中: Option | None
    需要再选: list[Option]        # 非空 = 缩小后的选项，请用户再选一次
    说明: str

    def to_dict(self) -> dict:
        return {
            "命中": self.命中.编号 if self.命中 else None,
            "命中说明": self.命中.说明 if self.命中 else None,
            "需要再选": [o.编号 for o in self.需要再选],
            "说明": self.说明,
        }


_PUNCT = re.compile(r"[\s✅✔☑√，,。.、；;：:！!？?“”\"'‘’（）()\[\]【】<>《》\-—_~·]+")


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text or "")
    return _PUNCT.sub("", text).lower()


def render(options: list[Option], title: str = "请选一个（回编号或关键字都可以）") -> dict:
    return {
        "标题": title,
        "选项": [{"编号": o.编号, "原话": o.键, "说明": o.说明} for o in options],
        "怎么回": "回编号（如 1）、回原话、或回几个关键字都行。打错字也没关系，对不上我会把范围缩小再问一次。",
    }


def match(reply: str, options: list[Option]) -> Match:
    raw = (reply or "").strip()
    if not raw:
        return Match(None, [], "还没收到你的选择。")
    norm = normalize(raw)

    # 0. 否定/停止优先：任何一个"否定优先"选项的关键字出现，就按它处理
    for o in options:
        if o.否定优先 and any(normalize(k) in norm for k in o.关键字):
            return Match(o, [], f"你的话里有「{next(k for k in o.关键字 if normalize(k) in norm)}」，按「{o.说明}」处理。")

    # 1. 编号
    m = re.fullmatch(r"(?:选|第)?(\d+)(?:号|个|项)?", norm)
    if m:
        n = int(m.group(1))
        hit = next((o for o in options if o.编号 == n), None)
        if hit:
            return Match(hit, [], f"按编号 {n} 命中：{hit.说明}")
        return Match(None, list(options), f"没有编号 {n} 的选项。")

    # 2. 原话
    for o in options:
        if normalize(o.键) == norm:
            return Match(o, [], f"原话命中：{o.说明}")

    # 3. 区分词
    distinct = [o for o in options if not o.否定优先 and any(normalize(k) in norm for k in o.区分词)]
    if len(distinct) == 1:
        return Match(distinct[0], [], f"按区分词命中：{distinct[0].说明}")
    if len(distinct) > 1:
        return Match(None, distinct, "你的话同时对上了下面几个，我不猜，请再选一次。")

    # 4. 共有关键字打分
    scored = []
    for o in options:
        if o.否定优先:
            continue
        s = sum(1 for k in o.关键字 if normalize(k) in norm)
        if s:
            scored.append((s, o))
    if not scored:
        return Match(None, list(options), "没对上任何选项，请从下面选。")
    top = max(s for s, _ in scored)
    tops = [o for s, o in scored if s == top]
    if len(tops) == 1 and len(scored) == 1:
        return Match(tops[0], [], f"按关键字命中：{tops[0].说明}")
    # 多个选项都得分：缩小到得分的这几个，再问
    return Match(None, [o for _, o in scored], "你的话能对上下面几个，我不猜，请再选一次。")


def ask(options: list[Option], m: Match | None, title: str) -> dict:
    """生成“需要你选”的返回体：命中多个就只列缩小后的。"""
    narrowed = m.需要再选 if (m and m.需要再选) else options
    body = render(narrowed, title if not (m and m.需要再选) else "缩小范围了，请在下面再选一次")
    if m:
        body["上一次"] = m.说明
    return body


# ---------------- 各处门禁的选项定义 ----------------

STOP_WORDS = ["不是", "不对", "不确定", "不知道", "停", "取消", "算了", "不要", "不扫", "不读", "不恢复", "不动", "不删", "不改", "拒绝", "等一下", "先别", "别扫", "别读", "别动", "别删", "别改", "别恢复", "别弄"]


def owner_options() -> list[Option]:
    return [
        Option(1, "✅ 这台机器是我的，我有权限，继续", "是我的机器、我有管理员权限，继续",
               关键字=["是我的", "我的", "有权限", "权限", "继续", "是我", "管理员", "是的", "对", "给予"], 值=True),
        Option(2, "不是我的 / 不确定 / 停", "不是我的、或不确定、或没有权限：停在这里，不扫整盘",
               关键字=STOP_WORDS + ["没权限", "没有权限", "别人的", "他人的", "公司的", "朋友的"], 否定优先=True, 值=False),
    ]


def disk_options() -> list[Option]:
    return [
        Option(1, "✅ 授权只读扫描整盘（只扫我能扫的，永不进其他用户家目录）",
               "扫整盘：跳过其他用户家目录。本工具没有「含其他用户」选项。",
               关键字=["授权", "整盘", "扫", "扫描", "只读", "只我", "不含"], 值=True),
        Option(2, "不扫", "不扫整盘。可以改用 mode=文件夹 只扫你自己的目录",
               关键字=STOP_WORDS + ["含其他", "包含其他", "其他用户", "别人的", "他人的"], 否定优先=True, 值=False),
    ]


def credential_options(filename: str) -> list[Option]:
    return [
        Option(1, f"✅ 授权只读密钥文件 {filename}", f"只读 {filename}：只回显变量名和结构，值一律隐去",
               关键字=["授权", "只读", "密钥", "读", filename], 值=True),
        Option(2, "不读", "不读这个文件；它只出现在凭据清单里（路径、变量名、git 跟踪状态）",
               关键字=STOP_WORDS, 否定优先=True, 值=False),
    ]


def restore_options(name: str) -> list[Option]:
    return [
        Option(1, f"用户已授权恢复 {name}", f"恢复回滚点 {name}：会覆盖仓库内对应文件",
               关键字=["授权", "恢复", "回滚", "还原", name], 值=True),
        Option(2, "不恢复", "不恢复，什么都不动", 关键字=STOP_WORDS, 否定优先=True, 值=False),
    ]


def neutralize_options(filename: str, line_no: int | None, whole_file: bool) -> list[Option]:
    target = f"{filename}（整个文件）" if whole_file else f"{filename} 第{line_no}行"
    return [
        Option(1, f"✅ 授权无害化 {target}", f"就地无害化 {target}：清原文、写空值、加只读中文注释；不留备份" if not whole_file
               else f"删除整个文件 {filename}：它本身就是载荷，不留空壳、不留副本",
               关键字=["授权", "无害化", "钉", "清", "删", "删除", "处理", filename], 值="do"),
        Option(2, "不动，只记后果", "不修改、不删除；把“不动的后果”写进报告",
               关键字=STOP_WORDS + ["只记", "记后果", "先不"], 否定优先=True, 值="record_only"),
        Option(3, "先出恢复正常功能的方案", "改动大：先说明要恢复网站哪些正常功能、去掉哪类私加物（不给复现）；看完再决定",
               关键字=["重写", "方案", "另开", "先看", "恢复", "正常功能"], 区分词=["重写", "方案", "另开", "恢复"], 值="rewrite_plan"),
    ]
