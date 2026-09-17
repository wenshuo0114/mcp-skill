"""确认词：编号 / 原话 / 关键字模糊命中；对上多个就缩小再问；否定词一律停。"""
from __future__ import annotations

import pytest

from servers.file_reviewer import confirm as cf


@pytest.mark.parametrize("reply,expect", [
    ("这台机器是我的，我有权限，给予", 1),   # 用户真实输入：打错字
    ("1 是我的", 1), ("1", 1), ("选1", 1), ("继续", 1), ("✅ 这台机器是我的，我有权限，继续", 1),
    ("不是我的", 2), ("是公司的", 2), ("不确定", 2), ("先别", 2), ("2", 2),
])
def test_owner_gate(reply, expect):
    m = cf.match(reply, cf.owner_options())
    assert m.命中 and m.命中.编号 == expect, m.说明


def test_owner_gate_no_match_lists_all():
    m = cf.match("嗯", cf.owner_options())
    assert m.命中 is None and [o.编号 for o in m.需要再选] == [1, 2]


def test_disk_gate_ambiguous_narrows_then_hits():
    opts = cf.disk_options()
    amb = cf.match("授权扫整盘", opts)
    assert amb.命中 is None and [o.编号 for o in amb.需要再选] == [1, 2]
    body = cf.ask(opts, amb, "x")
    assert "缩小" in body["标题"] and [o["编号"] for o in body["选项"]] == [1, 2]
    assert cf.match("2", opts).命中.值 is True
    assert cf.match("扫整盘含其他用户", opts).命中.编号 == 2
    assert cf.match("不含别人的", opts).命中.编号 == 1
    assert cf.match("别扫了", opts).命中.编号 == 3


def test_negation_wins_even_with_positive_words():
    m = cf.match("不是我的，但我有权限，继续", cf.owner_options())
    assert m.命中.编号 == 2, "有否定词就停，安全优先"


def test_credential_and_restore_and_neutralize_options():
    assert cf.match("读吧", cf.credential_options(".env")).命中.值 is True
    assert cf.match("不读", cf.credential_options(".env")).命中.值 is False
    assert cf.match("恢复", cf.restore_options("p1")).命中.值 is True
    assert cf.match("不恢复", cf.restore_options("p1")).命中.值 is False
    n = cf.neutralize_options("app.py", 7, False)
    assert cf.match("钉", n).命中.值 == "do"
    assert cf.match("先不动", n).命中.值 == "record_only"
    assert cf.match("先出重写方案", n).命中.值 == "rewrite_plan"
    assert cf.match("3", n).命中.值 == "rewrite_plan"
    w = cf.neutralize_options("evil.pth", None, True)
    assert "整个文件" in w[0].键 and "不留空壳" in w[0].说明


def test_normalize_fullwidth_and_punct():
    assert cf.normalize("✅ 这台机器是我的，我有权限，继续！") == cf.normalize("这台机器是我的我有权限继续")
    assert cf.normalize("１") == "1"
