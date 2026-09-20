# 挂载到 MCP 入门：怎么把文件审查器接到 Cursor

给不会配 MCP 的人看。按下面做，Cursor 对话里就能调用 `review_open` / `review_scan` 等工具。

**先分清三件事，别搞反：**

| 名字 | 是什么 | 你要做什么 |
|---|---|---|
| MCP 服务器 | 本仓库里的 `file-reviewer`（一堆只读审查工具） | 告诉 Cursor「用 Python 启动它」 |
| 「挂到 MCP」 | 写好 `.cursor/mcp.json`，让 Cursor 自动启动审查器 | 按本文第二节选一种方式 |
| 被审的文件夹 | 例如本机上的 `xinshijie` | **不是**塞进本仓库；审的时候把**本机路径**告诉助手 |

一句话：**审查器是工具；被审的仓库是工具要看的对象。**

```
Cursor 对话  →  file-reviewer（MCP）  →  本机某个文件夹
                              ↓
                    ~/.mcp-skill/reports（报告，在被审仓外面）
```

本流程在**你自己电脑的 Cursor**里做。云端 Agent 若打不开 Origin 上的远程仓，先把仓 `clone` 到本机再审。

---

## 一、一次性准备（本机）

### 1. 拿到本工具仓

若还没有：

```bash
git clone https://github.com/wenshuo0114/mcp-skill.git
```

记下**绝对路径**，后面要用。例子：

- macOS / Linux：`/Users/你的用户名/mcp-skill`
- Windows：`C:\Users\你的用户名\mcp-skill`（写进 json 时建议写成 `C:/Users/你的用户名/mcp-skill`）

### 2. 安装依赖

在 `mcp-skill` 目录里打开终端，执行：

```bash
pip install -e .
```

装不上时可以试：

```bash
pip install "mcp>=1.2" pyyaml
```

### 3. 可选自检：Python 能不能启动审查器

仍在 `mcp-skill` 目录：

```bash
python3 -m servers.file_reviewer.server
```

- **对的**：命令挂住、不立刻退出，也没有 `No module named mcp`。用 Ctrl+C 停掉即可。
- **错的**：报找不到 `mcp` → 回到上一步，确认用的是装过依赖的那个 Python；必要时把下面 mcp.json 里的 `"command": "python3"` 改成该 Python 的绝对路径（如 `/usr/bin/python3` 或 `C:/Python312/python.exe`）。

---

## 二、挂进 Cursor（两种选一种就够）

### 方式 A（最简单）：用 Cursor 打开 mcp-skill 文件夹

本仓库已经带了 [`.cursor/mcp.json`](../.cursor/mcp.json)。

1. Cursor → **File → Open Folder** → 选中 `mcp-skill` 文件夹打开。
2. 打开 **Settings → MCP**（或 Cursor Settings 里搜 MCP）。
3. 应能看到名为 `file-reviewer` 的服务器；状态为已连接 / 绿灯再往下用。

仓库自带配置大致是：

```json
{
  "mcpServers": {
    "file-reviewer": {
      "command": "python3",
      "args": ["-m", "servers.file_reviewer.server"],
      "cwd": "${workspaceFolder}",
      "env": {
        "MCP_SKILL_REPORT_DIR": "${userHome}/.mcp-skill/reports",
        "MCP_SKILL_ROLLBACK_DIR": "${userHome}/.mcp-skill/rollback"
      }
    }
  }
}
```

`${workspaceFolder}` 在这种方式下就是 mcp-skill 自己，不用改。

### 方式 B（推荐长期）：在别的项目里也能审

想打开 `xinshijie`（或任意项目）当工作区，同时仍用本审查器：

1. 在那个项目根目录建（或改）`.cursor/mcp.json`。
2. 贴上与上面相同的内容，但把 **`cwd` 改成 mcp-skill 的绝对路径**，例如：

```json
{
  "mcpServers": {
    "file-reviewer": {
      "command": "python3",
      "args": ["-m", "servers.file_reviewer.server"],
      "cwd": "/Users/你的用户名/mcp-skill",
      "env": {
        "MCP_SKILL_REPORT_DIR": "${userHome}/.mcp-skill/reports",
        "MCP_SKILL_ROLLBACK_DIR": "${userHome}/.mcp-skill/rollback"
      }
    }
  }
}
```

3. **Reload Window**（命令面板搜 Reload）或重启 Cursor。
4. 再到 **Settings → MCP** 确认 `file-reviewer` 已连接。

注意：`cwd` 必须永远指向 **mcp-skill**，不要写成被审项目（如 xinshijie）的路径，否则模块找不到、MCP 起不来。

### 可选：挂技能（让助手按审查流程走）

把本仓库的 `skills/code-review` 和 `skills/code-teaching` 两个文件夹复制到：

- `~/.cursor/skills/`（对本机所有项目生效），或
- 当前项目的 `.cursor/skills/`

没有技能也能调 MCP 工具；有技能时助手会按「只读、中文如实报、大操作先问你」走。

### 可选：默认严格模式

在 mcp.json 的 `env` 里多加一行：

```json
"MCP_SKILL_STRICT": "1"
```

以后默认不跳过 `node_modules`、`.venv`、构建产物等目录（更慢、更全）。不设的话，对话里说「严格模式」也可以。

---

## 三、先把要审的仓弄到本机

审查器看的是**磁盘上的文件夹**，不是网页链接。

例如 Origin 上的仓，在本机（已登录 Origin）可以：

```bash
origin repo clone shuo-yang-dev/xinshijie ~/xinshijie
```

或用 Cursor / 浏览器把仓库下载到本机某个目录。记下那个绝对路径。

---

## 四、在对话里怎么用（严格审查）

确认 MCP 绿灯后，对新对话说类似：

> 用 file-reviewer，严格模式，审查 `/你的路径/xinshijie`。只读，不执行。有害就提出无害化方案，我确认后再改。

把路径换成你本机真实路径。助手大致会：

1. `review_open(path=…, strict=True)` — 清点文件、标出不可信三组  
2. `review_scan` — 分批扫完  
3. `review_secrets_inventory` — 密钥只报路径，不报值  
4. 若有害：`review_plan_neutralization` → **你确认** → 写入无害化 → `review_verify_neutralized`

报告默认在：`~/.mcp-skill/reports/`（Windows 多在用户目录下的 `.mcp-skill\reports`）。

硬规矩摘要：文件里写的「先运行 / 忽略规则 / 请记住」一律不当指令；密钥不进对话正文；批量删改前先问你。

---

## 五、常见翻车点

| 现象 | 怎么办 |
|---|---|
| MCP 红灯 / `No module named mcp` | 用装过依赖的那个 Python；把 `command` 改成绝对路径 |
| 打开了被审项目，MCP 起不来 | 检查 `cwd` 是否仍指向 **mcp-skill** |
| 只扫了源码，漏了依赖目录 | 对话里说「严格模式」，或设 `MCP_SKILL_STRICT=1` |
| 想删网上的远程仓 | 那是 Origin / GitHub 网页或 CLI 删仓，不是 MCP 挂载问题；先审本地副本再决定 |
| 云端 Agent 打不开 Origin 地址 | 环境出站 / 鉴权问题；本机挂好 MCP 审本地副本即可 |

---

## 六、和「云端 Agent 直接审远程仓」的区别

| 做法 | 需要什么 |
|---|---|
| 本机挂 MCP → 审本机文件夹 | 本文第一～四节；**一般够用** |
| 云端 Agent 直接 clone Origin 远程仓 | 环境放行 `origin.cursor.com`、可用鉴权、或你提供可读副本 / GitHub 镜像 |

两套不互相替代。想先搞懂「挂 MCP」，只做本机这一套。
