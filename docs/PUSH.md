# 推送到 GitHub

代码已经在本地提交好了（`e6b2a35`），只差认证这一步。下面的操作 2 分钟能做完。

> 为什么不能由我代劳：本机没有任何 GitHub 凭据（没有 SSH key、没有 gh CLI、没有存储的令牌）。
> 推送需要以**你的账号**登录，这个动作只能由你完成；令牌也不应该出现在对话里。

---

## 方式一：脚本（推荐）

在 `C:\Users\16621\Desktop\github` 目录打开 PowerShell：

```powershell
.\push.ps1
```

脚本会依次做：

1. 配置 remote `origin`
2. `git fetch` 读取远端（**首次会弹浏览器让你登录 GitHub**，或提示输入令牌）
3. 给远端的旧版本打一个 `v0.1-legacy` 标签（旧代码不会丢）
4. 把新代码推到 `refactor/v0.2` 分支
5. 打印一个 PR 链接

然后在浏览器打开脚本最后给的链接 → 点 **Create pull request** → 看完 diff 点 **Merge**。

### 想直接覆盖 main

```powershell
.\push.ps1 -Mode replace
```

跳过 PR，直接 `--force-with-lease` 覆盖 `main`。旧代码在 `v0.1-legacy` 标签里，随时能翻出来对比。

---

## 方式二：手动命令

```powershell
cd C:\Users\16621\Desktop\github\AlertSage

git remote add origin https://github.com/zihan5754-arch/AlertSage.git
git fetch origin

# 旧版本留档（很建议做，之后能对比"重构前 vs 重构后"）
git tag -a v0.1-legacy origin/main -m "v0.1 原始版本"
git push origin v0.1-legacy

# 路线 A：推分支 + 开 PR（推荐）
git push -u origin main:refactor/v0.2
# 然后打开 https://github.com/zihan5754-arch/AlertSage/compare/main...refactor/v0.2

# 路线 B：直接覆盖 main
git push --force-with-lease origin main
```

---

## 认证说明

### 如果弹出浏览器

说明装了 Git Credential Manager，登录一次即可，凭据会存到 Windows 凭据管理器，之后不用再登。

### 如果提示输入用户名 / 密码

GitHub 从 2021 年起**不接受账号密码**，密码位置必须填 **Personal Access Token**：

1. 打开 https://github.com/settings/tokens
2. **Fine-grained tokens** → Generate new token
3. Repository access 选 **Only select repositories** → `AlertSage`
4. Permissions → **Contents: Read and write**（必须）；想让它能改仓库设置再加 `Administration`、`Metadata`
5. 有效期选 7 天
6. 生成后复制（`github_pat_...`），粘贴到 "Password:" 提示处
7. 用完可以在同一页面 **Revoke**

> 不建议用 Classic token 的 `repo` 全权限，范围太大。

---

## 推送之后的检查清单

- [ ] 仓库首页能看到新的 README（有架构图、评估表格）
- [ ] **Actions 标签页**：CI 是否全绿（首次约 1~2 分钟，3 个 Python 版本 + lint + 评估）
- [ ] CI 绿了之后，README 顶部的 build 徽章才会正常显示
- [ ] 仓库设置里改 Description：`面向蓝队的可解释告警研判引擎｜规则 + 行为基线 + 可选 LLM｜94% 准确率 / 132 测试`
- [ ] 加 Topics：`security` `soc` `blue-team` `alert-triage` `mitre-attack` `python` `llm`
- [ ] 个人主页把 AlertSage **Pin** 上去（Profile → Customize your pins）
- [ ] 打开 `docs/sample-report.html` 截一张图，放到 README 顶部（这一步对观感的提升最大）
- [ ] 旧版本对比：`https://github.com/zihan5754-arch/AlertSage/tree/v0.1-legacy`

---

## 如果推错了怎么回退

```powershell
# 看历史
git log --oneline --all

# 退回旧版本（本地）
git reset --hard v0.1-legacy

# 让远端也退回
git push --force-with-lease origin main
```
