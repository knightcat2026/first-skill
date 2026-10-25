# ADB 辅助工具

Python 3.10+ 标准库。ADB 使用官方 Platform Tools，电脑可为 Windows、macOS 或 Linux；本版只在 Windows 运行过测试，三种平台均使用参数数组而非 shell 拼接。不会下载工具、安装驱动、读取用户文件、上传数据、获取 root 或设置禁装策略。

## 审计与计划

先按 platforms.md 人工确认主系统，不把原生鸿蒙的 Android 容器当作主系统。连接唯一一台 USB 手机，确认机主授权。必须前台用户 0；工作资料、多用户或受管理设备不能自动修改。管理状态检查是保守提示，不替代在手机设置中确认。

以下命令假设位于项目根目录；会话目录放在仓库外，新建目录、不覆盖旧记录。`--adb` 可传含空格的官方工具完整路径。

```bash
python skills/phone-clean-guard/scripts/phone_guard.py audit --adb adb --out ../phone-guard-private/session-001
```

只读采集：品牌/型号/系统构建、当前用户数量、管理状态提示、包名、当前桌面/输入法/无障碍及通知读取服务的包名，以及匹配档案候选的启用状态。不会保存完整系统设置、设备策略原文、USB 序列号或任何文件内容；用于绑定的本地加盐摘要也属于私密会话记录。清单可能反映使用习惯，不可公开。

若 ADB 不存在、未授权、离线、多设备、无法确认 USB、缺少关键字段、SDK 不兼容，则停止。Windows 的设备清单可能没有 `usb:` 字段，因此另外通过 `adb -d get-serialno` 核对物理 USB 设备，不改用网络连接。

审查 `audit.json` 和当前界面。没有满足全部匹配字段的档案时照样得到只读结果，但自动计划被拒绝，改用 UI 路线。不要为了通过匹配而编辑设备报告或删去档案条件。初始档案只验证了公开的型号、Android/API、鸿蒙版本、显示构建号等历史字段，没有历史完整 fingerprint；当前完整指纹只绑定本次会话后续操作。须审查计划的 `profile_match` 和 `profile_evidence`，不能将字段相符当作新固件已真机验证。

仅选用途明确的独立推荐组件，逐个列明 `--package`；没有“全部禁用”参数。现有用户应用、浏览器、商店、快应用整套引擎和更新组件不作为净化停用对象。下面只是命令格式，必须替换成自己的审计中存在且已核对用途的候选包与真实检查结论：

```bash
python skills/phone-clean-guard/scripts/phone_guard.py plan --session ../phone-guard-private/session-001 --package com.huawei.recsys --reason "机主希望关闭系统推荐" --context-review "已在手机确认主系统为Android兼容环境；无工作资料或设备管理；记录具体界面证据位置"
```

计划不修改手机。查看 `plan.json` 的包、作用、功能影响和原状态，向用户说明并在已有授权范围内执行。`digest` 冻结了这份计划内容；它不是密码、数字签名或用户同意的证明，操作 AI 仍须检查真实授权。

## 执行、核验、恢复

把下面的 `REVIEWED_DIGEST` 替换为已经审查的 `plan.json` 中的 `digest`；未替换会拒绝执行：

```bash
python skills/phone-clean-guard/scripts/phone_guard.py apply --adb adb --session ../phone-guard-private/session-001 --approved-plan REVIEWED_DIGEST
python skills/phone-clean-guard/scripts/phone_guard.py verify --adb adb --session ../phone-guard-private/session-001
```

执行前要求审计不超过 24 小时，重新确认设备与固件、用户和管理状态、当前保护对象，以及所有目标的状态。实际唯一修改命令为 `pm disable-user --user 0 PACKAGE`，限已选择的独立推荐组件。保留代码与应用数据；该组件功能将暂时不可用。不会卸载已安装应用、删除保存的 APK 文件或改写更新设置。每一步修改前原子写入 `journal.json`，随后回读 `enabled=3`；系统拒绝、断连或结果不符就停止。

`verify` 验证所选组件状态，并将当前已安装包名与审计基线对比。`installed_packages_preserved=false` 或 `missing_packages` 非空会使命令退出 2；缺失不等于已证明原因，不自动重装。新增应用不作丢失处理，也不会自动删除。必须再按 ui-playbook.md 核验入口、更新页面与核心功能，不能从包状态推导零广告、资料内容无变化或已通过重启测试。

需要恢复时，连接同一手机与同一固件，检查日志与计划，再运行：

```bash
python skills/phone-clean-guard/scripts/phone_guard.py restore --adb adb --session ../phone-guard-private/session-001 --approved-plan REVIEWED_DIGEST
```

仅恢复本会话已尝试修改的条目，原状态为 0 时用 `pm default-state`，原状态为 1 时用 `pm enable`，均限定用户 0 并回读。不把所有包简单启用，不自动恢复后来由其它操作改变的状态。`stage=restored` 只表示本会话尝试项已恢复；尚未执行的条目若被外部改变不会被回滚，`verify` 会另行报出不匹配。恢复 UI 开关则按单独保存的原值和路径操作。

## 中断及冲突

- 保留整套会话文件，不编辑 JSON、不再运行 `apply`。对日志里的 `intent` 或 `uncertain` 先查询真实状态，`restore` 可在状态可解释时恢复。
- 状态被其它工具修改、包缺失、当前目标变成保护对象、手机或固件变化：停止自动恢复，结合原记录在正常界面检查；不重装、不清数据、不降级。
- 每个会话有独占锁，防止两次操作互相覆盖。异常终止可能留下 `.operation.lock`。确认对应进程确已退出、查看 journal 后，由使用者处理这个锁文件，再执行核验或恢复；不能无条件自动清锁重试。
- 开关日志和 APK 都不能代替照片、聊天等完整备份。恢复出厂、卸载软件、刷机和重新授权数据不属于本工具的故障处理方法。

## 更新后复查

保留系统、安全补丁及应用的正常更新功能和原有偏好。系统或应用升级可能重置入口；再次运行须新建审计目录、重新识别版本和匹配条件，只处理确实重新开启的项。不能重新运行旧 `apply` 或用旧档案强行匹配新固件；没有新版本档案时走正常界面。旧日志仅作参考，固件变更后自动恢复仍会被拒绝，避免覆盖更新后的配置。

退出码 0 表示该命令自己的有限检查完成；2 表示拒绝、错误、所选状态不符或基线安装包缺失。`verify` 的输出会明确其只检查包状态和基线安装存在性。
