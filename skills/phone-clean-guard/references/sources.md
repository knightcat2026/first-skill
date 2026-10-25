# 官方依据

查证日期：2026-10-25。以下链接支持处理原则和界面定位；厂商页面会更新，实际设备及当前官方文档优先。不将官方某机型的说明泛化为全部机型，也不复制社区精简包清单。

## Android

- [Android Debug Bridge](https://developer.android.com/tools/adb)：ADB 连接、设备选择和包管理。`uninstall -k` 的含义是保留数据与缓存目录，不是私有数据备份或完整恢复保证；`clear` 会删除应用数据，本 Skill 不使用。
- [SDK Platform-Tools](https://developer.android.com/tools/releases/platform-tools)：ADB 官方发行来源。工具应单独获取，不把个人电脑上的二进制或整个 SDK 打包进公开项目。
- [Android 8.0 行为变化](https://developer.android.com/about/versions/oreo/android-8.0-changes)：未知来源安装改为按来源授权；旧 `INSTALL_NON_MARKET_APPS` 值不适合判断实际安装权限。
- [UserManager：安装限制](https://developer.android.com/reference/android/os/UserManager#DISALLOW_INSTALL_UNKNOWN_SOURCES)：未知来源限制与全面禁止安装是不同策略；前者不覆盖所有可信商店和 ADB。不能把其中一项称为所有误装均已杜绝。

## 华为／HarmonyOS

- [USB 调试开关问题及版本路径](https://consumer.huawei.com/cn/support/content/zh-cn00407281/)：区分 HarmonyOS 4.x 及以下的 ADB 设置与 5+ 的开发者选项流程。需要按设备版本连接，不能将“USB 调试”一词等同于 ADB。
- [手机助手连接排查](https://consumer.huawei.com/cn/support/content/zh-cn00698619/)：HarmonyOS 5／6 连接说明涉及 HDC 端口和 `hdc.exe`，用于支持原生鸿蒙与旧版分流。
- [HDC 工具文档](https://developer.huawei.com/consumer/cn/doc/harmonyos-guides-V13/hdc-V13)：原生鸿蒙的设备调试工具和命令语义。工具文档不代表零售手机上的修改权限，也不为 Android 命令提供兼容保证。
- [应用市场新旧功能对照](https://consumer.huawei.com/cn/support/content/zh-cn16010279/)：HarmonyOS 5+ 的应用市场、服务模式与旧系统不同，旧快应用管理等入口已变动或下线。
- [负一屏个性化广告与推荐说明](https://consumer.huawei.com/cn/support/content/zh-cn00766239/)：关闭个性化广告会降低相关性，不等于关闭全部广告；推荐与广告开关须分别理解。
- [热门／精品推荐文件夹处理](https://consumer.huawei.com/cn/support/content/zh-cn15856798/)：云推荐图标与已安装内容不同；关闭个性化不等于移除推荐入口。移除操作也可能包含卸载已有应用，需区分。
- [小艺建议 FAQ](https://consumer.huawei.com/cn/support/content/zh-cn15965298/)：桌面建议、卡片及其移除方式的版本相关说明，作为界面审查参考。
- [外部来源应用安装权限](https://consumer.huawei.com/cn/support/content/zh-cn00766399/)：文件管理等来源拥有各自的允许安装开关，用于解释有针对性的防误装设置。

## 其它厂商

- [荣耀搜索说明](https://www.honor.com/cn/support/content/zh-cn15836518/)：搜索内模块、智能推荐、桌面搜索入口与下滑动作可分别设置，操作路径随新旧系统变化。
- [小米隐私 FAQ](https://privacy.mi.com/support/faq?locale=en)：HyperOS 与 MIUI 的个性化广告控制位置不同，各应用另有自己的控制入口。
- [小米 14T 个性化广告说明](https://www.mi.com/global/support/faq/details/KA-507647/)：关闭个性化后，系统应用广告数量仍可能相同。此例不作为所有小米机型固定菜单。
- [小米浏览器隐私说明](https://privacy.mi.com/mibrowser/en_US)：浏览器推荐与广告控制受应用版本影响，关闭后仍可能有非个性化内容。
- [三星 Auto Blocker](https://www.samsung.com/us/support/answer/ANS10003636/)：阻止未授权来源应用等额外保护的作用与限制；不是单纯去广告功能。

本项目不以“关闭个性化”推导“零广告”，不以“包已停用”推导“所有跳转已阻断”。真实效果需要逐个界面核验；没有验证的系统或入口必须明示。
