# available-routing-rules

校验过的路由规则文件，供 App 下载使用。

每天自动从上游取规则文件，全部校验通过才发布到本仓库的 Release；任何一项不通过就不发布，App 继续用上一个版本。

| 文件 | 上游 |
|---|---|
| `dlc.dat` | [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) |
| `geoip-only-cn-private.dat` | [v2fly/geoip](https://github.com/v2fly/geoip) |

下载地址（始终指向最新一次发布）：

```
https://github.com/soysuuu-png/available-routing-rules/releases/latest/download/dlc.dat
https://github.com/soysuuu-png/available-routing-rules/releases/latest/download/geoip-only-cn-private.dat
```

## 校验内容

脚本是 `scripts/sync.py`，定时任务是 `.github/workflows/sync.yml`。

1. 核对上游提供的 sha256 校验和。
2. 文件能解析，App 用到的分类（`geoip:cn`、`geoip:private`、`geosite:cn`、`geosite:google`、`geosite:private`）都在，条数在合理范围。
3. 抽查固定的 IP 和域名：国内的必须在国内列表里，国外的必须不在。
4. 用 Xray 实际加载一遍。

上游一发布就同步。想改成只取发布满一段时间的版本，可以设置环境变量 `MIN_AGE_HOURS`（单位小时）。

## 校验不通过怎么办

定时任务会失败，GitHub 会发邮件通知。在 Actions 页面打开失败的那次运行，日志最后一行写着是哪一项没通过。

- 上游确实有问题：不用管，等上游修好后自动恢复。
- 抽查的地址过时了：改 `scripts/sync.py` 开头的列表。

## 紧急停更或回滚

- 停更：在 Actions 页面停用这个工作流。
- 回滚：删除有问题的那个 Release，上一个 Release 会重新成为最新版。
