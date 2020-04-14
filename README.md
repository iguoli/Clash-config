# 个人定制 Clash 规则及分组

**版权所有，本文档内容均为手工整理，转载必须说明来源。**

## Clash/Surge 配置说明

Clash 的配置类似于 [Surge][surge]，相关配置语法可以参考 [Surge手册][surge_manual]。

### [规则][surge_rule]

#### 优先级

规则的匹配是按照在 Surge 配置文件中出现的顺序从上往下依次匹配，即规则列表中越靠上的规则优先级越高。

#### 规则的组成

每个规则包含3部分：**规则类型**，**匹配内容**和**代理策略** (TYPE，VALUE，POLICY)

Surge 支持以下规则类型 (完整规则类型请参考 Surge手册)：

- Domain-based Rule
  - DOMAIN
  - DOMAIN-SUFFIX
  - DOMAIN-KEYWORD
- IP-based Rule
  - IP-CIDR
  - IP-CIDR6
  - GEOIP
  - IP-based Rule Option: no-resolve
- HTTP Rule
  - USER-AGENT
  - URL-REGEX
- Process Rule
  - PROCESS-NAME
- Ruleset
- Final Rule

规则示例:

```ini
[Rule]
DOMAIN-SUFFIX,company.com,ProxyA
DOMAIN-KEYWORD,google,DIRECT
GEOIP,US,DIRECT
IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
PROCESS-NAME,Telegram,ProxyB
FINAL,ProxyC
```

### [代理策略][surge_policy]

Surge 包含3种类型的代理策略: **代理**，**策略组**和**内置策略**。Surge 有两个内置策略: **DIRECT** 和 **REJECT**，这两个内置策略可以在规则和策略组中直接使用。

## subconverter 使用说明

- 订阅转换及配置基于 [subconverter][subconverter]

- [subconverter][subconverter] 中用到的URL编码工具 [urlencoder][urlencoder]

- 常见规则请参考 [ACL4SSR][ACL4SSR] 的[帮助文档][rule_help]。

### `subconverter` 配置文件

- `subconverter` 通过配置文件 `pref.ini` 来转换订阅，生成 Clash/Surge/Quantumult(X) 的配置文件。

- `subconverter` 通过 URL 中的 `config` 参数读取自定义配置文件 (`custom_configs/clash.ini`)，自定义配置文件中的选项会覆盖 `pref.ini` 中的配置选项。

#### `pref.ini` 配置文件

- `pref.ini` 中的各部分选项说明见[配置文件说明][pref]。
- 部分选项说明
  
```ini
[common]
; 排除匹配到的节点，支持正则匹配
exclude_remarks=(英国|法国)

; 仅保留匹配到的节点，支持正则匹配
include_remarks=(?i:vip2|vip3)

; 生成不同代理软件配置的基础配置文件
; Clash 基础配置文件
clash_rule_base=clash.yaml

; Surge 基础配置文件
surge_rule_base=surge.conf

; Quantumult 基础配置文件
quan_rule_base=quantumult.conf

; Quantumult X 基础配置文件
quanx_rule_base=quantumultx.conf

[node_pref]
; 重命名节点，支持正则匹配
; Format: Pattern@Replacement
rename_node=IPLC@专线
rename_node=BGP@隧道中转

[emojis]
; 是否在节点名称前加入下面自定义的 Emoji，设置为 true 时打开，默认为 true
add_emoji=true

; 是否移除原有订阅中存在的 Emoji，设置为 true 时打开，默认为 true
remove_old_emoji=true

; 在匹配到的节点前添加自定义 Emojis，支持正则匹配
; Format: Pattern,Emoji
rule=(美国|US|United States),🇺🇸
rule=(日本|JP|Japan),🇯🇵

[ruleset]
; 启用自定义规则集的总开关，设置为 true 时打开，默认为 true
enabled=true

; 覆盖原有规则，即 [common] 中 xxx_rule_base 中的内容，设置为 true 时打开，默认为 false
overwrite_original_rules=false

; 规则片段，将 rule 关联到 custom_proxy_group 来进行分流
; Format: proxy_policy,local_file
;         proxy_policy,URL
;         proxy_policy,[]Rule
; [] 前缀后的文字将被当作规则，而不是链接或路径，主要包含 []GEOIP 和 []FINAL
surge_ruleset=DIRECT,rules/direct/misc.list
surge_ruleset=REJECT,https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanAD.list
surge_ruleset=Proxy,rules/proxy/github.list
surge_ruleset=DIRECT,[]GEOIP,CN
surge_ruleset=NotMatch,[]FINAL

[clash_proxy_group]
; 为 Clash, Quantumult, Quantumult X 以及 Surge 等程序创建策略组, 可用正则来筛选节点
; Format: policy_group_name`select`Pattern`[]policy_group_name`[]build_in_policy`...
;         policy_group_name`url-test|fallback|load-balance`Pattern`[]policy_group_name`[]build_in_policy`...`test_url`interval
; [] 前缀后的文字将被当作引用策略组
custom_proxy_group=Auto`url-test`.*`http://www.gstatic.com/generate_204`300
custom_proxy_group=FallBack`fallback`(?:香港|日本)`http://www.gstatic.com/generate_204`300
custom_proxy_group=LoadBalance`load-balance`^(?:(?!流量|时间|产品).)*$`http://www.gstatic.com/generate_204`300
custom_proxy_group=Proxy`select`[]AUTO`[]DIRECT`.*
custom_proxy_group=NotMatch`select`[]AUTO`[]DIRECT`.*

[server]
; subconverter 绑定到 Web 服务器的地址，将地址设为 0.0.0.0，则局域网内设备均可使用
listen=0.0.0.0

; subconverter 绑定到 Web 服务器地址的端口，默认为 25500
port=25500
```

#### `custom_configs/clash.ini` 自定义配置文件

```ini
[custom]

; 自定义规则，会覆盖 pref.ini 里的内容
enable_rule_generator=true
overwrite_original_rules=true
surge_ruleset=DIRECT,https://raw.githubusercontent.com/ConnersHua/Profiles/master/Surge/Ruleset/Unbreak.list

; 自定义策略组，会覆盖 pref.ini 里的内容
custom_proxy_group=Proxy`select`.*`[]AUTO`[]DIRECT`.*

; 自定义基础配置文件，会覆盖 pref.ini 里的内容
clash_rule_base=clash.yaml
;surge_rule_base=surge.conf
;surfboard_rule_base=surfboard.conf
;mellow_rule_base=mellow.conf
;quan_rule_base=quan.conf
;quanx_rule_base=quanx.conf

; 自定义节点重命名，会覆盖 pref.ini 里的内容
rename=Test-(.*?)-(.*?)-(.*?)\((.*?)\)@\1\4x测试线路_自\2到\3

; 自定义 Emoji，会覆盖 pref.ini 里的内容
emoji=阿根廷,🇦🇷

; 自定义包含或排除节点关键词，会覆盖 pref.ini 里的内容
include_remarks=vip3
exclude_remarks=(?i:test|测试)

```

### 命令行

```zsh
# 启动 subconverter
./subconverter

# 获取 ClashR 配置
curl http://localhost:25500/sub?target=clashr&url=<encoded-subscription-url>&config=custom_config.ini
```

将 `<encoded-subscription-url>` 部分替换为编码后的订阅链接。

[clash]: https://github.com/Dreamacro/clash
[clashx]: https://github.com/yichengchen/clashX
[clashxr]: https://github.com/WhoJave/clashX/releases
[surge]: https://nssurge.com/
[surge_manual]: https://manual.nssurge.com/
[surge_rule]: https://manual.nssurge.com/rule.html
[surge_policy]: https://manual.nssurge.com/policy.html
[subconverter]: https://github.com/tindy2013/subconverter
[urlencoder]: https://www.urlencoder.org/
[ACL4SSR]: https://github.com/ACL4SSR/ACL4SSR
[rule_help]: https://github.com/ACL4SSR/ACL4SSR/blob/master/Help.md
[pref]: https://github.com/tindy2013/subconverter/blob/master/README-cn.md#配置文件