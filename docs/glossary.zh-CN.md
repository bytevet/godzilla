# 中文术语表

`README.md` 是事实来源，[`docs/README.zh-CN.md`](README.zh-CN.md) 是它逐节对应的中文镜像。
两者必须在同一次提交里改动 —— 这条约定见 `CLAUDE.md`。

这份表解决的是另一个问题：**同一个英文术语在不同段落被译成了不同的词**。文档是分批写的，
每次新增一节都重新想一遍译法，漂移就这样积累起来。表里只收**已经出现在文档中、且译法需要
固定**的词，不做通用词典；新增章节时先查这里，不要另起译法。

## 编译与中间表示

| English | 中文 | 说明 |
|---|---|---|
| lowering / lower | **下降** | 采用 MLIR/LLVM 中文社区惯例。**必须写成及物结构**：「将 Go 源码下降为 gIR」「前端把依赖的函数体一并下降」，不能写「下降依赖的函数体」—— 「下降」本身是不及物动词，直接带宾语读不通。首次出现附英文。 |
| intermediate representation (IR) | 中间表示 | gIR 首次出现时写「语言无关的 SSA 中间表示 gIR」。 |
| frontend | 前端 | 指 `converters/*`，不是 Web 前端；歧义处写「语言前端」。 |
| export data | 导出数据 | Go 的 export data，编译期类型信息。 |
| bodyless / signature-only | 只保留签名 | 描述「只有声明、没有函数体」的包。 |

不要用「降级」翻译 lowering。这个词已经被下面的覆盖率状态占用了。

## 分析与污点

| English | 中文 | 说明 |
|---|---|---|
| taint | 污点 | |
| source | 污点源 | 首次出现附英文 source。 |
| sink | 汇点 | 数据流分析的既有译法（源点—汇点）。 |
| sanitizer | 净化函数 | |
| propagator | 传播函数 | 目前正文里还是英文，应汉化。 |
| validator | 校验函数 | 指 `validators:` 声明的应用层判定函数。 |
| interprocedural | 跨过程 | 不用「过程间」，保持与「过程内」对称。 |
| context-insensitive | 上下文不敏感 | |
| call graph | 调用图 | |
| pointer analysis | 指针分析 | |
| points-to analysis | 指向分析 | **必须与上一条区分**：正文「采用近似方案而非完整的指向分析」这句话依赖这个区别。 |
| dependency closure | 依赖闭包 | |
| receiver | 接收者 | 方法调用的接收者。 |

## 结果与门禁

| English | 中文 | 说明 |
|---|---|---|
| finding | 检出项 | 不用「发现」「结果」。 |
| confidence | 置信度 | High / Medium 保留英文，与输出一致。 |
| coverage | 覆盖率 | |
| **degraded**（覆盖率状态） | **降级** | **专用**于 `coverage: go=DEGRADED`：前端跑完了，但依赖闭包被内存预算裁剪过。此外一律不得使用「降级」。 |
| degrade gracefully（工具链缺失） | 跳过该语言，并在覆盖率中标出 | 刻意**不**译成「降级」。它和上一条是两件事：这里是整门语言没被分析，上一条是分析了但深度打了折。撞词会让读者以为 `-strict` 的行为也一样，而实际相反。 |
| false positive / false negative | 误报 / 漏报 | |
| true positive | 真实检出 | 不用「真阳性」，医学味过重。 |
| gate | 门禁 | CI 门禁。 |
| corpus | 语料库 | 指 `test/corpus`。 |
| canonical name | 规范名 | |
| logical argument index | 逻辑参数下标 | 规则里 `#<n>` 指定的那个下标。 |

## 漏洞类别

沿用中文安全社区的通行叫法，不自造：

| English | 中文 |
|---|---|
| SQL injection / command injection / code injection | SQL 注入 / 命令注入 / 代码注入 |
| path traversal | 路径穿越 |
| open redirect | 开放重定向 |
| SSRF | SSRF（不译） |
| XSS | XSS（不译）；需要展开时写「跨站脚本」 |
| insecure deserialization | 不安全的反序列化 |
| server-side template injection | 服务端模板注入 |
| hardcoded secrets | 硬编码凭据 |
| weak crypto | 弱加密 |

## 其他

| English | 中文 | 说明 |
|---|---|---|
| off-by-one | 差一（off-by-one） | 附英文；单说「差一错误」容易被读成「有个 bug」。 |
| single-file component (SFC) | 单文件组件 | Vue / Svelte。 |
| bytecode | 字节码 | |

## 排版约定

- 中英混排时，英文、数字与中文之间留一个空格：`需要 Go 1.26.5+`。
- 行内代码、命令、路径、flag 一律保持英文原样，不翻译也不加空格规则之外的修饰。
- 链接要**改写**而不是照抄：仓库根目录的文件需要 `../` 前缀（`../LICENSE`、`../ARCHITECTURE.md`），
  `docs/` 下的同级文件不带前缀（`writing-rules.md`），锚点指向**译后**的标题。
