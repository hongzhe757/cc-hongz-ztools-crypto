# hongz-ztools-crypto

Hongz **密码学工具库**（`jar`），对应 Hutool **`hutool-crypto`**，按需自 `hongz-zthrids/hongz-zthrids-hutool-v5-master/hutool-crypto` 平移/精简。

包名 `cc.hongz.ztools.crypto.*`，依赖 [`hongz-ztools-core`](../hongz-ztools-core/)（对应 `hutool-crypto` → `hutool-core`）。

## 模块关系

| Hutool | Hongz |
|---|---|
| `hutool-core` | `hongz-ztools-core`（codec、IO、工具） |
| `hutool-crypto` | **`hongz-ztools-crypto`**（本模块） |
| `hutool-captcha` | `hongz-ztools-captcha` |

**与 codec 的边界**：Base64/Hex 等表示层编码在 `hongz-ztools-core` 的 `cc.hongz.ztools.core.codec`；ASN.1 DER/BER、证书、密钥、加解密在本模块。

## 当前 API

| 类 | 说明 |
|---|---|
| `ASN1Util` | DER / BER / DL 序列编码、解码、`ASN1Dump` 调试导出 |
| `CryptoException` | 密码学运行时异常 |

依赖 **BouncyCastle** `bcpkix-jdk18on`（版本由根 POM `bouncycastle.version` 管理，与 hutool-crypto 对齐为 1.82）。

## 同步源码

自 `hongz-zthrids/hongz-zthrids-hutool-v5-master/hutool-crypto/.../cn/hutool/crypto` 同步 ASN.1 相关类：

```bash
python scripts/bootstrap-hongz-crypto-asn1.py
mvn -f hongz-ztools/hongz-ztools-crypto/pom.xml clean test
```

## 构建

```bash
mvn -pl hongz-ztools/hongz-ztools-core,hongz-ztools/hongz-ztools-crypto -am clean test
```

或单模块：

```bash
mvn -f hongz-ztools/hongz-ztools-crypto/pom.xml clean test
```

## 变更记录

详见 [CHANGELOG.md](./CHANGELOG.md)。
