# 变更日志

## 2026-06-19

- 迁入 `hongz-ztools/hongz-ztools-crypto/`；artifactId 重命名为 `hongz-ztools-crypto`（原 `hongz-crypto`）；依赖改为 `hongz-ztools-core`

## 2026-06-18

- 新建 `hongz-crypto` 子模块（对应 Hutool `hutool-crypto`），在 `hongz-parent` 注册于 `hongz-core` 之后
- 自 Hutool `hutool-crypto` 迁入 `ASN1Util`、`CryptoException` 至 `cc.hongz.ztools.crypto`；同步脚本 `scripts/bootstrap-hongz-crypto-asn1.py`
- 依赖 `hongz-core` 与 BouncyCastle `bcpkix-jdk18on`；新增 `ASN1UtilTest`、`CryptoExceptionTest`
