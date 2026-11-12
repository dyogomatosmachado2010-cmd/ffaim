# Assinatura — o que o `inject.py` faz hoje

Todo Mach-O dentro de um `.app` precisa de assinatura **válida**, não só presente. O IPA de
origem já vinha com dois problemas, e o inject mudava um terceiro:

| # | problema | onde | correção |
|---|---|---|---|
| 1 | `libac_sdk.dylib` sem `LC_CODE_SIGNATURE` | `Frameworks/` | assinado ad-hoc |
| 2 | `VKSdkFramework` com assinatura **quebrada** (101 de 171 páginas não batem) e `_CodeSignature` velho | `Frameworks/VKSdkFramework.framework/` | reassinado, `_CodeSignature` removida |
| 3 | `libac_sdk.dylib.orig` (backup do ffpatch) dentro do bundle, sem assinatura | `Frameworks/` | removido |
| 4 | binário principal com `LC_CODE_SIGNATURE` zerado (0/0) | `freefireth` | reassinado com entitlements |

O binário principal continua com o patch do AC intacto: `__TEXT.__text` não muda, o CRC
`0x3C1F7529` continua batendo, e a assinatura ocupa o espaço já reservado no fim do arquivo —
o tamanho do `freefireth` não muda (60.430.752 bytes).

## Conferir antes de instalar

```powershell
python tools\verify_ipa.py FreeFire_ffaim.ipa
```

Recalcula o hash de cada página de cada binário do bundle. Precisa terminar com:

```
resultado: OK - pronto pra instalar
```

## Erros de instalação

| mensagem | causa | o que fazer |
|---|---|---|
| `code signature invalid` / `assinatura inválida` | binário do bundle sem assinatura válida | `python tools\verify_ipa.py` mostra qual |
| `Failed to sign` / erro de certificado | certificado do Esign/Scarlet vencido ou revogado | trocar certificado no app |
| instala e fecha em 1 s | dylib não carregou | `idevicesyslog \| findstr ffaim` |
| `missing the application-identifier entitlement` | entitlements não casam com o bundle id | `python tools\inject.py ... --no-entitlements` |

Se nada resolver, o caminho que não depende de certificado nenhum é o **TrollStore**
(iOS 14.0–16.6.1 / 17.0): ele assina tudo na instalação, inclusive os dylibs aninhados.

## Como a assinatura ad-hoc funciona

`tools/ldid.py` escreve, sem depender de `ldid` nem de toolchain:

- `LC_CODE_SIGNATURE` (cria se não existir, reaproveita o espaço se existir);
- `CodeDirectory` v0x20400, SHA-256, páginas de 4096, flag `CS_ADHOC`;
- `SuperBlob` com CodeDirectory + Requirements (+ Entitlements);
- estende `__LINKEDIT` quando o blob não cabe.

A última página é hasheada **truncada no `codeLimit`** — igual ao `codesign` da Apple. Hash da
página inteira passa em alguns validadores e falha no kernel.
