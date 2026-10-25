# PHP2Shell Mitigation Script (CVE-2026-109618 / CVE-2026-109619)

**Developed by [ArmHack-Team](https://github.com/armhackteam)** 🇦🇲

Emergency mitigation tool designed by **ArmHack-Team** to neutralize critical RCE vectors on servers running PHP 7.4, PHP 8.1, and legacy unpatched PHP environments without requiring immediate application code changes.

---

> [!IMPORTANT]
> **Աշխատացնելուց առաջ անպայման բექափ (Backup) արեք! / Перед запуском обязательно сделайте резервную копию (Backup)! / Always Backup Before Running!**
>
> * **HY:** Թեև սկրիպտն ավտոմատ բեկափ է անում փոփոխվող ֆայլերը (`*.bak_php2shell`) և ստուգում է կոնֆիգները սերվիսները ռեստարտ անելուց առաջ, **խստորեն խորհուրդ ենք տալիս production սերվերի վրա `--apply` անելուց առաջ ձեռքով անել սերվերի կոնֆիգների լրիվ բექափ (`/etc/php*`, `/etc/nginx*`, `/etc/httpd*`) կամ VM-ի snapshot**։
> * **RU:** Несмотря на то, что скрипт автоматически создаёт резервные копии изменяемых файлов (`*.bak_php2shell`) и проверяет конфигурацию перед перезапуском служб, **настоятельно рекомендуется сделать полный ручной бэкап конфигураций вашего сервера (`/etc/php*`, `/etc/nginx*`, `/etc/httpd*`) или снапшот ВМ перед запуском `--apply` на продакшене**.
> * **EN:** Although this script automatically creates idempotent backups (`*.bak_php2shell`) and validates service configurations before reloading, **we strongly recommend creating a manual backup of your server configuration directories (`/etc/php*`, `/etc/nginx*`, `/etc/httpd*`) or a VM snapshot prior to running `--apply` in production**.

> [!WARNING]
> **Համատեղելիության մասին / Ограничения совместимости / Compatibility Disclaimer**
>
> * **HY:** **ArmHack-Team**-ը հաշվի է առել ամենատարածված սերվերային տարբերակներն ու դիստրիբուտիվները, բայց **անհնար է հաշվի առնել PHP-ի բոլոր հնարավոր կաստոմ (custom) տարբերակները, ոչ ստանդարտ ճանապարհներն (paths) ու կոնֆիգները**։ Որոշ ոչ ստանդարտ սերվերների վրա սկրիպտը կարող է մինչև վերջ չաշխատել կամ ձեռքով կարգավորման կարիք ունենալ (օրինակ՝ `PHP2SHELL_SEARCH_ROOTS`-ի միջոցով)։ Փոփոխությունները կիրառելուց հետո անպայման ստուգեք ձեր սերվիսների աշխատանքը։
> * **RU:** Команда **ArmHack-Team** учла большинство стандартных серверных окружений и дистрибутивов, однако **учесть абсолютно все кастомные сборки, нестандартные пути и специфические конфигурации PHP невозможно**. В некоторых нестандартных окружениях скрипт может сработать не полностью или потребовать ручной настройки (например, через переменную окружения `PHP2SHELL_SEARCH_ROOTS`). Обязательно проверяйте работу ваших сервисов после применения изменений.
> * **EN:** While **ArmHack-Team** has engineered this tool to support the vast majority of standard PHP environments, **it is impossible to account for every custom PHP build, non-standard directory layout, or third-party control panel**. On highly customized systems, manual verification or specifying `PHP2SHELL_SEARCH_ROOTS` may be required.

---

## What It Does

1. **Disables `session.upload_progress.enabled`**: Prevents unauthenticated session upload progress manipulation across `php.ini`, drop-in `conf.d`/`php.d` files, `[HOST=...]`/`[PATH=...]` sections, and PHP-FPM pool overrides.
2. **Configures Safe PHP-FPM Worker Recycling (`pm.max_requests`)**: Ensures PHP-FPM workers recycle periodically (`500` requests by default) to prevent persistent worker memory abuse with minimal CPU overhead, or `1` (`--max-requests 1`) for strict per-request worker isolation against multi-request exploit chains.
3. **Optional Nginx Header Filtering**: Generates and validates (`/etc/nginx/conf.d/php2shell_protect.conf` via `nginx -t`) a `map` rule to detect anomalous `Transfer-Encoding` headers.
4. **Pre-Flight Validation & Emergency Auto-Rollback**: Validates running PHP-FPM services via `php-fpm -t` before reloading. If any service fails to reload after patching, changes are automatically rolled back while preserving `*.bak_php2shell` backup files.

## Supported Environments

- **Debian / Ubuntu** (`/etc/php/*`)
- **RHEL / CentOS / AlmaLinux / Rocky Linux & Remi** (`/etc/php.ini`, `/etc/php.d`, `/etc/php-fpm.d`, `/etc/opt/remi/*`)
- **cPanel EasyApache 4** (`/opt/cpanel/ea-php*`, `/var/cpanel/ea-php*`)
- **Custom Paths** via `PHP2SHELL_SEARCH_ROOTS="/custom/php/path"`

## Quick Start

### 1. Audit the server for vulnerable settings
```bash
sudo bash php2shell-fix.sh --check
```

### 2. Apply mitigations (backups are created automatically)
```bash
sudo bash php2shell-fix.sh --apply
```

*(Optional)* For strict per-request worker isolation (breaks multi-request exploit chains per request at the cost of higher CPU usage):
```bash
sudo bash php2shell-fix.sh --apply --max-requests 1
```

### 3. Rollback changes (restore original configurations)
```bash
sudo bash php2shell-fix.sh --rollback
```

*(Optional)* Restore configurations while keeping `*.bak_php2shell` backup files on disk:
```bash
sudo bash php2shell-fix.sh --rollback --keep-backups
```

---

## Author

Created and maintained by **[ArmHack-Team](https://github.com/armhackteam)**.
