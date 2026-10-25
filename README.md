# ArmHack-Team Security & Mitigation Scripts 🇦🇲

Official repository of security mitigation, patching, and server hardening scripts developed by **[ArmHack-Team](https://github.com/armhackteam)**.

> [!IMPORTANT]
> **Backup Warning / Предупреждение о резервном копировании / Պահուստային պատճենման նախազգուշացում**
> * **HY:** Նախքան աշխատանքային (production) սերվերների վրա ցանկացած սկրիպտ գործարկելը, պարտադիր ստեղծեք կոնֆիգուրացիոն ֆայլերի ամբողջական պահուստային պատճեն (backup) կամ վիրտուալ մեքենայի snapshot։ Մենք հաշվի ենք առել ստանդարտ միջավայրերի մեծ մասը, սակայն հնարավոր չէ նախատեսել բոլոր հնարավոր ոչ ստանդարտ հավաքածուներն ու կարգավորումները։
> * **RU:** Перед запуском любых скриптов на боевых серверах обязательно создавайте полную резервную копию конфигурационных файлов или снапшот виртуальной машины. Мы учли большинство стандартных окружений, однако учесть абсолютно все кастомные сборки и конфигурации невозможно.
> * **EN:** Always create a full manual backup of your server configurations or a VM snapshot before running any mitigation scripts in production. While our tools cover the vast majority of standard deployments, it is impossible to account for every custom environment.

---

## Available Scripts

| Folder | Script | Target / CVE | Description |
| :--- | :--- | :--- | :--- |
| [`php2shell/`](./php2shell) | [`php2shell-fix.sh`](./php2shell/php2shell-fix.sh) | CVE-2026-109618 / CVE-2026-109619 | Emergency mitigation & hardening tool for PHP 7.4, PHP 8.1, and legacy PHP-FPM environments against PHP2Shell RCE vectors. |
