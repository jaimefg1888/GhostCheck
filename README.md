## 🇬🇧 English

# 👻 GhostCheck

GhostCheck — Linux server security audit script built with Python and native system tools. No external dependencies — just pure Python reading the system and telling you what's wrong, with a clean TXT and HTML report at the end.

---

## Features

- 6 audit modules that cover the most critical attack surfaces on a Linux server
- Detects dangerous active SSH directives like `PermitRootLogin yes` with exact line numbers
- Checks for pending security updates via `dnf check-update --security` (RHEL / Rocky / Fedora)
- SELinux state check — warns if it's Permissive or Disabled
- Firewall audit for both `firewalld` and `ufw`, flags any non-essential open ports
- Scans `/etc/passwd` for UID 0 accounts that aren't root, and `/etc/shadow` for empty passwords
- Global risk level at the end: `LOW`, `MEDIUM`, `HIGH` or `CRITICAL`
- Generates a timestamped `.txt` report and a clean `.html` report with color-coded badges
- Pure DRY-RUN — reads everything, changes nothing

## Requirements

- Python 3.10+
- Root privileges (`sudo`)
- RHEL / Rocky Linux / AlmaLinux / CentOS Stream / Fedora (or any distro with `firewalld` or `ufw`)

## Setup

```bash
git clone https://github.com/jaimefg1888/ghostcheck.git
cd ghostcheck
```

No `pip install` needed. Uses only Python standard library.

## Run it

```bash
sudo python3 ghostcheck.py
```

## Audit modules

| # | Module | What it checks |
|---|--------|----------------|
| 1 | Root check | UID 0 execution required |
| 2 | SELinux | Enforcing / Permissive / Disabled |
| 3 | Firewall | firewalld or ufw, open ports vs essential ones |
| 4 | Users | UID 0 duplicates, empty passwords in shadow |
| 5 | SSH | Risky directives in `sshd_config` |
| 6 | Updates | Pending security packages via dnf |

## Output files

```
auditoria_servidor_YYYYMMDD_HHMMSS.txt   # plain text report
auditoria_servidor_YYYYMMDD_HHMMSS.html  # visual HTML report
```

## Risk levels

| Level | Meaning |
|-------|---------|
| 🟢 LOW | No warnings found |
| 🟡 MEDIUM | Minor issues detected |
| 🟠 HIGH | Pending updates or SSH risk directives |
| 🔴 CRITICAL | Root-level exposure — act immediately |

## Project structure

```
ghostcheck.py   # full script in a single file
README.md
```

## License

Personal project, do whatever you want with it.

---

## ⚠️ Disclaimer

GhostCheck is provided **AS-IS**, without warranty of any kind, either expressed or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, or non-infringement.

**Obtaining a `LOW` risk level does not mean your server is 100% secure or immune to attack.** GhostCheck covers a specific set of common attack surfaces, but security is a much broader and continuous discipline. There may be other vulnerability vectors — misconfigurations, unaudited services, network-level exposures, application-layer flaws, supply-chain risks, zero-days, or human factors — that this tool does not evaluate and cannot detect.

Use this script as one layer of a defence-in-depth strategy, not as a definitive certification of security. The author assumes no liability for damages, data loss, or security incidents arising from the use or misuse of this tool.

---

## 🇪🇸 Español

# 👻 GhostCheck

GhostCheck — script de auditoría de seguridad para servidores Linux, escrito en Python con herramientas nativas del sistema. Sin dependencias externas — solo Python leyendo el sistema y diciéndote qué está mal, con un informe limpio en TXT y HTML al final.

---

## Características

- 6 módulos de auditoría que cubren las superficies de ataque más críticas de un servidor Linux
- Detecta directivas SSH peligrosas activas como `PermitRootLogin yes` con el número de línea exacto
- Comprueba actualizaciones de seguridad pendientes con `dnf check-update --security` (RHEL / Rocky / Fedora)
- Verifica el estado de SELinux — avisa si está en modo Permissive o Disabled
- Auditoría de firewall para `firewalld` y `ufw`, marca puertos abiertos no esenciales
- Escanea `/etc/passwd` en busca de cuentas con UID 0 que no sean root, y `/etc/shadow` por contraseñas vacías
- Nivel de riesgo global al final: `BAJO`, `MEDIO`, `ALTO` o `CRÍTICO`
- Genera un informe `.txt` con marca de tiempo y un informe `.html` visual con badges de color
- DRY-RUN puro — lee todo, no cambia nada

## Requisitos

- Python 3.10+
- Privilegios de root (`sudo`)
- RHEL / Rocky Linux / AlmaLinux / CentOS Stream / Fedora (o cualquier distro con `firewalld` o `ufw`)

## Instalación

```bash
git clone https://github.com/jaimefg1888/ghostcheck.git
cd ghostcheck
```

Sin `pip install`. Usa solo la librería estándar de Python.

## Ejecutar

```bash
sudo python3 ghostcheck.py
```

## Módulos de auditoría

| # | Módulo | Qué comprueba |
|---|--------|---------------|
| 1 | Root check | Ejecución con UID 0 obligatoria |
| 2 | SELinux | Enforcing / Permissive / Disabled |
| 3 | Firewall | firewalld o ufw, puertos abiertos vs esenciales |
| 4 | Usuarios | UID 0 duplicados, contraseñas vacías en shadow |
| 5 | SSH | Directivas peligrosas en `sshd_config` |
| 6 | Actualizaciones | Paquetes de seguridad pendientes con dnf |

## Archivos de salida

```
auditoria_servidor_YYYYMMDD_HHMMSS.txt   # informe en texto plano
auditoria_servidor_YYYYMMDD_HHMMSS.html  # informe visual en HTML
```

## Niveles de riesgo

| Nivel | Significado |
|-------|-------------|
| 🟢 BAJO | Sin advertencias |
| 🟡 MEDIO | Problemas menores detectados |
| 🟠 ALTO | Actualizaciones pendientes o directivas SSH de riesgo |
| 🔴 CRÍTICO | Exposición a nivel root — actúa inmediatamente |

## Estructura del proyecto

```
ghostcheck.py   # el script completo en un solo archivo
README.md
```

## Licencia

Proyecto personal, haz lo que quieras con él.

---

## ⚠️ Aviso Legal (Disclaimer)

GhostCheck se proporciona **TAL CUAL** (*AS-IS*), sin garantías de ningún tipo, ya sean expresas o implícitas, incluyendo pero sin limitarse a las garantías de comerciabilidad, idoneidad para un propósito particular o no infracción.

**Obtener un nivel de riesgo `BAJO` no significa que tu servidor sea 100% seguro o esté exento de ataques.** GhostCheck cubre un conjunto específico de superficies de ataque habituales, pero la seguridad es una disciplina mucho más amplia y continua. Pueden existir otros vectores de vulnerabilidad — configuraciones incorrectas en otros servicios, exposiciones a nivel de red, fallos en la capa de aplicación, riesgos en la cadena de suministro, zero-days o factores humanos — que esta herramienta no evalúa ni puede detectar.

Utiliza este script como una capa más dentro de una estrategia de defensa en profundidad, no como una certificación definitiva de seguridad. El autor no asume ninguna responsabilidad por daños, pérdida de datos o incidentes de seguridad derivados del uso o mal uso de esta herramienta.
