# Proxychains-Windows - Unified Binary Package

Este paquete contiene todos los archivos necesarios para usar proxychains en Windows.

## Contenido del Paquete

- **proxychains.exe** - Ejecutable principal (x64) con soporte para procesos x86 y x64
- **proxychains_hook_x64.dll** - DLL de hooks para procesos de 64 bits
- **proxychains_hook_x86.dll** - DLL de hooks para procesos de 32 bits
- **MinHook.x64.dll** - Biblioteca MinHook para x64 (si está incluida)
- **MinHook.x86.dll** - Biblioteca MinHook para x86 (si está incluida)
- **proxychains.conf** - Archivo de configuración de ejemplo
- **README.md** - Documentación completa
- **CHANGELOG.md** - Registro de cambios
- **TESTING.md** - Guía de pruebas
- **COPYING** - Licencia GPL v2

## Instalación Rápida

1. Extrae todos los archivos a un directorio (ej: `C:\Program Files\proxychains`)
2. Agrega ese directorio a tu variable de entorno PATH
3. Edita `proxychains.conf` con la configuración de tu proxy
4. ¡Listo para usar!

## Uso Básico

```cmd
proxychains.exe <tu-aplicación>
```

Ejemplos:
```cmd
proxychains.exe curl https://ifconfig.me
proxychains.exe ssh usuario@servidor
proxychains.exe "C:\Program Files\Firefox\firefox.exe"
```

## Detección Automática de Arquitectura

Este paquete incluye un **único ejecutable** que automáticamente:
- Detecta si el proceso objetivo es de 32 o 64 bits
- Inyecta la DLL correcta (x86 o x64)
- Funciona con ambos tipos de procesos sin configuración adicional

**No necesitas saber la arquitectura del programa** - proxychains.exe lo detecta automáticamente.

## Configuración

Edita `proxychains.conf` y configura tus proxies en la sección `[ProxyList]`:

```
[ProxyList]
socks5  127.0.0.1 1080
```

Consulta el archivo de configuración para opciones avanzadas.

## Requisitos

- Windows 11, Windows 10, o Windows 7 (64 bits)
- Visual C++ Redistributable 2015 o superior
- Un servidor proxy SOCKS5

## Documentación Completa

- Ver `README.md` para documentación detallada
- Ver `TESTING.md` para guía de pruebas
- Ver `CHANGELOG.md` para cambios y mejoras

## Soporte

Para problemas, reportes de bugs o sugerencias:
- GitHub Issues: https://github.com/EduardoA3677/proxychains-windows/issues

## Licencia

GNU General Public License v2 - Ver archivo COPYING
