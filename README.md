# BMTX

Windows C++ / Win32 API project with two binaries:

- `BMTX.exe` - interactive tray GUI client.
- `BMTXService.exe` - Windows service that owns the GUI lifecycle and exposes a local Windows RPC endpoint over `ncalrpc`/ALPC.

## What is implemented

### Service

- Runs as a Windows service named `BMTXService`.
- Starts `BMTX.exe --hidden` in all terminal sessions except session `0` when a user token is available.
- Starts `BMTX.exe --hidden` for newly logged-on/unlocked/reconnected terminal sessions.
- Launches the GUI as the owner of that terminal session via `WTSQueryUserToken`, `DuplicateTokenEx`, `CreateEnvironmentBlock`, and `CreateProcessAsUserW`.
- Does not accept SCM `Stop` or `Shutdown` controls; it accepts only session-change notifications.
- Starts a Windows RPC server using the local RPC protocol sequence `ncalrpc`, which is transported by ALPC on modern Windows.
- Registers the RPC interface `BmtxStopService()` for local clients.
- Runs until the RPC stop command is received.
- Terminates all GUI clients when stopping.
- During install, uses a safe service DACL: LocalSystem and Administrators keep full control, while Authenticated Users receive only query/start rights so the GUI can start the service if it is stopped. This build intentionally does not use anti-admin or anti-delete protection.

### GUI client

- On startup checks `BMTXService` state.
- If the service is stopped, starts it, waits for `Running`, then exits.
- If the service is already running, the GUI accepts only service-created launches: it requires `--bmtx-service-child`, verifies `--bmtx-service-pid=<pid>` against the real SCM service PID, and then checks that the parent process is `BMTXService.exe`. Manual launches exit before creating the tray icon/window.
- Starts hidden when service passes `--hidden`.
- Keeps the tray behavior from PRAC_1: left click opens the main window, right click opens the tray menu.
- `Файл -> Выход` calls the RPC stop method on the service.
- Tray menu `Выход` calls the RPC stop method on the service.
- Closing the window with `X` hides the window and keeps the process running.

## Deliberately not implemented

The optional anti-termination items that prevent normal users or administrators from terminating processes are not included. Those mechanisms are unsafe outside a controlled security product context and can easily become persistence/anti-administration behavior. The service uses standard Windows service/RPC control flow instead.

Secure Desktop confirmation is also not implemented in this version.

## Build

Run from a Visual Studio Developer PowerShell:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Or:

```powershell
.\build-release.ps1
```

Build artifacts:

```text
build\Release\BMTX.exe
build\Release\BMTXService.exe
```

## Install service

Run PowerShell or CMD as Administrator from the folder containing the built binaries:

```powershell
.\BMTXService.exe --install
```

Then start the service:

```powershell
sc.exe start BMTXService
```

The service will launch `BMTX.exe --hidden` in logged-on non-zero sessions.

## Test GUI behavior

Manual launch while the service is stopped:

```powershell
.\BMTX.exe
```

Expected behavior: GUI starts `BMTXService`, waits until it is running, then exits. The service then launches the hidden GUI instance itself.

Manual launch while the service is running:

```powershell
.\BMTX.exe
```

Expected behavior: exits immediately because the service launch marker is missing and the parent process is not `BMTXService.exe`. If the service is stopped, this manual launch may start the service and then exit; the visible/running client after that is the service-created one.

Stop through GUI:

```text
Файл -> Выход
```

or:

```text
Tray icon -> right click -> Выход
```

Expected behavior: GUI sends `BmtxStopService()` through local RPC. The service stops and terminates all GUI clients.

## Uninstall service

Run as Administrator:

```powershell
.\BMTXService.exe --uninstall
```
## Важно после обновления IDL/RPC

Если Visual Studio показывает `cannot open input file rpc.idl` или `bmtx_rpc.h` не найден, удалите старую папку `build` и сконфигурируйте проект заново:

```powershell
Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

В `rpc/bmtx_rpc.idl` не используется `import "rpc.idl";`, потому что `handle_t` является базовым типом MIDL, а импорт `rpc.idl` на некоторых установках Windows SDK не находится и ломает генерацию `bmtx_rpc.h`.



## MIDL note

The RPC IDL uses an explicit `handle_t` parameter instead of `implicit_handle`, so it does not require `/app_config` or a separate ACF file. If Visual Studio still shows stale `bmtx_rpc.h` errors, delete the `build` directory and configure the project again.

## Важно про RPC/MIDL в Visual Studio

Файлы `bmtx_rpc.h`, `bmtx_rpc_c.c` и `bmtx_rpc_s.c` генерируются из `rpc/bmtx_rpc.idl` во время CMake configure в папку `build/generated`. Если Visual Studio показывает `bmtx_rpc.h not found`, удалите `build` и выполните CMake configure заново.


## Build fix note

Session change handling uses `WTS_REMOTE_CONNECT` from `Wtsapi32.h` for remote reconnect events.

## Safe reinstall / cleanup

This build does not intentionally block administrators from maintaining the service. If an old broken service is still registered from a previous build, remove it once from an elevated PowerShell before installing this version:

```powershell
taskkill /IM BMTX.exe /F
taskkill /IM BMTXService.exe /F
sc.exe stop BMTXService
sc.exe delete BMTXService
```

If the previous broken service DACL still blocks deletion, remove the stale service registry key once and reboot:

```powershell
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\BMTXService" /f
shutdown /r /t 0
```

After reboot, install this fixed build from `build\Release`:

```powershell
.\BMTXService.exe --install
sc.exe start BMTXService
```

## Manual BMTX.exe launch behavior

`BMTX.exe` is not allowed to create the UI/tray when started manually.

Expected behavior:

- If `BMTXService` is stopped, manual `BMTX.exe` only starts the service, waits for Running, and exits before creating UI/tray.
- If `BMTXService` is already running, manual `BMTX.exe` exits immediately before creating UI/tray.
- Only the service-launched command line is accepted:
  `BMTX.exe --hidden --bmtx-service-child --bmtx-service-pid=<real service pid>`
- The client also verifies that its parent PID equals the real service PID from SCM.

Startup decisions are logged to:

`%TEMP%\BMTX_client_debug.log`

To prove that manual launch exits, use:

```powershell
Get-Process BMTX -ErrorAction SilentlyContinue | Select-Object Id,Path
.\BMTX.exe
Start-Sleep -Seconds 1
Get-Process BMTX -ErrorAction SilentlyContinue | Select-Object Id,Path
notepad "$env:TEMP\BMTX_client_debug.log"
```
