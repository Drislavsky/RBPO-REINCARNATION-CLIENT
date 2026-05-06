# BMTX

C++ / Win32 API / CMake tray application.

## Fixed behavior

- The tray icon is added during `WM_CREATE` after `g_main_window` is assigned.
- Left click on tray icon opens the main window.
- Right click on tray icon opens context menu: `Открыть`, `Выход`.
- `Файл -> Выход` fully exits the process.
- Tray menu `Выход` fully exits the process.
- Closing the main window with the `X` button hides the window and keeps the process running.
- The app restores the tray icon after taskbar recreation via `TaskbarCreated`.
- Single-instance protection is implemented with a named mutex.
- Hidden startup is supported with `--hidden`, `--background`, `--minimized`, or `/hidden`.

## Build

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

## Run

```powershell
.\build\Release\BMTX.exe
```

Hidden start:

```powershell
.\build\Release\BMTX.exe --hidden
```

## Important tray fix

The old version called `AddTrayIcon()` in `WM_CREATE`, but `g_main_window` was still `nullptr` during `CreateWindowExW`. Because of that, `AddTrayIcon()` returned early and the tray icon was never created. This version assigns `g_main_window = window` in `WM_NCCREATE` and again in `WM_CREATE` before calling `AddTrayIcon()`.
