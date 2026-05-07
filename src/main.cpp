#include <windows.h>
#include <shellapi.h>
#include <strsafe.h>

#include "resource.h"

namespace {

constexpr wchar_t kWindowClassName[] = L"BMTXMainWindow";
constexpr wchar_t kAppTitle[] = L"BMTX";
constexpr wchar_t kMutexName[] = L"Local\\BMTX_SINGLE_INSTANCE";
constexpr UINT kTrayMessage = WM_APP + 1;
constexpr UINT kTrayId = 1;

HINSTANCE g_instance = nullptr;
HWND g_main_window = nullptr;
HMENU g_main_menu = nullptr;
HICON g_app_icon = nullptr;
HICON g_tray_icon = nullptr;
NOTIFYICONDATAW g_tray_data{};
UINT g_taskbar_created_message = 0;
HANDLE g_mutex = nullptr;
bool g_tray_added = false;
bool g_exit_requested = false;

bool HasHiddenStartupFlag(LPWSTR command_line) {
    if (command_line == nullptr) {
        return false;
    }

    return wcsstr(command_line, L"--hidden") != nullptr ||
           wcsstr(command_line, L"--background") != nullptr ||
           wcsstr(command_line, L"--minimized") != nullptr ||
           wcsstr(command_line, L"/hidden") != nullptr;
}

void ShowLastErrorMessage(const wchar_t* operation) {
    const DWORD error = GetLastError();
    wchar_t text[512]{};
    StringCchPrintfW(
        text,
        ARRAYSIZE(text),
        L"%s failed. GetLastError = %lu",
        operation,
        error);
    MessageBoxW(g_main_window, text, L"BMTX", MB_OK | MB_ICONERROR);
}

HICON LoadApplicationIcon(int size) {
    HICON icon = reinterpret_cast<HICON>(LoadImageW(
        g_instance,
        MAKEINTRESOURCEW(IDI_APPICON),
        IMAGE_ICON,
        size,
        size,
        LR_DEFAULTCOLOR));

    if (icon == nullptr) {
        icon = LoadIconW(nullptr, IDI_APPLICATION);
    }

    return icon;
}

void ShowMainWindow() {
    if (g_main_window == nullptr) {
        return;
    }

    ShowWindow(g_main_window, SW_SHOWNORMAL);
    SetForegroundWindow(g_main_window);
    UpdateWindow(g_main_window);
}

void HideMainWindow() {
    if (g_main_window != nullptr) {
        ShowWindow(g_main_window, SW_HIDE);
    }
}

void RemoveTrayIcon() {
    if (g_tray_added) {
        Shell_NotifyIconW(NIM_DELETE, &g_tray_data);
        g_tray_added = false;
    }
    ZeroMemory(&g_tray_data, sizeof(g_tray_data));
}

bool AddTrayIcon() {
    if (g_main_window == nullptr) {
        return false;
    }

    if (g_tray_added) {
        return true;
    }

    ZeroMemory(&g_tray_data, sizeof(g_tray_data));
    g_tray_data.cbSize = sizeof(g_tray_data);
    g_tray_data.hWnd = g_main_window;
    g_tray_data.uID = kTrayId;
    g_tray_data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    g_tray_data.uCallbackMessage = kTrayMessage;
    g_tray_data.hIcon = g_tray_icon != nullptr ? g_tray_icon : LoadApplicationIcon(GetSystemMetrics(SM_CXSMICON));
    StringCchCopyW(g_tray_data.szTip, ARRAYSIZE(g_tray_data.szTip), kAppTitle);

    if (!Shell_NotifyIconW(NIM_ADD, &g_tray_data)) {
        ShowLastErrorMessage(L"Shell_NotifyIconW(NIM_ADD)");
        ZeroMemory(&g_tray_data, sizeof(g_tray_data));
        return false;
    }

    g_tray_added = true;
    g_tray_data.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &g_tray_data);
    return true;
}

void RecreateTrayIcon() {
    g_tray_added = false;
    ZeroMemory(&g_tray_data, sizeof(g_tray_data));
    AddTrayIcon();
}

void ExitApplication() {
    g_exit_requested = true;
    RemoveTrayIcon();

    if (g_main_window != nullptr) {
        DestroyWindow(g_main_window);
        g_main_window = nullptr;
    } else {
        PostQuitMessage(0);
    }
}

void ShowTrayMenu() {
    if (g_main_window == nullptr) {
        return;
    }

    HMENU menu = CreatePopupMenu();
    if (menu == nullptr) {
        return;
    }

    AppendMenuW(menu, MF_STRING, IDM_TRAY_OPEN, L"Открыть");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, IDM_TRAY_EXIT, L"Выход");

    POINT point{};
    GetCursorPos(&point);

    SetForegroundWindow(g_main_window);
    const UINT command = TrackPopupMenu(
        menu,
        TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN | TPM_RETURNCMD,
        point.x,
        point.y,
        0,
        g_main_window,
        nullptr);
    DestroyMenu(menu);

    if (command == IDM_TRAY_OPEN) {
        ShowMainWindow();
    } else if (command == IDM_TRAY_EXIT) {
        ExitApplication();
    }

    PostMessageW(g_main_window, WM_NULL, 0, 0);
}

void CreateMainMenu(HWND window) {
    g_main_menu = CreateMenu();
    HMENU file_menu = CreatePopupMenu();

    AppendMenuW(file_menu, MF_STRING, IDM_FILE_EXIT, L"Выход");
    AppendMenuW(g_main_menu, MF_POPUP, reinterpret_cast<UINT_PTR>(file_menu), L"Файл");

    SetMenu(window, g_main_menu);
}

void PaintInterface(HWND window) {
    PAINTSTRUCT paint{};
    HDC dc = BeginPaint(window, &paint);
    if (dc == nullptr) {
        return;
    }

    RECT client{};
    GetClientRect(window, &client);

    HBRUSH background = CreateSolidBrush(RGB(7, 9, 13));
    FillRect(dc, &client, background);
    DeleteObject(background);

    SetBkMode(dc, TRANSPARENT);

    HFONT title_font = CreateFontW(30, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    HFONT body_font = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    HFONT small_font = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

    SelectObject(dc, title_font);
    SetTextColor(dc, RGB(232, 238, 247));
    TextOutW(dc, 42, 42, kAppTitle, static_cast<int>(wcslen(kAppTitle)));

    SelectObject(dc, body_font);
    SetTextColor(dc, RGB(128, 146, 169));
    const wchar_t subtitle[] = L"BMTX // NEX GEN OF ANTI-MALWARE SOFTWARE";
    TextOutW(dc, 44, 86, subtitle, static_cast<int>(wcslen(subtitle)));

    HPEN border_pen = CreatePen(PS_SOLID, 1, RGB(40, 52, 70));
    HPEN accent_pen = CreatePen(PS_SOLID, 2, RGB(94, 234, 212));
    HBRUSH panel_brush = CreateSolidBrush(RGB(13, 17, 24));
    HGDIOBJ old_pen = SelectObject(dc, border_pen);
    HGDIOBJ old_brush = SelectObject(dc, panel_brush);

    RECT badge{client.right - 190, 38, client.right - 42, 96};
    RoundRect(dc, badge.left, badge.top, badge.right, badge.bottom, 16, 16);
    SelectObject(dc, small_font);
    SetTextColor(dc, RGB(94, 234, 212));
    const wchar_t badge_text[] = L"CORE ONLINE";
    TextOutW(dc, badge.left + 34, badge.top + 20, badge_text, static_cast<int>(wcslen(badge_text)));

    RECT panel{42, 130, client.right - 42, 326};
    RoundRect(dc, panel.left, panel.top, panel.right, panel.bottom, 18, 18);

    SelectObject(dc, accent_pen);
    MoveToEx(dc, panel.left + 22, panel.top + 34, nullptr);
    LineTo(dc, panel.right - 22, panel.top + 34);

    SelectObject(dc, body_font);
    SetTextColor(dc, RGB(214, 222, 235));
    const wchar_t status[] = L"STATUS / PROCESS IS ACTIVE";
    TextOutW(dc, panel.left + 24, panel.top + 58, status, static_cast<int>(wcslen(status)));

    SetTextColor(dc, RGB(145, 163, 187));
    const wchar_t hint1[] = L"• Крестик скрывает главное окно, процесс продолжает работу";
    const wchar_t hint2[] = L"• Полное завершение: Файл -> Выход или трей -> Выход";
    const wchar_t hint3[] = L"• ЛКМ по иконке трея открывает главное окно";
    const wchar_t hint4[] = L"• Для скрытого старта используйте параметр --hidden";
    TextOutW(dc, panel.left + 24, panel.top + 94, hint1, static_cast<int>(wcslen(hint1)));
    TextOutW(dc, panel.left + 24, panel.top + 124, hint2, static_cast<int>(wcslen(hint2)));
    TextOutW(dc, panel.left + 24, panel.top + 154, hint3, static_cast<int>(wcslen(hint3)));
    TextOutW(dc, panel.left + 24, panel.top + 178, hint4, static_cast<int>(wcslen(hint4)));

    SelectObject(dc, small_font);
    SetTextColor(dc, RGB(86, 102, 126));
    const wchar_t footer[] = L"BMTX 1.1 / Win32 API";
    TextOutW(dc, 44, client.bottom - 42, footer, static_cast<int>(wcslen(footer)));

    SelectObject(dc, old_pen);
    SelectObject(dc, old_brush);
    DeleteObject(border_pen);
    DeleteObject(accent_pen);
    DeleteObject(panel_brush);
    DeleteObject(title_font);
    DeleteObject(body_font);
    DeleteObject(small_font);

    EndPaint(window, &paint);
}

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM w_param, LPARAM l_param) {
    if (message == g_taskbar_created_message) {
        RecreateTrayIcon();
        return 0;
    }

    switch (message) {
    case WM_NCCREATE:
        g_main_window = window;
        return DefWindowProcW(window, message, w_param, l_param);

    case WM_CREATE:
        g_main_window = window;
        CreateMainMenu(window);
        AddTrayIcon();
        return 0;

    case WM_COMMAND:
        switch (LOWORD(w_param)) {
        case IDM_FILE_EXIT:
            ExitApplication();
            return 0;
        case IDM_TRAY_EXIT:
            ExitApplication();
            return 0;
        case IDM_TRAY_OPEN:
            ShowMainWindow();
            return 0;
        default:
            break;
        }
        return 0;

    case kTrayMessage:
        switch (LOWORD(l_param)) {
        case WM_LBUTTONUP:
        case WM_LBUTTONDBLCLK:
            ShowMainWindow();
            return 0;
        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
            ShowTrayMenu();
            return 0;
        default:
            break;
        }
        return 0;

    case WM_CLOSE:
        HideMainWindow();
        return 0;

    case WM_PAINT:
        PaintInterface(window);
        return 0;

    case WM_DESTROY:
        if (g_exit_requested) {
            RemoveTrayIcon();
            if (g_main_menu != nullptr) {
                DestroyMenu(g_main_menu);
                g_main_menu = nullptr;
            }
            PostQuitMessage(0);
        }
        return 0;

    default:
        return DefWindowProcW(window, message, w_param, l_param);
    }
}

bool RegisterMainWindowClass() {
    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.style = CS_HREDRAW | CS_VREDRAW;
    window_class.lpfnWndProc = WindowProc;
    window_class.hInstance = g_instance;
    window_class.hIcon = g_app_icon;
    window_class.hIconSm = g_tray_icon != nullptr ? g_tray_icon : LoadApplicationIcon(GetSystemMetrics(SM_CXSMICON));
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    window_class.lpszClassName = kWindowClassName;

    return RegisterClassExW(&window_class) != 0;
}

} // namespace

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR command_line, int show_command) {
    g_instance = instance;

    g_mutex = CreateMutexW(nullptr, TRUE, kMutexName);
    if (g_mutex == nullptr) {
        return 1;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(g_mutex);
        return 0;
    }

    g_taskbar_created_message = RegisterWindowMessageW(L"TaskbarCreated");
    g_app_icon = LoadApplicationIcon(GetSystemMetrics(SM_CXICON));
    g_tray_icon = LoadApplicationIcon(GetSystemMetrics(SM_CXSMICON));

    if (!RegisterMainWindowClass()) {
        CloseHandle(g_mutex);
        return 1;
    }

    g_main_window = CreateWindowExW(
        0,
        kWindowClassName,
        kAppTitle,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        760,
        460,
        nullptr,
        nullptr,
        instance,
        nullptr);

    if (g_main_window == nullptr) {
        CloseHandle(g_mutex);
        return 1;
    }

    const bool hidden_start = HasHiddenStartupFlag(command_line);
    if (!hidden_start) {
        ShowWindow(g_main_window, show_command);
        UpdateWindow(g_main_window);
    }

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    RemoveTrayIcon();

    if (g_app_icon != nullptr) {
        DestroyIcon(g_app_icon);
        g_app_icon = nullptr;
    }

    if (g_tray_icon != nullptr) {
        DestroyIcon(g_tray_icon);
        g_tray_icon = nullptr;
    }

    if (g_mutex != nullptr) {
        ReleaseMutex(g_mutex);
        CloseHandle(g_mutex);
        g_mutex = nullptr;
    }

    return static_cast<int>(message.wParam);
}
