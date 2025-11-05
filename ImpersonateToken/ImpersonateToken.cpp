#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

bool EnablePrivilege(LPCWSTR privilegeName)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    if (!LookupPrivilegeValueW(NULL, privilegeName, &tkp.Privileges[0].Luid))
    {
        CloseHandle(hToken);
        return false;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool result = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL) && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
    CloseHandle(hToken);
    return result;
}

DWORD GetProcessIdByName(const std::wstring& processName)
{
    PROCESSENTRY32W entry = { sizeof(PROCESSENTRY32W) };
    DWORD pid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (_wcsicmp(entry.szExeFile, processName.c_str()) == 0)
            {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return pid;
}

bool StartTrustedInstallerService()
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm)
        return false;

    SC_HANDLE service = OpenServiceW(scm, L"TrustedInstaller", SERVICE_START | SERVICE_QUERY_STATUS);
    if (!service)
    {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;

    QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded);

    if (ssp.dwCurrentState != SERVICE_RUNNING)
    {
        StartServiceW(service, 0, NULL);

        for (int i = 0; i < 30; i++)
        {
            Sleep(500);
            QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded);
            if (ssp.dwCurrentState == SERVICE_RUNNING)
                break;
        }
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return (ssp.dwCurrentState == SERVICE_RUNNING);
}

bool GetTrustedInstallerToken(HANDLE* phToken)
{
    // ??? 1: ??????? ?? PROCESS_QUERY_LIMITED_INFORMATION
    DWORD pid = GetProcessIdByName(L"TrustedInstaller.exe");
    if (!pid)
    {
        std::wcerr << L"[-] TrustedInstaller process not found\n";
        return false;
    }

    std::wcout << L"[+] Found TrustedInstaller PID: " << pid << L"\n";

    // ??? ?? PROCESS_QUERY_LIMITED_INFORMATION
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc)
    {
        std::wcerr << L"[-] OpenProcess failed: " << GetLastError() << L"\n";
        return false;
    }

    std::wcout << L"[+] Opened process handle\n";

    HANDLE hToken;
    // ??????? ?? TOKEN_QUERY ???? TOKEN_DUPLICATE
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken))
    {
        DWORD error = GetLastError();
        CloseHandle(hProc);
        std::wcerr << L"[-] OpenProcessToken failed: " << error << L"\n";

        // ??? ???????: ??????? ?? winlogon.exe
        std::wcout << L"[*] Trying alternative method via winlogon.exe...\n";
        CloseHandle(hProc);

        pid = GetProcessIdByName(L"winlogon.exe");
        if (!pid)
            return false;

        hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProc)
            return false;

        if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken))
        {
            CloseHandle(hProc);
            return false;
        }
    }

    std::wcout << L"[+] Opened process token\n";

    // Duplicate token
    HANDLE hDupToken;
    if (!DuplicateTokenEx(hToken, TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE,
        NULL, SecurityImpersonation, TokenPrimary, &hDupToken))
    {
        DWORD error = GetLastError();
        std::wcerr << L"[-] DuplicateTokenEx failed: " << error << L"\n";
        CloseHandle(hToken);
        CloseHandle(hProc);
        return false;
    }

    std::wcout << L"[+] Duplicated token\n";

    *phToken = hDupToken;
    CloseHandle(hToken);
    CloseHandle(hProc);
    return true;
}

bool CreateProcessAsTrustedInstaller(const std::wstring& commandLine)
{
    if (!EnablePrivilege(SE_DEBUG_NAME))
    {
        std::wcerr << L"[-] Failed to enable SeDebugPrivilege\n";
        return false;
    }

    if (!EnablePrivilege(SE_IMPERSONATE_NAME))
    {
        std::wcerr << L"[-] Failed to enable SeImpersonatePrivilege\n";
        return false;
    }

    std::wcout << L"[+] Privileges enabled\n";

    if (!StartTrustedInstallerService())
    {
        std::wcerr << L"[-] Failed to start TrustedInstaller service\n";
        return false;
    }

    std::wcout << L"[+] TrustedInstaller service started\n";
    Sleep(2000);

    HANDLE hToken;
    if (!GetTrustedInstallerToken(&hToken))
    {
        std::wcerr << L"[-] Failed to get TrustedInstaller token\n";
        return false;
    }

    std::wcout << L"[+] Got TrustedInstaller token\n";

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    wchar_t cmd[1024];
    wcscpy_s(cmd, commandLine.c_str());

    if (!CreateProcessWithTokenW(hToken, 0, NULL, cmd, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
    {
        DWORD error = GetLastError();
        std::wcerr << L"[-] CreateProcessWithTokenW failed: " << error << L"\n";
        CloseHandle(hToken);
        return false;
    }

    std::wcout << L"[+] Process created successfully!\n";
    std::wcout << L"[+] Process ID: " << pi.dwProcessId << L"\n";

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hToken);
    return true;
}

int main()
{
    std::wcout << L"=== TrustedInstaller Process Creator ===\n\n";

    // ????? Administrator
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;

    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup))
    {
        CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin);
        FreeSid(AdministratorsGroup);
    }

    if (!isAdmin)
    {
        std::wcerr << L"[-] Must run as Administrator!\n";
        system("pause");
        return 1;
    }

    std::wcout << L"[+] Running with Administrator privileges\n\n";

    // ????? cmd ?? ?????? TrustedInstaller
    if (CreateProcessAsTrustedInstaller(L"cmd.exe /k whoami /groups & echo. & echo TrustedInstaller privileges active!"))
    {
        std::wcout << L"\n[+] Success! A new cmd window opened with TrustedInstaller privileges.\n";
    }
    else
    {
        std::wcerr << L"\n[-] Failed to create process.\n";
    }

    system("pause");
    return 0;
}
