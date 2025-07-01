# Process Monitor (eBPF)

A program designed to monitor the execution of new processes on a Linux system using eBPF technology. It hooks into the `exec` syscalls, gathers detailed information about each new process, and saves it to a `processes.json` file in chronological order.

## Features

*   **Process Monitoring:** Uses the `tracepoint/sched/sched_process_exec` to track all new process launches across the system.
*   **Data Collection:** For each process, the following data is collected:
    *   PID, TGID, PPID, PGID
    *   UID, GID
    *   Process name (`comm`)
    *   Command line (`cmdline`)
    *   Timestamp (in milliseconds)
*   **Filtering:** The eBPF code filters out kernel threads.
*   **Event Order Guarantee:** Events received from the `perf buffer` are sorted in user space in chronological order.
*   **Output Format:** Data is serialized into JSON format.
*   **Fully Static Build:** The program is compiled into a single, static binary with no external dynamic dependencies (including `libc` and `libc++`), ensuring maximum portability.

## Requirements

*   **OS:** Linux with kernel version 5.8+ (for BTF support).
*   **Build Tools:**
    *   A C++23 compliant compiler (GCC 13+ or Clang 16+).
    *   `CMake` (version 3.23+).
    *   `clang` and `bpftool` for compiling and processing eBPF code.
*   **Dependencies:**
    *   `libbpf`
    *   `nlohmann-json`
    *   All dependencies are managed via `vcpkg` and are installed automatically during the build process.

## Building the Project

1.  **Clone the repository with submodules:**
    ```bash
    git clone --recursive <your_repository_url>
    cd <project_folder_name>
    ```

2.  **Configure and build the project:**
    The `build.sh` script automates this process.
    ```bash
    ./build.sh
    ```
    Alternatively, you can run the commands manually:
    ```bash
    # Configure the project, specifying the static triplet
    cmake -B build -S .

    # Build the project
    cmake --build build -j$(nproc)
    ```

## Usage

The program requires superuser (`root`) privileges to load eBPF programs into the kernel.

```bash
sudo ./build/ProcessMonitor
```

The application will start monitoring and run until interrupted by a signal (e.g., `Ctrl+C`).
Upon termination, a `processes.json` file containing the collected data will be created in the current directory.

### Output Format (`processes.json`)

The file contains a sequence of JSON objects, one per line.

**Example object:**
```json
{
  "cmdline": "/usr/bin/ls",
  "comm": "ls",
  "gid": 1000,
  "pgid": 12345,
  "pid": 54321,
  "ppid": 12345,
  "tgid": 54321,
  "timestamp": 1678886400123,
  "uid": 1000
}
```
