#ifndef PROCESS_UTILS_HPP
#define PROCESS_UTILS_HPP

#include <dirent.h>
#include <string>
#include <unordered_map>
#include "process.hpp"

inline std::string get_exe_path(int pid) {
    char buf[512];
    snprintf(buf, sizeof(buf), "/proc/%d/exe", pid);
    char path[512];
    ssize_t n = readlink(buf, path, sizeof(path) - 1);
    if (n != -1) {
        path[n] = '\0';
        return std::string(path);
    }
    return std::string();
}

inline void map_all_processes(std::unordered_map<int, Process *> &table) {
    DIR *proc = opendir("/proc");
    if (!proc) return;
    struct dirent *entry;
    while ((entry = readdir(proc)) != nullptr) {
        int pid = atoi(entry->d_name);
        if (pid <= 0) continue;
        std::string exe = get_exe_path(pid);
        Process *p = new Process(pid, exe, entry->d_name, {});
        table[pid] = p;
    }
    closedir(proc);
}

#endif

