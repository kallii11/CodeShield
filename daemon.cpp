// SPDX-License-Identifier: GPL-2.0
#include <atomic>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <json-c/json.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json_types.h>
#include <linux/netlink.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

#include <chrono>
#include <cmath>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "process.hpp"
#include "process_utils.hpp"
#include "syscall_monitor.skel.h" // gerado pela libbpf

using std::lock_guard;
using std::mutex;
using std::string;
using std::unordered_map;
using std::vector;

// constantes
#define MAX_EVENTS_BATCH 10000
#define MAX_SYSCALL_LEN 64
#define TASK_COMM_LEN 16
#define FNAME_LEN 256
#define CONSUMERS 4
#define MAX_FDS 6

// ========================== STRUCTS ==========================
typedef struct {
        __u32 pid;
        char comm[TASK_COMM_LEN];
        char fname[FNAME_LEN];
        char syscall[16];
        int32_t fds[MAX_FDS];
        uint32_t nfds;
} BpfEvent;

typedef struct {
        int pid;
        char comm[TASK_COMM_LEN];
        char fname[FNAME_LEN];
        char syscall[MAX_SYSCALL_LEN];
        int fds[MAX_FDS];
        int nfds;
} Event;

typedef struct {
        Event events[MAX_EVENTS_BATCH];
        int head;
        int tail;
        int count;
        pthread_mutex_t mutex;
        pthread_cond_t not_empty;
        pthread_cond_t not_full;
} EventQueue;

// ========================== Politica ==========================
typedef struct {
        char *tipo;
        char *label;
        __u32 score;
} Regra;

typedef struct {
        __u32 score_max;
        __u32 num_regras;
        Regra *regras;
        char **whitelist;
        int num_whitelist;
} Politica_de_seguranca;

// ========================== GLOBAIS ==========================
static unordered_map<int, Process *> process_table;
static mutex table_mutex;
static pthread_mutex_t rules_mutex = PTHREAD_MUTEX_INITIALIZER;
static EventQueue event_queue = {0};
static std::atomic<bool> running(true);
static bool debug = false;
static bool verbose_debug = false;
static std::atomic<int> tracepoint_count(0);
static Politica_de_seguranca politica = {0};

// ========================== JSON / REGRAS ==========================
static void Cleanup_regras() {
    for (uint32_t i = 0; i < politica.num_regras; ++i) {
        free(politica.regras[i].tipo);
        free(politica.regras[i].label);
    }
    free(politica.regras);
    for (int i = 0; i < politica.num_whitelist; i++)
        free(politica.whitelist[i]);
    free(politica.whitelist);
}

static int load_rules(const char *filename) {
    struct json_object *json, *syscalls, *dirs, *whitelist, *tmp;
    json = json_object_from_file(filename);
    if (!json)
        return -1;

    if (json_object_object_get_ex(json, "score_max", &tmp))
        politica.score_max = json_object_get_int(tmp);

    int num_sys = 0, num_dir = 0;
    if (json_object_object_get_ex(json, "syscalls", &syscalls))
        num_sys = json_object_object_length(syscalls);

    if (json_object_object_get_ex(json, "diretorios", &dirs))
        num_dir = json_object_object_length(dirs);
    else if (json_object_object_get_ex(json, "directories", &dirs))
        num_dir = json_object_object_length(dirs);

    politica.num_regras = num_sys + num_dir;
    politica.regras = (Regra *)calloc(politica.num_regras, sizeof(Regra));

    int idx = 0;
    json_object_object_foreach(syscalls, key1, val1) {
        politica.regras[idx].tipo = strdup("syscall");
        politica.regras[idx].label = strdup(key1);
        politica.regras[idx].score = json_object_get_int(val1);
        idx++;
    }

    json_object_object_foreach(dirs, key2, val2) {
        politica.regras[idx].tipo = strdup("diretorio");
        politica.regras[idx].label = strdup(key2);
        politica.regras[idx].score = json_object_get_int(val2);
        idx++;
    }

    if (json_object_object_get_ex(json, "whitelist", &whitelist)) {
        politica.num_whitelist = json_object_array_length(whitelist);
        politica.whitelist =
            (char **)calloc(politica.num_whitelist, sizeof(char *));
        for (int i = 0; i < politica.num_whitelist; i++) {
            struct json_object *w = json_object_array_get_idx(whitelist, i);
            politica.whitelist[i] = strdup(json_object_get_string(w));
        }
    }

    json_object_put(json);
    return 0;
}

static int get_score_for_event(const Event *e) {
    pthread_mutex_lock(&rules_mutex);
    for (int i = 0; i < politica.num_whitelist; i++) {
        if (fnmatch(politica.whitelist[i], e->comm, 0) == 0) {
            pthread_mutex_unlock(&rules_mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&rules_mutex);
    return 0; // agora score base = 0, só bursts contam
}

// ========================== FILA ==========================
static void enqueue(EventQueue *queue, const Event &e) {
    pthread_mutex_lock(&queue->mutex);
    if (queue->count == MAX_EVENTS_BATCH) {
        queue->head = (queue->head + 1) % MAX_EVENTS_BATCH;
        queue->count--;
    }
    queue->events[queue->tail] = e;
    queue->tail = (queue->tail + 1) % MAX_EVENTS_BATCH;
    queue->count++;
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);
}

static Event dequeue(EventQueue *queue) {
    Event e{};
    pthread_mutex_lock(&queue->mutex);
    while (queue->count == 0 && running.load())
        pthread_cond_wait(&queue->not_empty, &queue->mutex);

    if (queue->count > 0) {
        e = queue->events[queue->head];
        queue->head = (queue->head + 1) % MAX_EVENTS_BATCH;
        queue->count--;
        pthread_cond_signal(&queue->not_full);
    }
    pthread_mutex_unlock(&queue->mutex);
    return e;
}

// ========================== RINGBUFFER HANDLER ==========================
static int handle_ring_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    if (!data || data_sz < sizeof(BpfEvent))
        return 0;
    BpfEvent *bev = (BpfEvent *)data;

    Event e{};
    e.pid = (int)bev->pid;
    strncpy(e.comm, bev->comm, TASK_COMM_LEN);
    e.comm[TASK_COMM_LEN - 1] = '\0';
    strncpy(e.fname, bev->fname, FNAME_LEN);
    e.fname[FNAME_LEN - 1] = '\0';
    strncpy(e.syscall, bev->syscall, MAX_SYSCALL_LEN);
    e.syscall[MAX_SYSCALL_LEN - 1] = '\0';
    e.nfds = (int)bev->nfds;
    if (e.nfds > MAX_FDS)
        e.nfds = MAX_FDS;
    for (int i = 0; i < e.nfds; ++i)
        e.fds[i] = bev->fds[i];
    if (e.nfds == 0)
        e.fds[0] = -1;

    enqueue(&event_queue, e);
    if (debug)
        tracepoint_count.fetch_add(1);
    return 0;
}

// ========================== PROCESSOS PROTEGIDOS ==========================
bool is_system_process(int pid) {
    const char *protected_procs[] = {
        "gnome-shell", "polkitd", "ibus-daemon", "systemd", "login", 
        "spice-vdagentd", "bash", "zsh", "gnome-terminal", "firefox"
    };

    char comm_path[256];
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
    FILE *f = fopen(comm_path, "r");
    if (!f) return false;
    char name[256];
    if (!fgets(name, sizeof(name), f)) { fclose(f); return false; }
    fclose(f);
    name[strcspn(name, "\n")] = 0;

    for (auto &pname : protected_procs) {
        if (strcmp(name, pname) == 0) return true;
    }

    struct stat st;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d", pid);
    if (stat(path, &st) == 0 && st.st_uid == 0) return true;

    return false;
}

void log_killed_processes(const Process &p) {
    syslog(LOG_INFO, "Killed process PID %d COMM %s SCORE %d",
           p.getPid(), p.getComm().c_str(), p.getScore());
}

// ========================== SCORE COMPUTATION ==========================
static int compute_event_score(const Event &e, Process *p) {
    if (!p)
        return 0;

    const char *burst_syscalls[] = {"open", "openat", "creat", "write", "pwrite64", "rename", "unlink", "read"};
    bool is_relevant = false;
    for (const char *s : burst_syscalls)
        if (strcmp(e.syscall, s) == 0) { is_relevant = true; break; }

    if (!is_relevant) return 0;

    return p->register_syscall_event(std::string(e.syscall));
}

// ========================== CONSUMER THREAD ==========================
static void *consumer_thread(void *arg) {
    (void)arg;
    while (running.load()) {
        Event e = dequeue(&event_queue);
        if (e.pid == 0)
            continue;

        Process *p = nullptr;
        bool created = false;

        {
            lock_guard<mutex> lk(table_mutex);
            auto it = process_table.find(e.pid);
            if (it != process_table.end())
                p = it->second;

            if (!p) {
                std::string exe = get_exe_path(e.pid);
                std::string comm = std::string(e.comm);
                std::vector<std::string> fds_repr;
                for (int i = 0; i < e.nfds; ++i) {
                    char buf[64];
                    snprintf(buf, sizeof(buf), "%d", e.fds[i]);
                    fds_repr.push_back(std::string(buf));
                }
                p = new Process(e.pid, exe, comm, fds_repr);
                process_table[e.pid] = p;
                created = true;
            } else {
                if (e.nfds > 0) {
                    int tmpfds[MAX_FDS];
                    for (int i = 0; i < e.nfds && i < MAX_FDS; ++i)
                        tmpfds[i] = e.fds[i];
                    p->update_fds_from_event(tmpfds, e.nfds);
                }
            }

            int add_score = compute_event_score(e, p);
            p->add_score(add_score);

            if (verbose_debug && add_score > 0) {
                std::cout << "PID " << p->getPid() << " SCORE " << p->getScore() << " (burst)\n";
                fflush(stdout);
            }

            if (p->reached_limit(politica.score_max)) {
                if (!is_system_process(p->getPid())) {
                    syslog(LOG_WARNING,
                           "Processo %d (%s) ultrapassou limite (%d >= %d) e sera morto",
                           p->getPid(), p->getComm().c_str(), p->getScore(),
                           politica.score_max);
                    p->kill_process();
                    log_killed_processes(*p);
                } else {
                    syslog(LOG_INFO,
                           "Processo protegido %d (%s) atingiu limite (%d >= %d) mas nao sera morto",
                           p->getPid(), p->getComm().c_str(), p->getScore(),
                           politica.score_max);
                }
            }
        }
    }
    return NULL;
}

// ========================== SIGNAL ==========================
static void sig_handler(int signo) {
    (void)signo;
    running.store(false);
    pthread_cond_broadcast(&event_queue.not_empty);
}

// ========================== MAIN ==========================
int main(int argc, char *argv[]) {
    openlog("daemon-ebpf-cpp", LOG_PID | LOG_CONS, LOG_DAEMON);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0)
            debug = true;
        if (strcmp(argv[i], "-vd") == 0)
            verbose_debug = true;
    }
    if (verbose_debug)
        std::cout << "Modo debug verboso ativado\n";

    if (load_rules("config.json") != 0) {
        fprintf(stderr, "Erro ao carregar regras\n");
        return 1;
    }

    map_all_processes(process_table);

    pthread_mutex_init(&event_queue.mutex, NULL);
    pthread_cond_init(&event_queue.not_empty, NULL);
    pthread_cond_init(&event_queue.not_full, NULL);

    struct syscall_monitor_bpf *skel = NULL;
    skel = syscall_monitor_bpf__open_and_load();
    if (!skel) {
        syslog(LOG_ERR, "Falha ao abrir/load BPF");
        fprintf(stderr, "Falha ao abrir/load BPF\n");
        return 1;
    }
    if (syscall_monitor_bpf__attach(skel) != 0) {
        syslog(LOG_ERR, "Falha attach BPF");
        fprintf(stderr, "Falha attach BPF\n");
        syscall_monitor_bpf__destroy(skel);
        return 1;
    }

    struct ring_buffer *rb = NULL;
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_ring_event, NULL, NULL);
    if (!rb) {
        syslog(LOG_ERR, "Falha criar ring buffer");
        fprintf(stderr, "Falha criar ring buffer\n");
        syscall_monitor_bpf__destroy(skel);
        return 1;
    }

    pthread_t consumers[CONSUMERS];
    for (int i = 0; i < CONSUMERS; ++i)
        pthread_create(&consumers[i], NULL, consumer_thread, NULL);

    syslog(LOG_INFO, "Daemon iniciado (C++ port)");
    std::cout << "Daemon iniciado\n";

    while (running.load()) {
        int ret = ring_buffer__poll(rb, 100);
        if (ret < 0 && errno != EINTR) {
            perror("ring_buffer__poll");
            break;
        }
    }

    running.store(false);
    pthread_cond_broadcast(&event_queue.not_empty);
    for (int i = 0; i < CONSUMERS; ++i)
        pthread_join(consumers[i], NULL);

    ring_buffer__free(rb);
    syscall_monitor_bpf__destroy(skel);

    {
        lock_guard<mutex> lk(table_mutex);
        for (auto &kv : process_table)
            delete kv.second;
        process_table.clear();
    }
    Cleanup_regras();

    syslog(LOG_INFO, "Daemon finalizado");
    printf("\nDaemon encerrado!\n");
    closelog();
    return 0;
}

