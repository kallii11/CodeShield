#ifndef PROCESS_HPP
#define PROCESS_HPP

#include <csignal>
#include <ctime>
#include <iostream>
#include <string>
#include <unistd.h>
#include <vector>
#include <deque>
#include <unordered_map>
#define MAX_FDS 6
static const int BURST_WINDOW_SEC = 5;
static const int BURST_THRESHOLD = 400;
static const int BURST_SCORE = 1000;

class Process {
private:
    int pid;
    int score;
    time_t last_update;
    std::string exe_path;
    std::string comm;
    std::vector<std::string> fds;

    std::unordered_map<std::string, std::deque<time_t>> syscall_history;
    std::unordered_map<std::string, time_t> last_burst_time;

public:
    Process(int pid_, const std::string &exe, const std::string &comm_,
            const std::vector<std::string> &fd_list)
        : pid(pid_), score(0), last_update(std::time(nullptr)),
          exe_path(exe), comm(comm_), fds(fd_list) {}

    int getPid() const { return pid; }
    int getScore() const { return score; }
    std::string getExePath() const { return exe_path; }
    std::string getComm() const { return comm; }
    std::vector<std::string> getFDs() const { return fds; }

    void add_score(int value) {
        score += value;
        last_update = std::time(nullptr);
    }

    bool reached_limit(int limit) const { return score >= limit; }

    void kill_process() const {
        if (::kill(pid, SIGKILL) == 0) {
            std::cout << "Killed process " << pid << " (" << exe_path
                      << ") with score " << score << std::endl;
        } else {
            perror("Erro ao tentar matar processo");
        }
    }

	void update_fds_from_event(int fds_arr[], int nfds_in) {
	    if (nfds_in <= 0) return;
	    fds.clear();
	    for (int i = 0; i < nfds_in && i < MAX_FDS; ++i) {
		char buf[512];
		snprintf(buf, sizeof(buf), "%d", fds_arr[i]);
		fds.push_back(std::string(buf));
	    }
	}

    void print_info() const {
        std::cout << "PID: " << pid << " COMM: " << comm << " SCORE: " << score << "\n";
    }

    int register_syscall_event(const std::string &sc) {
        time_t now = std::time(nullptr);
        auto &dq = syscall_history[sc];
        dq.push_back(now);

        while (!dq.empty() && (now - dq.front() > BURST_WINDOW_SEC)) dq.pop_front();

        if (dq.size() > BURST_THRESHOLD) {
            if (last_burst_time.find(sc) == last_burst_time.end() || now - last_burst_time[sc] > BURST_WINDOW_SEC) {
                last_burst_time[sc] = now;
                return BURST_SCORE;
            }
        }
        return 0;
    }
};

#endif

