#include <unistd.h>
#include <cctype>
#include <sstream>
#include <string>
#include <vector>

#include "process.h"

using std::string;
using std::to_string;
using std::vector;

void Process::setPid(const int pid) {
    pid_ = pid;
}

// TODO: Return this process's ID
int Process::Pid() { return pid_; }

// TODO: Return this process's CPU utilization
float Process::CpuUtilization() { 
    long int upTime = LinuxParser::UpTime(pid_);
    vector<string> cpuInfo = LinuxParser::ProcessorUtilization(pid_);
    long int utime = std::stol(cpuInfo[13]);
    long int stime = std::stol(cpuInfo[14]);
    long int cutime = std::stol(cpuInfo[15]);
    long int cstime = std::stol(cpuInfo[16]); 
    long int startime = std::stol(cpuInfo[21]);
    
    int long totalTime = utime + stime;
    totalTime += cutime + cstime;

    float seconds = (float)upTime - ((float)startime / sysconf(_SC_CLK_TCK));
    float cpuUsage = (((float)totalTime / sysconf(_SC_CLK_TCK)) / seconds);

    cpu_ = cpuUsage;

    return cpuUsage; 
}

// TODO: Return the command that generated this process
string Process::Command() { return LinuxParser::Command(pid_); }

// TODO: Return this process's memory utilization
string Process::Ram() { 
    string ramstring = LinuxParser::Ram(pid_); 
    try {
        ram_ = std::stol(ramstring) / 1024;        
    } catch(...) {
        ram_ = 0;
    }
    return std::to_string(ram_);
}

// TODO: Return the user (name) that generated this process
string Process::User() { return LinuxParser::User(pid_); }

// TODO: Return the age of this process (in seconds)
long int Process::UpTime() { return LinuxParser::UpTime(pid_); }

// TODO: Overload the "less than" comparison operator for Process objects
// REMOVE: [[maybe_unused]] once you define the function
bool Process::operator<(Process const& a) const { 
    return ram_ > a.ram_;
    //return cpu_ < a.cpu_;
}

void Process::setRam() {
    string ramStr = LinuxParser::Ram(pid_);
    try {
        ram_ = std::stol(ramStr) / 1024;
    } catch (...) {
        ram_ = 0;
    }
}
