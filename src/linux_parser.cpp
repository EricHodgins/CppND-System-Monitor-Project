#include <dirent.h>
#include <unistd.h>
#include <string>
#include <vector>

#include "linux_parser.h"

using std::stof;
using std::string;
using std::to_string;
using std::vector;

// DONE: An example of how to read data from the filesystem
string LinuxParser::OperatingSystem() {
  string line;
  string key;
  string value;
  std::ifstream filestream(kOSPath);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::replace(line.begin(), line.end(), ' ', '_');
      std::replace(line.begin(), line.end(), '=', ' ');
      std::replace(line.begin(), line.end(), '"', ' ');
      std::istringstream linestream(line);
      while (linestream >> key >> value) {
        if (key == "PRETTY_NAME") {
          std::replace(value.begin(), value.end(), '_', ' ');
          return value;
        }
      }
    }
  }
  return value;
}

// DONE: An example of how to read data from the filesystem
string LinuxParser::Kernel() {
  string os, version, kernel;
  string line;
  std::ifstream stream(kProcDirectory + kVersionFilename);
  if (stream.is_open()) {
    std::getline(stream, line);
    std::istringstream linestream(line);
    linestream >> os >> version >> kernel;
  }
  return kernel;
}

// BONUS: Update this to use std::filesystem
vector<int> LinuxParser::Pids() {
  vector<int> pids;
  DIR* directory = opendir(kProcDirectory.c_str());
  struct dirent* file;
  while ((file = readdir(directory)) != nullptr) {
    // Is this a directory?
    if (file->d_type == DT_DIR) {
      // Is every character of the name a digit?
      string filename(file->d_name);
      if (std::all_of(filename.begin(), filename.end(), isdigit)) {
        int pid = stoi(filename);
        pids.push_back(pid);
      }
    }
  }
  closedir(directory);
  return pids;
}

// TODO: Read and return the system memory utilization
float LinuxParser::MemoryUtilization() { 
    const std::string MEM_TOTAL{"MemTotal:"};
    const std::string MEM_FREE{"MemFree:"};
    const std::string BUFFERS{"Buffers:"};
    const std::string CACHED{"Cached:"};
    const std::string SRECLAIMABLE{"SReclaimable:"};
    const std::string SHMEM{"Shmem:"};
    const std::string MEM_AVAILABLE{"MemAvailable:"};

    float percent, memTotal{0}, memAvailable{0}, memFree{0};
    std::string test;
    std::string line;
    std::string key, value, buffers, cached, sReclaimable, shmem;
    std::ifstream stream(kProcDirectory + kMeminfoFilename);
    if (stream.is_open()) {
        while (std::getline(stream, line)) {
            std::istringstream linestream(line);
            linestream >> key >> value;
            if (key == MEM_TOTAL) { memTotal = std::stod(value); }            
            if (key == MEM_FREE) { memFree = std::stod(value); }
            if (key == BUFFERS) { buffers = value; }
            if (key == CACHED) { cached = value; }
            if (key == SRECLAIMABLE) { sReclaimable = value; }
            if (key == SHMEM) { shmem = value; }
            if (key == MEM_AVAILABLE) { memAvailable = std::stod(value); }
        }
    }

    percent = memFree / memTotal;

    return percent;
}

// TODO: Read and return the system uptime
long LinuxParser::UpTime() { 
    const std::string TOTAL_PROCESSES{"processes"};
    std::string line, idleTime, suspendTime;
    std::ifstream stream(kProcDirectory + kUptimeFilename);
    if (stream.is_open()) {
        while (std::getline(stream, line)) {
            std::istringstream linestream(line);
            linestream >> idleTime >> suspendTime;
        }
    }

    long int totalTime = std::stol(idleTime) + std::stol(suspendTime);
    
    return totalTime; 
}

// TODO: Read and return the number of jiffies for the system
long LinuxParser::Jiffies() { return 0; }

// TODO: Read and return the number of active jiffies for a PID
// REMOVE: [[maybe_unused]] once you define the function
long LinuxParser::ActiveJiffies(int pid[[maybe_unused]]) { return 0; }

// TODO: Read and return the number of active jiffies for the system
long LinuxParser::ActiveJiffies() { return 0; }

// TODO: Read and return the number of idle jiffies for the system
long LinuxParser::IdleJiffies() { return 0; }

// TODO: Read and return CPU utilization
vector<string> LinuxParser::CpuUtilization() { 
    vector<string> cpuInfo;
    const std::string CPU{"cpu"};
    std::string line, key, value, user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
    std::ifstream stream(kProcDirectory + kStatFilename);
    if (stream.is_open()) {
        while (std::getline(stream, line)) {
            std::istringstream linestream(line);
            linestream >> key;
            if (key == CPU) { 
                linestream >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal >> guest >> guest_nice;  
            }            
        }
    }

    cpuInfo.push_back(user);
    cpuInfo.push_back(nice);
    cpuInfo.push_back(system);
    cpuInfo.push_back(idle);
    cpuInfo.push_back(iowait);
    cpuInfo.push_back(irq);
    cpuInfo.push_back(softirq);
    cpuInfo.push_back(steal);
    cpuInfo.push_back(guest);
    cpuInfo.push_back(guest_nice);

    return cpuInfo;
}

// TODO: Read and return the total number of processes
int LinuxParser::TotalProcesses() {
    const std::string TOTAL_PROCESSES{"processes"};
    std::string line, key, value;
    std::ifstream stream(kProcDirectory + kStatFilename);
    if (stream.is_open()) {
        while (std::getline(stream, line)) {
            std::istringstream linestream(line);
            linestream >> key;
            if (key == TOTAL_PROCESSES) {
                linestream >> value;
            }
        }
    }

    return std::stoi(value); 
}

// TODO: Read and return the number of running processes
int LinuxParser::RunningProcesses() {
    const std::string PROCS_RUNNING{"procs_running"};
    std::string line, key, value;
    std::ifstream stream(kProcDirectory + kStatFilename);
    if (stream.is_open()) {
        while (std::getline(stream, line)) {
            std::istringstream linestream(line);
            linestream >> key;
            if (key == PROCS_RUNNING) {
                linestream >> value;
            }
        }
    }

    return std::stoi(value); 
}
// TODO: Read and return the command associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Command(int pid) { 
    std::string line;
    std::ifstream stream(kProcDirectory + std::to_string(pid) + kCmdlineFilename);
    if (stream.is_open()) {
        std::getline(stream, line);
    }
    return line; 
}

// TODO: Read and return the memory used by a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Ram(int pid) { 
    const string VM_SIZE{"VmSize:"};
    string line, key, vmsize;
    std::ifstream stream(kProcDirectory + std::to_string(pid) + kStatusFilename);
    if (stream.is_open()) {
        while (std::getline(stream, line)) {
            std::istringstream linestream(line);
            linestream >> key;
            if (key == VM_SIZE) {
                linestream >> vmsize;
            }
        }
    }
    return vmsize;
}

// TODO: Read and return the user ID associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Uid(int pid) { 
    const string USER_ID{"Uid:"};
    string line, key, userId;
    std::ifstream stream(kProcDirectory + std::to_string(pid) + kStatusFilename);
    if (stream.is_open()) {
        while (std::getline(stream, line)) {
                std::istringstream linestream(line);
                linestream >> key;
                if (key == USER_ID) {
                    linestream >> userId;
                }
        }
    }
    return userId;
}

// TODO: Read and return the user associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::User(int pid) { 
    string line, tmp, user;
    vector<string> etcTmp;
    std::ifstream stream(kPasswordPath);
    if (stream.is_open()) {
        while (std::getline(stream, line)) {
            std::replace(line.begin(), line.end(), ':', ' ');
            std::istringstream linestream(line);
            while (linestream >> tmp) {
                etcTmp.push_back(tmp);
            }
            
            if (etcTmp[2] == Uid(pid)) {
                user = etcTmp[0];
            }
            etcTmp.clear();
        }
    }

    return user;
}

// TODO: Read and return the uptime of a process
// REMOVE: [[maybe_unused]] once you define the function
long LinuxParser::UpTime(int pid) { 
    string line, tmp;
    vector<string> info;
    std::ifstream stream(kProcDirectory + std::to_string(pid) + kStatFilename);
    if (stream.is_open()) {
        while (std::getline(stream, line)) {
            std::istringstream linestream(line);
            while (linestream >> tmp) {
                info.push_back(tmp);
            }
        }
    }
    return std::stol(info[21]) / sysconf(_SC_CLK_TCK);
}

vector<string> LinuxParser::ProcessorUtilization(int pid) {
    string line, tmp;
    vector<string> info;
    std::ifstream stream(kProcDirectory + std::to_string(pid) + kStatFilename);
    if (stream.is_open()) {
        while (std::getline(stream, line)) {
            std::istringstream linestream(line);
            while (linestream >> tmp) {
                info.push_back(tmp);
            }
        }
    }

    return info;
}
