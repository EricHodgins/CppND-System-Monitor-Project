#include <string>

#include "format.h"

using std::string;

// TODO: Complete this helper function
// INPUT: Long int measuring seconds
// OUTPUT: HH:MM:SS
// REMOVE: [[maybe_unused]] once you define the function
string Format::ElapsedTime(long seconds) { 
    long int tmp = seconds;
    long int hour = tmp / 3600;
    tmp %= 3600;
    long int minutes = tmp / 60;
    tmp %= 60;
    long int sec = tmp;

    return std::to_string(hour) + ":" + std::to_string(minutes) + ":" + std::to_string(sec);
}
