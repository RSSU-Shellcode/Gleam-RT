#ifndef DEBUG_H
#define DEBUG_H

#include "build.h"
#include "c_types.h"

#ifdef RELEASE_MODE
    #define NAME_RT_MUTEX_GLOBAL  NULL
    #define NAME_RT_TIMER_SLEEPHR NULL
    #define NAME_TT_TIMER_SLEEP   NULL
#else
#ifdef _WIN64
    #define NAME_RT_MUTEX_GLOBAL  "x64_RT_Core_Global"
    #define NAME_RT_TIMER_SLEEPHR "x64_RT_Core_SleepHR"
    #define NAME_TT_TIMER_SLEEP   "x64_RT_TT_Sleep"
#elif _WIN32
    #define NAME_RT_MUTEX_GLOBAL  "x86_RT_Core_Global"
    #define NAME_RT_TIMER_SLEEPHR "x86_RT_Core_SleepHR"
    #define NAME_TT_TIMER_SLEEP   "x86_RT_TT_Sleep"
#endif
#endif // RELEASE_MODE

// for test PE Loader
#ifdef RELEASE_MODE
    #define NAME_LDR_MUTEX_GLOBAL NULL
    #define NAME_LDR_MUTEX_STATUS NULL
#else
#ifdef _WIN64
    #define NAME_LDR_MUTEX_GLOBAL "x64_LDR_Global"
    #define NAME_LDR_MUTEX_STATUS "x64_LDR_Status"
#elif _WIN32
    #define NAME_LDR_MUTEX_GLOBAL "x86_LDR_Global"
    #define NAME_LDR_MUTEX_STATUS "x86_LDR_Status"
#endif
#endif // RELEASE_MODE

#ifndef RELEASE_MODE

bool InitDebugger();

void dbg_log(char* mod, char* fmt, ...);

#else

#define InitDebugger() (true)

#define dbg_log(mod, fmt, ...)

#endif // RELEASE_MODE

#endif // DEBUG_H
