#ifndef DEBUG_H
#define DEBUG_H

#include "build.h"
#include "c_types.h"

#ifdef RELEASE_MODE
    #define NAME_RT_MUTEX_GLOBAL     NULL
    #define NAME_RT_TIMER_SLEEPHR    NULL
    #define NAME_RT_LT_MUTEX_GLOBAL  NULL
    #define NAME_RT_MT_MUTEX_GLOBAL  NULL
    #define NAME_RT_TT_MUTEX_GLOBAL  NULL
    #define NAME_RT_TT_TIMER_SLEEP   NULL
    #define NAME_RT_RT_MUTEX_GLOBAL  NULL
    #define NAME_RT_AS_MUTEX_GLOBAL  NULL
    #define NAME_RT_IMS_MUTEX_GLOBAL NULL
    #define NAME_RT_WIN_HTTP_MUTEX   NULL
    #define NAME_RT_WIN_CRYPTO_MUTEX NULL
#else
#ifdef _WIN64
    #define NAME_RT_MUTEX_GLOBAL     "x64_RT_Core_Global"
    #define NAME_RT_TIMER_SLEEPHR    "x64_RT_Core_SleepHR"
    #define NAME_RT_LT_MUTEX_GLOBAL  "x64_RT_LT_Global"
    #define NAME_RT_MT_MUTEX_GLOBAL  "x64_RT_MT_Global"
    #define NAME_RT_TT_MUTEX_GLOBAL  "x64_RT_TT_Global"
    #define NAME_RT_TT_TIMER_SLEEP   "x64_RT_TT_Sleep"
    #define NAME_RT_RT_MUTEX_GLOBAL  "x64_RT_RT_Global"
    #define NAME_RT_AS_MUTEX_GLOBAL  "x64_RT_AS_Global"
    #define NAME_RT_IMS_MUTEX_GLOBAL "x64_RT_IMS_Global"
    #define NAME_RT_WIN_HTTP_MUTEX   "x64_RT_WinHTTP"
    #define NAME_RT_WIN_CRYPTO_MUTEX "x64_RT_WinCrypto"
#elif _WIN32
    #define NAME_RT_MUTEX_GLOBAL     "x86_RT_Core_Global"
    #define NAME_RT_TIMER_SLEEPHR    "x86_RT_Core_SleepHR"
    #define NAME_RT_LT_MUTEX_GLOBAL  "x86_RT_LT_Global"
    #define NAME_RT_MT_MUTEX_GLOBAL  "x86_RT_MT_Global"
    #define NAME_RT_TT_MUTEX_GLOBAL  "x86_RT_TT_Global"
    #define NAME_RT_TT_TIMER_SLEEP   "x86_RT_TT_Sleep"
    #define NAME_RT_RT_MUTEX_GLOBAL  "x86_RT_RT_Global"
    #define NAME_RT_AS_MUTEX_GLOBAL  "x86_RT_AS_Global"
    #define NAME_RT_IMS_MUTEX_GLOBAL "x86_RT_IMS_Global"
    #define NAME_RT_WIN_HTTP_MUTEX   "x86_RT_WinHTTP"
    #define NAME_RT_WIN_CRYPTO_MUTEX "x86_RT_WinCrypto"
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
