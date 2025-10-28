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
    #define NAME_RT_IS_MUTEX_GLOBAL  NULL
    #define NAME_RT_WIN_HTTP_MUTEX   NULL
    #define NAME_RT_WIN_CRYPTO_MUTEX NULL
    #define NAME_RT_SM_MUTEX_GLOBAL  NULL
    #define NAME_RT_SM_MUTEX_STATUS  NULL
    #define NAME_RT_SM_EVENT_STOP    NULL
    #define NAME_RT_SM_TIMER_SLEEP   NULL
    #define NAME_RT_WD_MUTEX_GLOBAL  NULL
    #define NAME_RT_WD_MUTEX_STATUS  NULL
    #define NAME_RT_WD_EVENT_STOP    NULL
    #define NAME_RT_WD_TIMER_SLEEP   NULL
#else
#ifdef _WIN64
    #define NAME_RT_MUTEX_GLOBAL     "RT_Core_Global-x64"
    #define NAME_RT_TIMER_SLEEPHR    "RT_Core_SleepHR-x64"
    #define NAME_RT_LT_MUTEX_GLOBAL  "RT_LibraryTracker_Global-x64"
    #define NAME_RT_MT_MUTEX_GLOBAL  "RT_MemoryTracker_Global-x64"
    #define NAME_RT_TT_MUTEX_GLOBAL  "RT_ThreadTracker_Global-x64"
    #define NAME_RT_TT_TIMER_SLEEP   "RT_ThreadTracker_Sleep-x64"
    #define NAME_RT_RT_MUTEX_GLOBAL  "RT_ResourceTracker_Global-x64"
    #define NAME_RT_AS_MUTEX_GLOBAL  "RT_ArgumentStore_Global-x64"
    #define NAME_RT_IS_MUTEX_GLOBAL  "RT_InMemoryStorage_Global-x64"
    #define NAME_RT_WIN_HTTP_MUTEX   "RT_WinHTTP-x64"
    #define NAME_RT_WIN_CRYPTO_MUTEX "RT_WinCrypto-x64"
    #define NAME_RT_SM_MUTEX_GLOBAL  "RT_Sysmon_Global-x64"
    #define NAME_RT_SM_MUTEX_STATUS  "RT_Sysmon_Status-x64"
    #define NAME_RT_SM_EVENT_STOP    "RT_Sysmon_Stop-x64"
    #define NAME_RT_SM_TIMER_SLEEP   "RT_Sysmon_Sleep-x64"
    #define NAME_RT_WD_MUTEX_GLOBAL  "RT_Watchdog_Global-x64"
    #define NAME_RT_WD_MUTEX_STATUS  "RT_Watchdog_Status-x64"
    #define NAME_RT_WD_EVENT_STOP    "RT_Watchdog_Stop-x64"
    #define NAME_RT_WD_TIMER_SLEEP   "RT_Watchdog_Sleep-x64"
#elif _WIN32
    #define NAME_RT_MUTEX_GLOBAL     "RT_Core_Global-x86"
    #define NAME_RT_TIMER_SLEEPHR    "RT_Core_SleepHR-x86"
    #define NAME_RT_LT_MUTEX_GLOBAL  "RT_LibraryTracker_Global-x86"
    #define NAME_RT_MT_MUTEX_GLOBAL  "RT_MemoryTracker_Global-x86"
    #define NAME_RT_TT_MUTEX_GLOBAL  "RT_ThreadTracker_Global-x86"
    #define NAME_RT_TT_TIMER_SLEEP   "RT_ThreadTracker_Sleep-x86"
    #define NAME_RT_RT_MUTEX_GLOBAL  "RT_ResourceTracker_Global-x86"
    #define NAME_RT_AS_MUTEX_GLOBAL  "RT_ArgumentStore_Global-x86"
    #define NAME_RT_IS_MUTEX_GLOBAL  "RT_InMemoryStorage_Global-x86"
    #define NAME_RT_WIN_HTTP_MUTEX   "RT_WinHTTP-x86"
    #define NAME_RT_WIN_CRYPTO_MUTEX "RT_WinCrypto-x86"
    #define NAME_RT_SM_MUTEX_GLOBAL  "RT_Sysmon_Global-x86"
    #define NAME_RT_SM_MUTEX_STATUS  "RT_Sysmon_Status-x86"
    #define NAME_RT_SM_EVENT_STOP    "RT_Sysmon_Stop-x86"
    #define NAME_RT_SM_TIMER_SLEEP   "RT_Sysmon_Sleep-x86"
    #define NAME_RT_WD_MUTEX_GLOBAL  "RT_Watchdog_Global-x86"
    #define NAME_RT_WD_MUTEX_STATUS  "RT_Watchdog_Status-x86"
    #define NAME_RT_WD_EVENT_STOP    "RT_Watchdog_Stop-x86"
    #define NAME_RT_WD_TIMER_SLEEP   "RT_Watchdog_Sleep-x86"
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
