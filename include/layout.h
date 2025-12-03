#ifndef LAYOUT_H
#define LAYOUT_H

// +--------------+-------------+-------------+-------------------+
// |    0-4096    |  4096-8192  |  8192-20480 |    20480-32768    |
// +--------------+-------------+-------------+-------------------+
// | runtime core | base module |  submodules | high-level module |
// +--------------+-------------+-------------+-------------------+

#define MAIN_MEM_PAGE_SIZE (8 * 4096)

// ----------runtime core-----------

#define LAYOUT_RUNTIME_STRUCT 256
#define LAYOUT_RUNTIME_MODULE 2560

// -----------base module-----------

// Spoof Call & Indirect Syscall
#define LAYOUT_SI_STRUCT 4096
#define LAYOUT_SI_MODULE 5000

// Detector
#define LAYOUT_DT_STRUCT 6000
#define LAYOUT_DT_MODULE 7000

// ------------submodule------------

// Library Tracker
#define LAYOUT_LT_STRUCT 8192
#define LAYOUT_LT_MODULE 9000

// Memory Tracker
#define LAYOUT_MT_STRUCT 10000
#define LAYOUT_MT_MODULE 11000

// Thread Tracker
#define LAYOUT_TT_STRUCT 12000
#define LAYOUT_TT_MODULE 13000

// Resource Tracker
#define LAYOUT_RT_STRUCT 14000
#define LAYOUT_RT_MODULE 15000

// Argument Store
#define LAYOUT_AS_STRUCT 16000
#define LAYOUT_AS_MODULE 16500

// In-memory Storage
#define LAYOUT_IS_STRUCT 17000
#define LAYOUT_IS_MODULE 17500

// --------high-level module--------

// WinBase
#define LAYOUT_WB_STRUCT 20480
#define LAYOUT_WB_METHOD 21000

// WinFile
#define LAYOUT_WF_STRUCT 22000
#define LAYOUT_WF_METHOD 23000

// WinHTTP
#define LAYOUT_WH_STRUCT 24000
#define LAYOUT_WH_METHOD 25000

// WinCrypto
#define LAYOUT_WC_STRUCT 26000
#define LAYOUT_WC_METHOD 27000

// Watchdog
#define LAYOUT_WD_STRUCT 28000
#define LAYOUT_WD_METHOD 28500

// Sysmon
#define LAYOUT_SM_STRUCT 29000
#define LAYOUT_SM_METHOD 29500

#endif // LAYOUT_H
