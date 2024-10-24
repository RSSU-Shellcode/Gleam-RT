#ifndef ERRNO_H
#define ERRNO_H

#include "c_types.h"

typedef uint32 errno;

void  SetLastErrno(errno errno);
errno GetLastErrno();

// 00，，，，，， module id
// ，，00，，，， error flags
// ，，，，00，， major error id
// ，，，，，，00 minor error id

#define NO_ERROR 0x00000000

#define ERR_FLAG_CAN_IGNORE 0x00010000

#define ERR_RUNTIME_INIT_DEBUGGER       (0xFF000001)
#define ERR_RUNTIME_INVALID_ARGS_STUB   (0xFF000002)
#define ERR_RUNTIME_ALLOC_MEMORY        (0xFF000003)
#define ERR_RUNTIME_INIT_API            (0xFF000004)
#define ERR_RUNTIME_ADJUST_PROTECT      (0xFF000005)
#define ERR_RUNTIME_RECOVER_PROTECT     (0xFF000006)
#define ERR_RUNTIME_UPDATE_PTR          (0xFF000007)
#define ERR_RUNTIME_INIT_IAT_HOOKS      (0xFF000008)
#define ERR_RUNTIME_FLUSH_INST          (0xFF000009)
#define ERR_RUNTIME_START_EVENT_HANDLER (0xFF00000A)

#define ERR_RUNTIME_CREATE_GLOBAL_MUTEX (0xFF000101)
#define ERR_RUNTIME_CREATE_SLEEP_MUTEX  (0xFF000102)
#define ERR_RUNTIME_CREATE_EVENT_ARRIVE (0xFF000103)
#define ERR_RUNTIME_CREATE_EVENT_DONE   (0xFF000104)
#define ERR_RUNTIME_CREATE_EVENT_MUTEX  (0xFF000105)

#define ERR_RUNTIME_LOCK            (0xFF000201)
#define ERR_RUNTIME_UNLOCK          (0xFF000202)
#define ERR_RUNTIME_LOCK_LIBRARY    (0xFF000203)
#define ERR_RUNTIME_LOCK_MEMORY     (0xFF000204)
#define ERR_RUNTIME_LOCK_THREAD     (0xFF000205)
#define ERR_RUNTIME_LOCK_RESOURCE   (0xFF000206)
#define ERR_RUNTIME_LOCK_ARGUMENT   (0xFF000207)
#define ERR_RUNTIME_LOCK_WIN_HTTP   (0xFF000208)
#define ERR_RUNTIME_UNLOCK_LIBRARY  (0xFF000209)
#define ERR_RUNTIME_UNLOCK_MEMORY   (0xFF00020A)
#define ERR_RUNTIME_UNLOCK_THREAD   (0xFF00020B)
#define ERR_RUNTIME_UNLOCK_RESOURCE (0xFF00020C)
#define ERR_RUNTIME_UNLOCK_ARGUMENT (0xFF00020D)
#define ERR_RUNTIME_UNLOCK_WIN_HTTP (0xFF00020E)

#define ERR_RUNTIME_LOCK_SLEEP           (0xFF000301)
#define ERR_RUNTIME_UNLOCK_SLEEP         (0xFF000302)
#define ERR_RUNTIME_LOCK_EVENT           (0xFF000303)
#define ERR_RUNTIME_UNLOCK_EVENT         (0xFF000304)
#define ERR_RUNTIME_NOTICE_EVENT_HANDLER (0xFF000305)
#define ERR_RUNTIME_WAIT_EVENT_HANDLER   (0xFF000306)
#define ERR_RUNTIME_RESET_EVENT          (0xFF000307)

#define ERR_RUNTIME_CREATE_WAITABLE_TIMER (0xFF000401)
#define ERR_RUNTIME_SET_WAITABLE_TIMER    (0xFF000402)
#define ERR_RUNTIME_DEFENSE_RT            (0xFF000403)
#define ERR_RUNTIME_FLUSH_INST_CACHE      (0xFF000404)
#define ERR_RUNTIME_CLOSE_WAITABLE_TIMER  (0xFF000405)

#define ERR_RUNTIME_EXIT_EVENT_HANDLER    (0xFF00FF01)
#define ERR_RUNTIME_CLEAN_H_MUTEX         (0xFF00FF02)
#define ERR_RUNTIME_CLEAN_H_MUTEX_SLEEP   (0xFF00FF03)
#define ERR_RUNTIME_CLEAN_H_EVENT_ARRIVE  (0xFF00FF04)
#define ERR_RUNTIME_CLEAN_H_EVENT_DONE    (0xFF00FF05)
#define ERR_RUNTIME_CLEAN_H_MUTEX_EVENT   (0xFF00FF06)
#define ERR_RUNTIME_CLEAN_H_EVENT_HANDLER (0xFF00FF07)
#define ERR_RUNTIME_CLEAN_FREE_MEM        (0xFF00FF08)
#define ERR_RUNTIME_EXIT_RECOVER_INST     (0xFF00FF09)

#define ERR_LIBRARY_INIT_API      (0xC1000001)
#define ERR_LIBRARY_UPDATE_PTR    (0xC1000002)
#define ERR_LIBRARY_INIT_ENV      (0xC1000003)
#define ERR_LIBRARY_CLEAN_MODULE  (0xC100FF01|ERR_FLAG_CAN_IGNORE)
#define ERR_LIBRARY_DELETE_MODULE (0xC100FF02|ERR_FLAG_CAN_IGNORE)
#define ERR_LIBRARY_FREE_LIST     (0xC100FF03|ERR_FLAG_CAN_IGNORE)
#define ERR_LIBRARY_CLOSE_MUTEX   (0xC100FF04|ERR_FLAG_CAN_IGNORE)
#define ERR_LIBRARY_RECOVER_INST  (0xC100FF05|ERR_FLAG_CAN_IGNORE)

#define ERR_MEMORY_INIT_API         (0xC2000001)
#define ERR_MEMORY_UPDATE_PTR       (0xC2000002)
#define ERR_MEMORY_INIT_ENV         (0xC2000003)
#define ERR_MEMORY_ENCRYPT_PAGE     (0xC2000004)
#define ERR_MEMORY_DECRYPT_PAGE     (0xC2000005)
#define ERR_MEMORY_CLEAN_PAGE       (0xC200FF01|ERR_FLAG_CAN_IGNORE)
#define ERR_MEMORY_CLEAN_REGION     (0xC200FF02|ERR_FLAG_CAN_IGNORE)
#define ERR_MEMORY_DELETE_PAGE      (0xC200FF03|ERR_FLAG_CAN_IGNORE)
#define ERR_MEMORY_DELETE_REGION    (0xC200FF04|ERR_FLAG_CAN_IGNORE)
#define ERR_MEMORY_FREE_PAGE_LIST   (0xC200FF05|ERR_FLAG_CAN_IGNORE)
#define ERR_MEMORY_FREE_REGION_LIST (0xC200FF06|ERR_FLAG_CAN_IGNORE)
#define ERR_MEMORY_CLOSE_MUTEX      (0xC200FF07|ERR_FLAG_CAN_IGNORE)
#define ERR_MEMORY_RECOVER_INST     (0xC200FF08|ERR_FLAG_CAN_IGNORE)

#define ERR_THREAD_INIT_API        (0xC3000001)
#define ERR_THREAD_UPDATE_PTR      (0xC3000002)
#define ERR_THREAD_INIT_ENV        (0xC3000003)
#define ERR_THREAD_GET_CURRENT_TID (0xC3000004)
#define ERR_THREAD_SUSPEND         (0xC3000005|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_RESUME          (0xC3000006|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_TERMINATE       (0xC3000007|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_WAIT_TERMINATE  (0xC3000008|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_DELETE_THREAD   (0xC3000101|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_CLOSE_HANDLE    (0xC300FF01|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_FREE_LIST       (0xC300FF02|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_CLOSE_MUTEX     (0xC300FF03|ERR_FLAG_CAN_IGNORE)
#define ERR_THREAD_RECOVER_INST    (0xC300FF04|ERR_FLAG_CAN_IGNORE)

#define ERR_RESOURCE_INIT_API         (0xC4000001)
#define ERR_RESOURCE_UPDATE_PTR       (0xC4000002)
#define ERR_RESOURCE_INIT_ENV         (0xC4000003)
#define ERR_RESOURCE_CLOSE_HANDLE     (0xC400FF01|ERR_FLAG_CAN_IGNORE)
#define ERR_RESOURCE_FIND_CLOSE       (0xC400FF02|ERR_FLAG_CAN_IGNORE)
#define ERR_RESOURCE_INVALID_SRC_TYPE (0xC400FF03|ERR_FLAG_CAN_IGNORE)
#define ERR_RESOURCE_FREE_HANDLE_LIST (0xC400FF04|ERR_FLAG_CAN_IGNORE)
#define ERR_RESOURCE_WSA_CLEANUP      (0xC400FF05|ERR_FLAG_CAN_IGNORE)
#define ERR_RESOURCE_CLOSE_MUTEX      (0xC400FF06|ERR_FLAG_CAN_IGNORE)
#define ERR_RESOURCE_RECOVER_INST     (0xC400FF07|ERR_FLAG_CAN_IGNORE)

#define ERR_ARGUMENT_INIT_API     (0xC5000001)
#define ERR_ARGUMENT_UPDATE_PTR   (0xC5000002)
#define ERR_ARGUMENT_INIT_ENV     (0xC5000003)
#define ERR_ARGUMENT_ALLOC_MEM    (0xC5000004)
#define ERR_ARGUMENT_FREE_MEM     (0xC500FF01|ERR_FLAG_CAN_IGNORE)
#define ERR_ARGUMENT_CLOSE_MUTEX  (0xC500FF02|ERR_FLAG_CAN_IGNORE)
#define ERR_ARGUMENT_RECOVER_INST (0xC500FF03|ERR_FLAG_CAN_IGNORE)

#define ERR_WIN_BASE_INIT_API     (0xE1000001)
#define ERR_WIN_BASE_UPDATE_PTR   (0xE1000002)
#define ERR_WIN_BASE_INIT_ENV     (0xE1000003)
#define ERR_WIN_BASE_RECOVER_INST (0xE100FF01|ERR_FLAG_CAN_IGNORE)

#define ERR_WIN_FILE_INIT_API     (0xE2000001)
#define ERR_WIN_FILE_UPDATE_PTR   (0xE2000002)
#define ERR_WIN_FILE_INIT_ENV     (0xE2000003)
#define ERR_WIN_FILE_RECOVER_INST (0xE200FF01|ERR_FLAG_CAN_IGNORE)

#define ERR_WIN_HTTP_INIT_API     (0xE3000001)
#define ERR_WIN_HTTP_UPDATE_PTR   (0xE3000002)
#define ERR_WIN_HTTP_INIT_ENV     (0xE3000003)
#define ERR_WIN_HTTP_FREE_LIBRARY (0xE300FF01|ERR_FLAG_CAN_IGNORE)
#define ERR_WIN_HTTP_CLOSE_MUTEX  (0xE300FF02|ERR_FLAG_CAN_IGNORE)
#define ERR_WIN_HTTP_RECOVER_INST (0xE300FF03|ERR_FLAG_CAN_IGNORE)

#endif // ERRNO_H
