IFDEF _WIN32
.model flat
ENDIF

; ===================================== Runtime Options =====================================
;
; bool EnableSecurityMode;  // detect environment when initialize runtime.
; bool DisableDetector;     // disable detector for test or debug.
; bool DisableSysmon;       // disable sysmon for implement single thread model.
; bool DisableWatchdog;     // disable watchdog for implement single thread model.
; bool NotEraseInstruction; // not erase runtime instructions after call Runtime_M.Exit
; bool NotAdjustProtect;    // not adjust current memory page protect for erase runtime
; bool TrackCurrentThread;  // track current thread for some special executable file like Go
;
; ===========================================================================================

.code

IFDEF _WIN32
  _Option_Stub@0 proc
ELSE
  Option_Stub proc
ENDIF

  ; 0xFC is magic for valid
  ; then append options
  db 0FCh, 000h, 000h, 000h

  ; reversed and 16 bytes aligned
  db 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h

  db 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h

  db 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h

  db 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h
  db 000h, 000h, 000h, 000h

IFDEF _WIN32
  _Option_Stub@0 endp
ELSE
  Option_Stub endp
ENDIF

end
