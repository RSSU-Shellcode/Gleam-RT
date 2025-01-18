IFDEF _WIN32
.model flat
ENDIF

; +---------+----------+-----------+----------+--------+----------+----------+
; |   key   | num args | args size | checksum | arg id | arg size | arg data |
; +---------+----------+-----------+----------+--------+----------+----------+
; | 32 byte |  uint32  |  uint32   |  uint32  | uint32 |  uint32  |   var    |
; +---------+----------+-----------+----------+--------+----------+----------+

.code

IFDEF _WIN32
  _Argument_Stub@0 proc
ELSE
  Argument_Stub proc
ENDIF
  db 0F0h, 0B6h, 099h, 0F6h   ; 32 bytes decrypt key
  db 086h, 080h, 0C4h, 0B4h
  db 068h, 050h, 04Bh, 0CBh
  db 0EBh, 060h, 0BAh, 01Eh
  db 04Ah, 0D7h, 062h, 0B3h
  db 009h, 0DAh, 0A9h, 0F9h
  db 015h, 045h, 0DBh, 07Ah
  db 010h, 047h, 021h, 00Dh
  db 003h, 000h, 000h, 000h   ; record the number of the arguments
  db 028h, 000h, 000h, 000h   ; record the total argument data size
  db 0D0h, 013h, 081h, 094h   ; 4 bytes checksum for check header
  db 030h, 0CFh, 025h, 03Ch   ; record the ID of the argument-1
  db 058h, 0EAh, 029h, 0C3h   ; record the size of the argument-1
  db 096h, 062h, 09Ah, 071h   ; argument-1 data
  db 0BCh, 02Eh, 0D2h, 031h   ; record the ID of the argument-2
  db 089h, 098h, 002h, 019h   ; record the size of the argument-2
  db 081h, 059h, 0C5h, 0B4h   ; argument-2 data
  db 05Fh, 058h, 07Ch, 053h
  db 0BBh, 056h, 07Dh, 0C9h
  db 032h, 0A3h, 005h, 050h   ; record the ID of the argument-3
  db 08Fh, 0E2h, 0B9h, 047h   ; record the size of the argument-3
                              ; argument-3 data (empty)
IFDEF _WIN32
  _Argument_Stub@0 endp
ELSE
  Argument_Stub endp
ENDIF

end
