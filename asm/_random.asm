IFDEF _WIN32
.model flat
ENDIF

.code

IFDEF _WIN32

_GenerateSeed@0 proc
  add eax, ecx                  ; store ecx
  pop ecx                       ; read return address
  push ecx                      ; restore return address
  add eax, ecx                  ; add return address

  rol eax, 13
  xor eax, ecx
  add eax, esp
  ror eax, 17
  xor eax, esp

  rol edx, 17
  xor edx, ecx
  add edx, esp
  ror edx, 5
  xor edx, esp

  ; add, xor and ror with other registers
  add eax, ebx
  ror eax, 3
  add eax, ecx
  ror eax, 3
  add eax, edx
  ror eax, 3
  add eax, edi
  ror eax, 3
  add eax, esi
  ror eax, 3
  add eax, ebp
  ror eax, 3
  add eax, esp

  ; build eax with xor shift
  push esi
  mov esi, eax
  rol eax, 13
  xor eax, esi
  mov esi, eax
  ror eax, 17
  xor eax, esi
  mov esi, eax
  rol eax, 5
  xor eax, esi
  pop esi

  ; build edx with xor shift
  mov edx, eax
  rol edx, 13
  xor edx, eax
  ror edx, 17
  xor edx, eax
  rol edx, 5

  ret
_GenerateSeed@0 endp

ELSE

GenerateSeed proc
  add rax, rcx                 ; store rcx
  pop rcx                      ; read return address
  push rcx                     ; restore return address
  add rax, rcx                 ; add return address
  imul rax, rsp                ; rax * rsp
  add rax, rsp                 ; add rsp

  ; add and ror rax with other registers
  add rax, rbx
  ror rax, 16
  add rax, rcx
  ror rax, 15
  add rax, rdx
  ror rax, 14
  add rax, rdi
  ror rax, 13
  add rax, rsi
  ror rax, 12
  add rax, rbp
  ror rax, 11
  add rax, rsp
  ror rax, 10

  add rax, r8
  ror rax, 8
  add rax, r9
  ror rax, 16
  add rax, r10
  ror rax, 24
  add rax, r11
  ror rax, 32
  add rax, r12
  ror rax, 4
  add rax, r13
  ror rax, 8
  add rax, r14
  ror rax, 12
  add rax, r15
  ror rax, 16

  ; active destroy volatile registers for
  ; cooperate with the previous step
  add rax, 1024
  xor rcx, rax
  add rax, 2048
  xor rdx, rax
  add rax, 4096
  xor r8, rax
  add rax, 8192
  xor r9, rax

  ; build rax with xor shift
  mov rcx, rax
  rol rax, 13
  xor rax, rcx
  mov rcx, rax
  ror rax, 7
  xor rax, rcx
  mov rcx, rax
  rol rax, 17
  xor rax, rcx
  ret
GenerateSeed endp

ENDIF

end
