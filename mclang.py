#!/usr/bin/env python3
import sys
import subprocess
import os
from typing import *
from enum import Enum, auto
from dataclasses import dataclass

builtin_lib_path = "./include"

MEMORY_SIZE = 640_000 # should be enough
STR_SIZE = 640_000

class colors:
    RESET      = '\33[0m'
    BOLD       = '\33[1m'
    ITALIC     = '\33[3m'
    UNDERLINE  = '\33[4m'
    BLINK      = '\33[5m'
    BLINK2     = '\33[6m'
    SELECTED   = '\33[7m'

    BLACK      = '\33[30m'
    RED        = '\33[31m'
    GREEN      = '\33[32m'
    YELLOW     = '\33[33m'
    BLUE       = '\33[34m'
    VIOLET     = '\33[35m'
    BEIGE      = '\33[36m'
    WHITE      = '\33[37m'

    BLACKBG    = '\33[40m'
    REDBG      = '\33[41m'
    GREENBG    = '\33[42m'
    YELLOWBG   = '\33[43m'
    BLUEBG     = '\33[44m'
    VIOLETBG   = '\33[45m'
    BEIGEBG    = '\33[46m'
    WHITEBG    = '\33[47m'

    GREY       = '\33[90m'
    RED2       = '\33[91m'
    GREEN2     = '\33[92m'
    YELLOW2    = '\33[93m'
    BLUE2      = '\33[94m'
    VIOLET2    = '\33[95m'
    BEIGE2     = '\33[96m'
    WHITE2     = '\33[97m'

Loc = Tuple[str, int, int]

class OpType(Enum):
    #syscalls
    SYSCALL0 = auto();
    SYSCALL1 = auto();
    SYSCALL2 = auto();
    SYSCALL3 = auto();
    SYSCALL4 = auto();
    SYSCALL5 = auto();
    SYSCALL6 = auto();
    
    # memory ops
    MEM = auto();
    STORE = auto();
    LOAD = auto();
    
    # stack modificating ops
    PUSH_STR = auto();
    PUSH_INT = auto();
    DUP = auto();
    DUP2 = auto();
    SWAP = auto();
    DROP = auto();
    OVER = auto();

    # bitwise ops
    SHR = auto();
    SHL = auto();
    BOR = auto();
    BAND = auto();
    MOD = auto();
    
    # arithmatic ops
    MINUS = auto();
    PLUS = auto();
    MULT = auto();
    DIV = auto();

    # comparison ops
    EQUAL = auto();
    LT = auto();
    GT = auto();
    NE = auto();
    LE = auto();
    GE = auto();

    # Ops that form blocks
    IF = auto();
    ELSE = auto();
    DO = auto();
    END = auto();
    WHILE = auto();
    
    # other
    PRINT = auto();

    # prerocessed ops
    MACRO = auto();
    INCLUDE = auto();

    # bools
    TRUE = auto();
    FALSE = auto();


@dataclass
class Op:
    typ: OpType
    loc: Loc
    # Exists only for PUSH_INT and PUSH_STR
    value: Optional [Union[int, int]] = None
    # Exists only for OPS with blocks
    jmp: Optional [int] = None

Program = List[Op]

class TokenType(Enum):
    WORD = auto();
    INT = auto();
    STR = auto();
    CHAR = auto();

@dataclass
class Token:
    typ: TokenType
    loc: Loc
    value: Union[int, int]

def run_cmd(cmd):
    print("[CMD]: %s" % ' '.join(cmd));
    subprocess.call(cmd);




def simulate_little_endian_linux(program: Program, debug: int):
    stack: List[int] = []
    mem = bytearray(STR_SIZE + MEMORY_SIZE)
    str_offsets = {}
    str_size = 0
    ip = 0
    while ip < len(program):
        assert len(OpType) == 42, "Exhaustive op handling in simulate_little_endian_linux"
        op = program[ip]
        if op.typ == OpType.PUSH_INT:
            assert isinstance(op.value, int), "This could be a bug in the compilation step"
            stack.append(op.value)
            ip += 1
        elif op.typ == OpType.PUSH_STR:
            assert isinstance(op.value, str), "This could be a bug in the compilation step"
            value = op.value.encode('utf-8')
            n = len(value)
            stack.append(n)
            if ip not in str_offsets:
                str_offsets[ip] = str_size
                mem[str_size:str_size+n] = value
                str_size += n
                assert str_size <= STR_SIZE, "String buffer overflow"
            stack.append(str_offsets[ip])
            ip += 1
        elif op.typ == OpType.PLUS:
            a = stack.pop()
            b = stack.pop()
            stack.append(a + b)
            ip += 1
        elif op.typ == OpType.MINUS:
            a = stack.pop()
            b = stack.pop()
            stack.append(b - a)
            ip += 1
        elif op.typ == OpType.TRUE:
            stack.append(1)
            ip += 1
        elif op.typ == OpType.FALSE:
            stack.append(0)
            ip += 1
        elif op.typ == OpType.MULT:
            a = stack.pop()
            b = stack.pop()
            stack.append(b * a)
            ip += 1
        elif op.typ == OpType.DIV:
            a = stack.pop()
            b = stack.pop()
            stack.append(b / a)
            ip += 1
        elif op.typ == OpType.MOD:
            a = stack.pop()
            b = stack.pop()
            stack.append(b % a)
            ip += 1
        elif op.typ == OpType.EQUAL:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(a == b))
            ip += 1
        elif op.typ == OpType.GT:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(b > a))
            ip += 1
        elif op.typ == OpType.LT:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(b < a))
            ip += 1
        elif op.typ == OpType.GE:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(b >= a))
            ip += 1
        elif op.typ == OpType.LE:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(b <= a))
            ip += 1
        elif op.typ == OpType.NE:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(b != a))
            ip += 1
        elif op.typ == OpType.SHR:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(b >> a))
            ip += 1
        elif op.typ == OpType.SHL:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(b << a))
            ip += 1
        elif op.typ == OpType.BOR:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(a | b))
            ip += 1
        elif op.typ == OpType.BAND:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(a & b))
            ip += 1
        elif op.typ == OpType.IF:
            a = stack.pop()
            if a == 0:
                assert op.jmp is not None, "This could be a bug in the compilation step"
                ip = op.jmp
            else:
                ip += 1
        elif op.typ == OpType.ELSE:
            assert op.jmp is not None, "This could be a bug in the compilation step"
            ip = op.jmp
        elif op.typ == OpType.END:
            assert op.jmp is not None, "This could be a bug in the compilation step"
            ip = op.jmp
        elif op.typ == OpType.PRINT:
            a = stack.pop()
            print(a)
            ip += 1
        elif op.typ == OpType.DUP:
            a = stack.pop()
            stack.append(a)
            stack.append(a)
            ip += 1
        elif op.typ == OpType.DUP2:
            b = stack.pop()
            a = stack.pop()
            stack.append(a)
            stack.append(b)
            stack.append(a)
            stack.append(b)
            ip += 1
        elif op.typ == OpType.SWAP:
            a = stack.pop()
            b = stack.pop()
            stack.append(a)
            stack.append(b)
            ip += 1
        elif op.typ == OpType.DROP:
            stack.pop()
            ip += 1
        elif op.typ == OpType.OVER:
            a = stack.pop()
            b = stack.pop()
            stack.append(b)
            stack.append(a)
            stack.append(b)
            ip += 1
        elif op.typ == OpType.WHILE:
            ip += 1
        elif op.typ == OpType.DO:
            a = stack.pop()
            if a == 0:
                assert op.jmp is not None, "This could be a bug in the compilation step"
                ip = op.jmp
            else:
                ip += 1
        elif op.typ == OpType.MEM:
            stack.append(STR_SIZE)
            ip += 1
        elif op.typ == OpType.LOAD:
            addr = stack.pop()
            byte = mem[addr]
            stack.append(byte)
            ip += 1
        elif op.typ == OpType.STORE:
            store_value = stack.pop()
            store_addr = stack.pop()
            mem[store_addr] = store_value & 0xFF
            ip += 1
        elif op.typ == OpType.SYSCALL0:
            syscall_number = stack.pop()
            if syscall_number == 39:
                stack.append(os.getpid())
            else:
                assert False, "unknown syscall number %d" % syscall_number
            ip += 1
        elif op.typ == OpType.SYSCALL1:
            assert False, "not implemented"
        elif op.typ == OpType.SYSCALL2:
            assert False, "not implemented"
        elif op.typ == OpType.SYSCALL3:
            syscall_number = stack.pop()
            arg1 = stack.pop()
            arg2 = stack.pop()
            arg3 = stack.pop()
            if syscall_number == 1:
                fd = arg1
                buf = arg2
                count = arg3
                s = mem[buf:buf+count].decode('utf-8')
                if fd == 1:
                    print(s, end='')
                elif fd == 2:
                    print(s, end='', file=sys.stderr)
                else:
                    assert False, "unknown file descriptor %d" % fd
                stack.append(count)
            else:
                assert False, "unknown syscall number %d" % syscall_number
            ip += 1
        elif op.typ == OpType.SYSCALL4:
            assert False, "not implemented"
        elif op.typ == OpType.SYSCALL5:
            assert False, "not implemented"
        elif op.typ == OpType.SYSCALL6:
            assert False, "not implemented"
        elif op.typ == OpType.MACRO:
            assert False, "Unreachable, all macros should be deleted in parsing"
        else:
            assert False, "unreachable"
    if debug > 1:
        print("[INFO] Memory dump")
        print(mem[:debug])
        print("[INFO] Stack dump")
        print(stack)
        

def generate_nasm_linux_x86_64(program: Program, file_path: str):
    str_arr: List[bytes] = []
    print("[INFO]: Generating %s" % file_path)
    with open(file_path, "w") as out:
        out.write("BITS 64\n")
        out.write("segment .text\n\n")
        out.write("print:\n")
        out.write("    mov     r9, -3689348814741910323\n")
        out.write("    sub     rsp, 40\n")
        out.write("    mov     BYTE [rsp+31], 10\n")
        out.write("    lea     rcx, [rsp+30]\n")
        out.write(".L2:\n")
        out.write("    mov     rax, rdi\n")
        out.write("    lea     r8, [rsp+32]\n")
        out.write("    mul     r9\n")
        out.write("    mov     rax, rdi\n")
        out.write("    sub     r8, rcx\n")
        out.write("    shr     rdx, 3\n")
        out.write("    lea     rsi, [rdx+rdx*4]\n")
        out.write("    add     rsi, rsi\n")
        out.write("    sub     rax, rsi\n")
        out.write("    add     eax, 48\n")
        out.write("    mov     BYTE [rcx], al\n")
        out.write("    mov     rax, rdi\n")
        out.write("    mov     rdi, rdx\n")
        out.write("    mov     rdx, rcx\n")
        out.write("    sub     rcx, 1\n")
        out.write("    cmp     rax, 9\n")
        out.write("    ja      .L2\n")
        out.write("    lea     rax, [rsp+32]\n")
        out.write("    mov     edi, 1\n")
        out.write("    sub     rdx, rax\n")
        out.write("    xor     eax, eax\n")
        out.write("    lea     rsi, [rsp+32+rdx]\n")
        out.write("    mov     rdx, r8\n")
        out.write("    mov     rax, 1\n")
        out.write("    syscall\n")
        out.write("    add     rsp, 40\n")
        out.write("    ret\n")
        out.write("global _start\n")
        out.write("_start:\n")
        for ip in range(len(program)):
            op = program[ip]
            assert len(OpType) == 42, "Exhaustive handling of ops in compilation"
            out.write("addr_%d:\n" % ip)
            if op.typ == OpType.PUSH_INT:
                assert isinstance(op.value, int), "This could be a bug in the compilation step"
                out.write("    ;; -- push int %d --\n" % op.value)
                out.write("    mov rax, %d\n" % op.value)
                out.write("    push rax\n")
            elif op.typ == OpType.PUSH_STR:
                assert isinstance(op.value, str), "This could be a bug in the compilation step"
                value = op.value.encode('utf-8')
                n = len(value)
                out.write("    ;; -- push str--\n")
                out.write("    mov rax, %d\n" % n)
                out.write("    push rax\n")
                out.write("    push str_%d\n" % len(str_arr))
                str_arr.append(value)
            elif op.typ == OpType.PLUS:
                out.write("    ;; -- plus --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    add rax, rbx\n")
                out.write("    push rax\n")
            elif op.typ == OpType.MINUS:
                out.write("    ;; -- minus --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    sub rbx, rax\n")
                out.write("    push rbx\n")
            elif op.typ == OpType.MULT:
                out.write("    ;; -- mult --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    mul rbx\n")
                out.write("    push rax\n")
            elif op.typ == OpType.DIV:
                out.write("    ;; -- div --\n")
                out.write("    pop rbx\n")
                out.write("    pop rax\n")
                out.write("    mov rdx, 0\n")
                out.write("    div rbx\n")
                out.write("    push rax\n")
            elif op.typ == OpType.SHR:
                out.write("    ;; -- shr --\n")
                out.write("    pop rcx\n")
                out.write("    pop rbx\n")
                out.write("    shr rbx, cl\n")
                out.write("    push rbx\n")
            elif op.typ == OpType.SHL:
                out.write("    ;; -- shl --\n")
                out.write("    pop rcx\n")
                out.write("    pop rbx\n")
                out.write("    shl rbx, cl\n")
                out.write("    push rbx\n")
            elif op.typ == OpType.BOR:
                out.write("    ;; -- bor --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    or rbx, rax\n")
                out.write("    push rbx\n")
            elif op.typ == OpType.BAND:
                out.write("    ;; -- band --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    and rbx, rax\n")
                out.write("    push rbx\n")
            elif op.typ == OpType.PRINT:
                out.write("    ;; -- print --\n")
                out.write("    pop rdi\n")
                out.write("    call print\n")
            elif op.typ == OpType.EQUAL:
                out.write("    ;; -- equal -- \n")
                out.write("    mov rcx, 0\n");
                out.write("    mov rdx, 1\n");
                out.write("    pop rax\n");
                out.write("    pop rbx\n");
                out.write("    cmp rax, rbx\n");
                out.write("    cmove rcx, rdx\n");
                out.write("    push rcx\n")
            elif op.typ == OpType.IF:
                out.write("    ;; -- if --\n")
                out.write("    pop rax\n")
                out.write("    test rax, rax\n")
                assert op.jmp is not None, "`if` instruction does not have a reference to the end of its block. Please call compile_tokens_to_program() on the program before trying to compile it"
                out.write("    jz addr_%d\n" % op.jmp)
            elif op.typ == OpType.ELSE:
                out.write("    ;; -- else --\n")
                assert op.jmp is not None, "`else` instruction does not have a reference to the end of its block. Please call compile_tokens_to_program() on the program before trying to compile it"
                out.write("    jmp addr_%d\n" % op.jmp)
            elif op.typ == OpType.END:
                assert op.jmp is not None, "`end` instruction does not have a reference to the next instruction to jump to. Please call compile_tokens_to_program() on the program before trying to compile it"
                out.write("    ;; -- end --\n")
                if ip + 1 != op.jmp:
                    out.write("    jmp addr_%d\n" % op.jmp)
            elif op.typ == OpType.DUP:
                out.write("    ;; -- dup -- \n")
                out.write("    pop rax\n")
                out.write("    push rax\n")
                out.write("    push rax\n")
            elif op.typ == OpType.DUP2:
                out.write("    ;; -- 2dup -- \n")
                out.write("    pop rbx\n")
                out.write("    pop rax\n")
                out.write("    push rax\n")
                out.write("    push rbx\n")
                out.write("    push rax\n")
                out.write("    push rbx\n")
            elif op.typ == OpType.SWAP:
                out.write("    ;; -- swap --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    push rax\n")
                out.write("    push rbx\n")
            elif op.typ == OpType.DROP:
                out.write("    ;; -- drop --\n")
                out.write("    pop rax\n")
            elif op.typ == OpType.GT:
                out.write("    ; -- greater than (>) --\n")
                out.write("    mov rcx, 0\n");
                out.write("    mov rdx, 1\n");
                out.write("    pop rbx\n");
                out.write("    pop rax\n");
                out.write("    cmp rax, rbx\n");
                out.write("    cmovg rcx, rdx\n");
                out.write("    push rcx\n")
            elif op.typ == OpType.LT:
                out.write("    ; -- greater than (>) --\n")
                out.write("    mov rcx, 0\n");
                out.write("    mov rdx, 1\n");
                out.write("    pop rbx\n");
                out.write("    pop rax\n");
                out.write("    cmp rax, rbx\n");
                out.write("    cmovl rcx, rdx\n");
                out.write("    push rcx\n")
            elif op.typ == OpType.WHILE:
                out.write("    ;; -- while --\n")
            elif op.typ == OpType.DO:
                out.write("    ;; -- do --\n")
                out.write("    pop rax\n")
                out.write("    test rax, rax\n")
                assert op.jmp is not None, "This could be a bug in the compilation step"
                out.write("    jz addr_%d\n" % op.jmp)
            elif op.typ == OpType.MEM:
                out.write("    ; -- mem --\n")
                out.write("    push mem\n")
            elif op.typ == OpType.LOAD:
                out.write("    ; -- mem load --\n")
                out.write("    pop rax\n")
                out.write("    xor rbx, rbx\n")
                out.write("    mov bl, [rax]\n")
                out.write("    push rbx\n")
            elif op.typ == OpType.STORE:
                out.write("    ; -- mem store --\n")
                out.write("    pop rbx\n")
                out.write("    pop rax\n")
                out.write("    mov [rax], bl\n")
            elif op.typ == OpType.SYSCALL0:
                out.write("    ;; -- syscall0 --\n")
                out.write("    pop rax\n")
                out.write("    syscall\n")
                out.write("    push rax\n")
            elif op.typ == OpType.SYSCALL1:
                out.write("    ;; -- syscall1 --\n")
                out.write("    pop rax\n")
                out.write("    pop rdi\n")
                out.write("    syscall\n")
                out.write("    push rax\n")
            elif op.typ == OpType.SYSCALL2:
                out.write("    ;; -- syscall2 -- \n")
                out.write("    pop rax\n");
                out.write("    pop rdi\n");
                out.write("    pop rsi\n");
                out.write("    syscall\n");
                out.write("    push rax\n")
            elif op.typ == OpType.SYSCALL3:
                out.write("    ;; -- syscall3 --\n")
                out.write("    pop rax\n")
                out.write("    pop rdi\n")
                out.write("    pop rsi\n")
                out.write("    pop rdx\n")
                out.write("    syscall\n")
                out.write("    push rax\n")
            elif op.typ == OpType.SYSCALL4:
                out.write("    ;; -- syscall4 --\n")
                out.write("    pop rax\n")
                out.write("    pop rdi\n")
                out.write("    pop rsi\n")
                out.write("    pop rdx\n")
                out.write("    pop r10\n")
                out.write("    syscall\n")
                out.write("    push rax\n")
            elif op.typ == OpType.SYSCALL5:
                out.write("    ;; -- syscall5 --\n")
                out.write("    pop rax\n")
                out.write("    pop rdi\n")
                out.write("    pop rsi\n")
                out.write("    pop rdx\n")
                out.write("    pop r10\n")
                out.write("    pop r8\n")
                out.write("    syscall\n")
                out.write("    push rax\n")
            elif op.typ == OpType.SYSCALL6:
                out.write("    ;; -- syscall6 --\n")
                out.write("    pop rax\n")
                out.write("    pop rdi\n")
                out.write("    pop rsi\n")
                out.write("    pop rdx\n")
                out.write("    pop r10\n")
                out.write("    pop r8\n")
                out.write("    pop r9\n")
                out.write("    syscall\n")
                out.write("    push rax\n")
            elif op.typ == OpType.OVER:
                out.write("    ;; -- over --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    push rbx\n")
                out.write("    push rax\n")
                out.write("    push rbx\n")
            elif op.typ == OpType.MOD:
                out.write("    ;; -- mod --\n")
                out.write("    xor rdx, rdx\n")
                out.write("    pop rbx\n")
                out.write("    pop rax\n")
                out.write("    div rbx\n")
                out.write("    push rdx\n");
            elif op.typ == OpType.GE:
                out.write("    ;; -- gt --\n")
                out.write("    mov rcx, 0\n");
                out.write("    mov rdx, 1\n");
                out.write("    pop rbx\n");
                out.write("    pop rax\n");
                out.write("    cmp rax, rbx\n");
                out.write("    cmovge rcx, rdx\n");
                out.write("    push rcx\n")
            elif op.typ == OpType.LE:
                out.write("    ;; -- gt --\n")
                out.write("    mov rcx, 0\n");
                out.write("    mov rdx, 1\n");
                out.write("    pop rbx\n");
                out.write("    pop rax\n");
                out.write("    cmp rax, rbx\n");
                out.write("    cmovle rcx, rdx\n");
                out.write("    push rcx\n")
            elif op.typ == OpType.NE:
                out.write("    ;; -- ne --\n")
                out.write("    mov rcx, 0\n")
                out.write("    mov rdx, 1\n")
                out.write("    pop rbx\n")
                out.write("    pop rax\n")
                out.write("    cmp rax, rbx\n")
                out.write("    cmovne rcx, rdx\n")
                out.write("    push rcx\n")
            elif op.typ == OpType.TRUE:
                out.write("    ;; -- true --\n")
                out.write("    mov rcx, 1\n")
                out.write("    push rcx\n")
            elif op.typ == OpType.FALSE:
                out.write("    ;; -- false --\n")
                out.write("    mov rcx, 0\n")
                out.write("    push rcx\n")

            else:
                print(op.typ)
                assert False, "Unreachable"

        out.write("addr_%d:\n" % len(program))
        out.write("    mov rax, 60\n")
        out.write("    mov rdi, 0\n")
        out.write("    syscall\n")

        out.write("segment .data\n")

        for index, s in enumerate(str_arr):
            out.write("; %s\n" % str(s).encode("unicode_escape").decode("utf-8"))
            out.write("str_%d: db %s" % (index, ",".join(map(hex, list(s))) + "\n\n"))
            
        out.write("segment .bss\n")
        out.write("mem: resb %d\n" % MEMORY_SIZE)




BUILTIN_WORDS = {
                    "+":          OpType.PLUS,
                    "-":          OpType.MINUS,
                    "/":          OpType.DIV,
                    "*":          OpType.MULT,
                    "mod":        OpType.MOD,
                    "print":      OpType.PRINT,
                    "=":          OpType.EQUAL,
                    "if":         OpType.IF,
                    "end":        OpType.END,
                    "else":       OpType.ELSE,
                    "dup":        OpType.DUP,
                    ">":          OpType.GT,
                    "<":          OpType.LT,
                    ">=":         OpType.GE,
                    "<=":         OpType.LE,
                    "!=":         OpType.NE,
                    "while":      OpType.WHILE,
                    "do":         OpType.DO,
                    "mem":        OpType.MEM,
                    "store":      OpType.STORE,
                    "load":       OpType.LOAD,
                    "syscall0":   OpType.SYSCALL0,
                    "syscall1":   OpType.SYSCALL1,
                    "syscall2":   OpType.SYSCALL2,
                    "syscall3":   OpType.SYSCALL3,
                    "syscall4":   OpType.SYSCALL4,
                    "syscall5":   OpType.SYSCALL5,
                    "syscall6":   OpType.SYSCALL6,
                    '>>':         OpType.SHR,
                    '<<':         OpType.SHL,
                    '|':          OpType.BOR,
                    '&':          OpType.BAND,
                    '2dup':       OpType.DUP2,
                    'drop':       OpType.DROP,
                    'over':       OpType.OVER,
                    'swap':       OpType.SWAP,
                    'macro':      OpType.MACRO,
                    'include':    OpType.INCLUDE,
                    'true':    OpType.TRUE,
                    'false':    OpType.FALSE
                }
                              #           \/ push_int and push_str
assert len(OpType) == len(BUILTIN_WORDS) + 2, colors.RED + "Exaustive BUILT_IN_WORDS definitions. Keep in mind that not all of the new words have to be defined here only those that introduce new builtin words" + colors.RESET


@dataclass
class Macro:
    loc: Loc
    tokens: List[Op]

def tokentype_human_readable_name(typ: TokenType) -> str:
    if typ == TokenType.WORD:
        return "word"
    elif typ == TokenType.INT:
        return "int"
    elif typ == TokenType.STR:
        return "string"
    elif typ == TokenType.CHAR:
        return "char"
    else:
        return "UNKNOWN"

def compile_tokens_to_program(tokens: List[Token]) -> Program:
    stack = []
    program = []
    rtokens = list(reversed(tokens))
    macros: Dict[str, Macro] = {}
    ip = 0;
    while len(rtokens) > 0:
        # TODO: some sort of safety mechanism for recursive macros
        token = rtokens.pop()
        op = None
        assert len(TokenType) == 4, "Exhaustive token handling in compile_tokens_to_program"
        if token.typ == TokenType.WORD:
            assert isinstance(token.value, str), "This could be a bug in the lexer"
            if token.value in BUILTIN_WORDS:
                op = Op(typ=BUILTIN_WORDS[token.value], loc=token.loc)
            elif token.value in macros:
                rtokens += reversed(macros[token.value].tokens)
                continue
            else:
                print("%s:%d:%d: unknown word `%s`" % (token.loc + (token.value, )))
                exit(1)
        elif token.typ == TokenType.INT:
            op = Op(typ=OpType.PUSH_INT, value=token.value, loc=token.loc)
        elif token.typ == TokenType.STR:
            op = Op(typ=OpType.PUSH_STR, value=token.value, loc=token.loc)
        elif token.typ == TokenType.CHAR:
            op = Op(typ=OpType.PUSH_INT, value=ord(token.value), loc=token.loc)
        else:
            assert False, 'unreachable'

        assert len(OpType) == 42, "Exhaustive ops handling in compile_tokens_to_program. Keep in mind that not all of the ops need to be handled in here. Only those that form blocks."
        if op.typ == OpType.IF:
            program.append(op)
            stack.append(ip)
            ip += 1
        elif op.typ == OpType.ELSE:
            program.append(op)
            if_ip = stack.pop()
            if program[if_ip].typ != OpType.IF:
                print('%s:%d:%d: ERROR: `else` can only be used in `if`-blocks' % program[if_ip].loc)
                exit(1)
            program[if_ip].jmp = ip + 1
            stack.append(ip)
            ip += 1
        elif op.typ == OpType.END:
            program.append(op)
            block_ip = stack.pop()
            if program[block_ip].typ == OpType.IF or program[block_ip].typ == OpType.ELSE:
                program[block_ip].jmp = ip
                program[ip].jmp = ip + 1
            elif program[block_ip].typ == OpType.DO:
                assert program[block_ip].jmp is not None
                program[ip].jmp = program[block_ip].jmp
                program[block_ip].jmp = ip + 1
            else:
                print('%s:%d:%d: ERROR: `end` can only close `if`, `else` or `do` blocks for now' % program[block_ip].loc)
                exit(1)
            ip += 1
        elif op.typ == OpType.WHILE:
            program.append(op)
            stack.append(ip)
            ip += 1
        elif op.typ == OpType.DO:
            program.append(op)
            while_ip = stack.pop()
            program[ip].jmp = while_ip
            stack.append(ip)
            ip += 1

        elif op.typ == OpType.INCLUDE:
            if len(rtokens) == 0:
                print('%s:%d:%d: ERROR: Expected include file path or a built in library' % op.loc)
                sys.exit(1)

            token = rtokens.pop()
            if token.typ != TokenType.STR:
                print('%s:%d:%d: ERROR: Expected include file path or a built in library path to be a `%s`, but found `%s`' % (op.loc + (
                                                                                                                tokentype_human_readable_name(TokenType.STR),
                                                                                                                tokentype_human_readable_name(token.typ))))
                sys.exit(1)
            path = token.value

            # builtin_lib_path = "./include"

            if "/" in path:
                path = path
            else:
                path = os.path.join(builtin_lib_path, path)

            if not os.path.exists(path):
                print('%s:%d:%d: ERROR: Include file `%s` does not exist' % (op.loc + (path,)))
                sys.exit(1)


            rtokens += reversed(lex_file(path))



        elif op.typ == OpType.MACRO:
            if len(rtokens) == 0:
                print("%s:%d:%d: ERROR: expected macro name but found nothing" % op.loc)
                exit(1)
            token = rtokens.pop()
            if token.typ != TokenType.WORD:
                print("%s:%d:%d: ERROR: expected macro name to be %s but found %s" % (token.loc + (tokentype_human_readable_name(TokenType.WORD), tokentype_human_readable_name(token.typ))))
                exit(1)
            if token.value in macros:
                print("%s:%d:%d: ERROR: redefinition of already existing macro `%s`" % (token.loc + (token.value, )))
                print("%s:%d:%d: NOTE: the first definition is located here" % macros[token.value].loc)
                exit(1)
            if token.value in BUILTIN_WORDS:
                print("%s:%d:%d: ERROR: redefinition of a builtin word `%s`" % (token.loc + (token.value, )))
                exit(1)
            macro = Macro(op.loc, [])
            macros[token.value] = macro

            # TODO: support for nested blocks within the macro definition
            while len(rtokens) > 0:
                token = rtokens.pop()
                if token.typ == TokenType.WORD and token.value == "end":
                    break
                else:
                    macro.tokens.append(token)
            if token.typ != TokenType.WORD or token.value != "end":
                print("%s:%d:%d: ERROR: expected `end` at the end of the macro definition but got `%s`" % (token.loc + (token.value, )))
                exit(1)
        else:
            program.append(op)
            ip += 1

    if len(stack) > 0:
        print('%s:%d:%d: ERROR: unclosed block' % program[stack.pop()].loc)
        exit(1)

    return program

def find_col(line: str, start: int, predicate: Callable[[str], bool]) -> int:
    while start < len(line) and not predicate(line[start]):
        start += 1
    return start

def unescape_string(s: str) -> str:
    # NOTE: unicode_escape assumes latin-1 encoding, so we kinda have
    # to do this weird round trip
    return s.encode('utf-8').decode('unicode_escape').encode('latin-1').decode('utf-8')

def lex_line(file_path: str, row: int, line: str) -> Generator[Token, None, None]:
    col = find_col(line, 0, lambda x: not x.isspace())
    while col < len(line):
        loc = (file_path, row + 1, col + 1)
        col_end = None
        if line[col] == '"':
            col_end = find_col(line, col+1, lambda x: x == '"')
            if col_end >= len(line) or line[col_end] != '"':
                print("%s:%d:%d: ERROR: unclosed string literal" % loc)
                exit(1)
            text_of_token = line[col+1:col_end]
            yield Token(TokenType.STR, loc, unescape_string(text_of_token))
            col = find_col(line, col_end+1, lambda x: not x.isspace())
        elif line[col] == "'":
            col_end = find_col(line, col+1, lambda x: x == "'")
            if col_end >= len(line) or line[col_end] != "'":
                print("%s:%d:%d: ERROR: unclosed char literal" % loc)
                exit(1)
            text_of_token = line[col+1:col_end]
            if len(text_of_token) != 1 and ( not text_of_token.startswith("\\") and len(text_of_token) == 2):
                print("%s:%d:%d: ERROR: char literals can only have 1 character but found %d ('%s')" % (loc + (len(text_of_token),text_of_token)))
                exit(1)


            yield Token(TokenType.CHAR, loc, unescape_string(text_of_token))
            col = find_col(line, col_end+1, lambda x: not x.isspace())
        else:
            col_end = find_col(line, col, lambda x: x.isspace())
            text_of_token = line[col:col_end]
            try:
                yield Token(TokenType.INT, loc, int(text_of_token))
            except ValueError:
                yield Token(TokenType.WORD, loc, text_of_token)
            col = find_col(line, col_end, lambda x: not x.isspace())


def lex_file(file_path: str) -> List[Token]:
    with open(file_path, "r", encoding='utf-8') as f:
        return [token
                for (row, line) in enumerate(f.readlines())
                for token in lex_line(file_path, row, line.split('//')[0])]

def compile_file_to_program(file_path: str) -> Program:
    return compile_tokens_to_program(lex_file(file_path))
        

# simulate_program(program)

def usage(exec):
    print("Usage: %s [SUBCOMMAND] [FLAGS] [FILE]" % exec)
    print("SUBCOMMANDS:")
    print("    c, com, compile                     => Compile the program.")
    print("    s, sim, simulate                    => Simulate/interpret the program.")
    print("FLAGS:")
    print("    -h, --help                          => Show this help text.")
    print("    -r, --run                           => Run the program after compiling. Only relavent in compile mode.")
    print("    -rm, --remove                       => Remove the out.asm and out.o files. Only relavent in compile mode.")
    print("    -o [FILENAME]                       => The name of the compile program.")
    print("    -dm, --dump-memory [DUMP_MEM_SIZE]  => Dump memory from address 0 to [DUMP_MEM_SIZE]. Only relavent in simulate mode.")


def run_compiled_prog(outfile):
    print("Running \"%s\":" % outfile);
    exit_code = subprocess.call(["./" + outfile]);

    if exit_code == 0:
        print("\n{green}Process exited normally.{reset}".format(
                                                red = colors.RED,
                                                green = colors.GREEN,
                                                reset = colors.RESET,
                                                underline = colors.UNDERLINE,
                                                    ))
    else:
        print("\n{red}Process exited abnormally with {underline}{code}{reset}{red} exit code.".format(
                                                                red = colors.RED,
                                                                green = colors.GREEN,
                                                                reset = colors.RESET,
                                                                underline = colors.UNDERLINE,
                                                                code=exit_code
                                                                    ))



def setup_build_env(outfile, build_dir = "build", obj_dir = "build/obj", asm_dir = "build/asm"):
    basepath = ""
    if "/" in outfile:
        basepath = "/".join(outfile.split("/")[:-1]) + "/"

    elif "\\" in outfile:
        assert False, "{red}Windows support is not implemented{reset}".format(
                                                                red = colors.RED,
                                                                green = colors.GREEN,
                                                                reset = colors.RESET,
                                                                underline = colors.UNDERLINE,
                                                                    )
    os.makedirs(basepath + build_dir, exist_ok = True)
    os.makedirs(basepath + obj_dir, exist_ok = True)
    os.makedirs(basepath + asm_dir, exist_ok = True)
        
    return (basepath + build_dir + "/" + outfile.split("/")[-1], 
            basepath + obj_dir + "/" + outfile.split("/")[-1] + ".o", 
            basepath + asm_dir + "/" + outfile.split("/")[-1] + ".asm")

if __name__ == "__main__":
    
    argv = sys.argv
    prog, *argv = argv
    if len(argv) < 1:
        usage(prog);
        print("{red}[ERR]: Not enough arguments. Exiting!{reset}".format(
                                                            red = colors.RED,
                                                            green = colors.GREEN,
                                                            reset = colors.RESET,
                                                            underline = colors.UNDERLINE,
                                                                ))
        sys.exit(1);


    subc, *argv = argv
    input_filepath = ""
    global outfile
    outfile = "output"
    b_run = False
    b_outfile = False
    b_remove = False
    i_dumpmem = 0
    for flag in argv:
        if b_outfile == True:
            b_outfile == False
            
            outfile = flag
            continue
        if i_dumpmem == -1:
            i_dumpmem = int(flag)
            continue

        if flag.startswith("-"):
            if flag == "-h" or flag == "--help":
                usage(prog);
                sys.exit(1);

            elif flag == "-r" or flag == "--run":
                b_run = True
            elif flag == "-o":
                b_outfile = True
            elif flag == "-rm" or flag == "--remove":
                b_noremove = True
            elif flag == "-dm" or flag == "--dump-memory":
                i_dumpmem = -1
            else:
                print("{red}[ERR]: Unknown flag {green}{underline}\"{flag}\"{reset}{red}. Exiting!{reset}".format(
                                                                red = colors.RED,
                                                                green = colors.GREEN,
                                                                reset = colors.RESET,
                                                                underline = colors.UNDERLINE,
                                                                flag=flag
                                                                    ));
                sys.exit(1);
        else:
            input_filepath = flag
        
    if input_filepath == "":
        usage(prog)
        print("{red}[ERR]: No file supplied. Exiting!{reset}".format(
                                                    red = colors.RED,
                                                    green = colors.GREEN,
                                                    reset = colors.RESET,
                                                    underline = colors.UNDERLINE,
                                                        ));
        sys.exit(1)
    outfile = ".".join(input_filepath.split(".")[:-1])

    (build_path, obj_path, asm_path) = setup_build_env(outfile)

    # print(subc)
    if subc == "s" or subc == "sim" or subc == "simulate":

        program = compile_file_to_program(input_filepath);
        simulate_little_endian_linux(program, i_dumpmem)
    elif subc == "c" or subc == "com" or subc == "compile":

        program = compile_file_to_program(input_filepath);
        generate_nasm_linux_x86_64(program, asm_path)
        run_cmd(["nasm", "-felf64", "-o", obj_path, asm_path])
        run_cmd(["ld", "-o", build_path, obj_path])

        if b_remove == True:
            run_cmd(["rm", "-f", asm_path, obj_path])
        if b_run == True:
            run_compiled_prog(build_path)
    else:
        usage(prog);

        print("{red}[ERR]: Unknown subcommand {green}{underline}\"{subcommand}\"{reset}{red}. Exiting!{reset}".format(
                                                                red = colors.RED,
                                                                green = colors.GREEN,
                                                                reset = colors.RESET,
                                                                underline = colors.UNDERLINE,
                                                                subcommand = subc
                                                                    ));
        sys.exit(1);
