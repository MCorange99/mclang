#!/usr/bin/env python3
from copy import copy
from pathlib import Path, PurePath
import sys
import subprocess
import os
from typing import *
from enum import Enum, IntEnum, auto
from dataclasses import dataclass
import traceback
from time import sleep
import time
import re

builtin_lib_path = ["./include"]

SIM_STR_CAPACITY = 640_000
SIM_ARGV_CAPACITY = 640_000
MAX_MACRO_EXPANSION = 1000
SIM_NULL_POINTER_PADDING = 1
AT_FDCWD=-100
O_RDONLY=0
ENOENT=2
CLOCK_MONOTONIC=1

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


def eprint(txt, loc=None):
    if loc != None:
        print("{red}{lnk}{fn}{rs}{green}:{red}{lnk}{ln}{rs}{green}:{red}{lnk}{col}{rs} {green}[{red}ERR{green}]{rs}: {red}{text}{rs}".format(
            fn = loc[0],
            ln = loc[1],
            col= loc[2],
            text=txt,
            red=colors.RED,
            green=colors.GREEN,
            lnk=colors.UNDERLINE,
            rs=colors.RESET
        ), file=sys.stderr)
    else:
        print("{green}[{red}ERR{green}]{rs}: {red}{text}{rs}".format(
            text=txt,
            red=colors.RED,
            green=colors.GREEN,
            lnk=colors.UNDERLINE,
            rs=colors.RESET
        ), file=sys.stderr)

def nprint(txt):
    print("{green}[{blue}NOTE{blue}]{rs}: {blue}{text}{rs}".format(
            text=txt,
            blue=colors.BLUE,
            green=colors.GREEN,
            lnk=colors.UNDERLINE,
            rs=colors.RESET
        ))

def not_enough_arguments(op):
    if op.typ == OpType.INTRINSIC:
        assert isinstance(op.operand, Intrinsic)
        eprint("not enough arguments for the `%s` intrinsic" % INTRINSIC_NAMES[op.operand], op.token.loc)
    elif op.typ == OpType.IF:
        eprint("not enough arguments for the if-block", op.token.loc)
    else:
        assert False, "unsupported type of operation"

def compiler_error(loc, txt):
    eprint(txt, loc.loc)

def compiler_note(loc, txt):
    nprint(txt)

Loc = Tuple[str, int, int]

class Keyword(Enum):

    # Ops that form blocks
    IF = auto();
    ELSE = auto();
    ELIF = auto();
    DO = auto();
    END = auto();
    WHILE = auto();
    MACRO = auto();
    MEMORY = auto();

    #other
    INCLUDE = auto();

class Intrinsic(Enum):
    # arithmatices
    PLUS=auto()
    MINUS=auto()
    MUL=auto()
    DIVMOD=auto()
    EQ=auto()
    GT=auto()
    LT=auto()
    GE=auto()
    LE=auto()
    NE=auto()
    SHR=auto()
    SHL=auto()
    OR=auto()
    AND=auto()
    NOT=auto()
    PRINT=auto()

    # stack ops
    DUP=auto()
    SWAP=auto()
    DROP=auto()
    OVER=auto()
    ROT=auto()

    # memory
    LOAD8=auto()
    STORE8=auto()
    LOAD16=auto()
    STORE16=auto()
    LOAD32=auto()
    STORE32=auto()
    LOAD64=auto()
    STORE64=auto()

    # syscalls
    SYSCALL0=auto()
    SYSCALL1=auto()
    SYSCALL2=auto()
    SYSCALL3=auto()
    SYSCALL4=auto()
    SYSCALL5=auto()
    SYSCALL6=auto()

    # other
    ARGC=auto()
    ARGV=auto()
    CAST_PTR=auto()
    CAST_INT=auto()
    CAST_BOOL=auto()
    HERE=auto()

class OpType(Enum):
    PUSH_INT=auto()
    PUSH_MEM=auto()
    PUSH_STR=auto()
    PUSH_CSTR=auto()
    INTRINSIC=auto()
    IF=auto()
    END=auto()
    ELSE=auto()
    ELIF = auto();
    WHILE=auto()
    DO=auto()

OpAddr = int
class TokenType(Enum):
    WORD = auto();
    INT = auto();
    STR = auto();
    CSTR = auto();
    CHAR = auto();
    KEYWORD = auto();

@dataclass
class Token:
    typ: TokenType
    text: str
    loc: Loc
    value: Union[int, str, Keyword]
    # https://www.python.org/dev/peps/pep-0484/#forward-references
    expanded_from: Optional['Token'] = None
    expanded_count: int = 0
@dataclass
class Op:
    typ: OpType
    token: Token
    operand: Optional[Union[int, str, Intrinsic, OpAddr]] = None

@dataclass
class Program:
    ops: List[Op]
    memory_capacity: int


def run_cmd(cmd, silent=False):
    if silent != True:
        print("[CMD]: %s" % ' '.join(cmd));
    subprocess.call(cmd);


def get_cstr_from_mem(mem: bytearray, ptr: int) -> bytes:
    end = ptr
    while mem[end] != 0:
        end += 1
    return mem[ptr:end]

def simulate_little_endian_linux(program: Program, debug: int, argv: List[str]):

    AT_FDCWD=-100
    O_RDONLY=0
    ENOENT=2
    CLOCK_MONOTONIC=1

    stack: List[int] = []
    mem = bytearray(SIM_NULL_POINTER_PADDING + SIM_STR_CAPACITY + SIM_ARGV_CAPACITY + program.memory_capacity)

    str_buf_ptr  = SIM_NULL_POINTER_PADDING
    str_ptrs: Dict[int, int] = {}
    str_size = 0

    argv_buf_ptr = SIM_NULL_POINTER_PADDING + SIM_STR_CAPACITY
    argc = 0

    mem_buf_ptr  = SIM_NULL_POINTER_PADDING + SIM_STR_CAPACITY + SIM_ARGV_CAPACITY

    fds: List[BinaryIO] = [sys.stdin.buffer, sys.stdout.buffer, sys.stderr.buffer]

    for arg in argv:
        value = arg.encode('utf-8')
        n = len(value)

        arg_ptr = str_buf_ptr + str_size
        mem[arg_ptr:arg_ptr+n] = value
        mem[arg_ptr+n] = 0
        str_size += n + 1
        assert str_size <= SIM_STR_CAPACITY, "String buffer overflow"

        argv_ptr = argv_buf_ptr+argc*8
        mem[argv_ptr:argv_ptr+8] = arg_ptr.to_bytes(8, byteorder='little')
        argc += 1
        assert argc*8 <= SIM_ARGV_CAPACITY, "Argv buffer, overflow"

    ip = 0
    while ip < len(program.ops):
        assert len(OpType) == 11, "Exhaustive op handling in simulate_little_endian_linux"
        op = program.ops[ip]
        try:
            if op.typ == OpType.PUSH_INT:
                assert isinstance(op.operand, int), "This could be a bug in the compilation step"
                stack.append(op.operand)
                ip += 1
            elif op.typ == OpType.PUSH_STR:
                assert isinstance(op.operand, str), "This could be a bug in the compilation step"
                value = op.operand.encode('utf-8')
                n = len(value)
                stack.append(n)
                if ip not in str_ptrs:
                    str_ptr = str_buf_ptr+str_size
                    str_ptrs[ip] = str_ptr
                    mem[str_ptr:str_ptr+n] = value
                    str_size += n
                    assert str_size <= SIM_STR_CAPACITY, "String buffer overflow"
                stack.append(str_ptrs[ip])
                ip += 1
            elif op.typ == OpType.PUSH_CSTR:
                assert isinstance(op.operand, str), "This could be a bug in the parsing step"
                value = op.operand.encode('utf-8') + b'\0'
                n = len(value)
                if ip not in str_ptrs:
                    str_ptr = str_buf_ptr+str_size
                    str_ptrs[ip] = str_ptr
                    mem[str_ptr:str_ptr+n] = value
                    str_size += n
                    assert str_size <= SIM_STR_CAPACITY, "String buffer overflow"
                stack.append(str_ptrs[ip])
                ip += 1
            elif op.typ == OpType.PUSH_MEM:
                stack.append(mem_buf_ptr + op.operand)
                ip += 1
            elif op.typ == OpType.IF:
                ip += 1
            elif op.typ == OpType.WHILE:
                ip += 1
            elif op.typ == OpType.ELSE:
                assert isinstance(op.operand, OpAddr), "This could be a bug in the parsing step"
                ip = op.operand
            elif op.typ == OpType.ELIF:
                assert isinstance(op.operand, OpAddr), "This could be a bug in the parsing step"
                ip = op.operand
            elif op.typ == OpType.END:
                assert isinstance(op.operand, OpAddr), "This could be a bug in the parsing step"
                ip = op.operand
            elif op.typ == OpType.DO:
                a = stack.pop()
                if a == 0:
                    assert isinstance(op.operand, OpAddr), "This could be a bug in the parsing step"
                    ip = op.operand
                else:
                    ip += 1
            elif op.typ == OpType.INTRINSIC:
                assert len(Intrinsic) == 42, "Exhaustive handling of intrinsic in simulate_little_endian_linux() " + str(len(Intrinsic)) 
                if op.operand == Intrinsic.PLUS:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(a + b)
                    ip += 1
                elif op.operand == Intrinsic.MINUS:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(b - a)
                    ip += 1
                elif op.operand == Intrinsic.MUL:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(b * a)
                    ip += 1
                elif op.operand == Intrinsic.DIVMOD:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(b // a)
                    stack.append(b % a)
                    ip += 1
                elif op.operand == Intrinsic.EQ:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(int(a == b))
                    ip += 1
                elif op.operand == Intrinsic.GT:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(int(b > a))
                    ip += 1
                elif op.operand == Intrinsic.LT:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(int(b < a))
                    ip += 1
                elif op.operand == Intrinsic.GE:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(int(b >= a))
                    ip += 1
                elif op.operand == Intrinsic.LE:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(int(b <= a))
                    ip += 1
                elif op.operand == Intrinsic.NE:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(int(b != a))
                    ip += 1
                elif op.operand == Intrinsic.SHR:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(int(b >> a))
                    ip += 1
                elif op.operand == Intrinsic.SHL:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(int(b << a))
                    ip += 1
                elif op.operand == Intrinsic.OR:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(int(a | b))
                    ip += 1
                elif op.operand == Intrinsic.AND:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(int(a & b))
                    ip += 1
                elif op.operand == Intrinsic.NOT:
                    a = stack.pop()
                    stack.append(int(~a))
                    ip += 1
                elif op.operand == Intrinsic.PRINT:
                    a = stack.pop()
                    fds[1].write(b"%d\n" % a)
                    fds[1].flush()
                    ip += 1
                elif op.operand == Intrinsic.DUP:
                    a = stack.pop()
                    stack.append(a)
                    stack.append(a)
                    ip += 1
                elif op.operand == Intrinsic.SWAP:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(a)
                    stack.append(b)
                    ip += 1
                elif op.operand == Intrinsic.DROP:
                    stack.pop()
                    ip += 1
                elif op.operand == Intrinsic.OVER:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(b)
                    stack.append(a)
                    stack.append(b)
                    ip += 1
                elif op.operand == Intrinsic.ROT:
                    a = stack.pop()
                    b = stack.pop()
                    c = stack.pop()
                    stack.append(b)
                    stack.append(a)
                    stack.append(c)
                    ip += 1
                elif op.operand == Intrinsic.LOAD8:
                    addr = stack.pop()
                    byte = mem[addr]
                    stack.append(byte)
                    ip += 1
                elif op.operand == Intrinsic.STORE8:
                    store_addr = stack.pop()
                    store_value = stack.pop()
                    mem[store_addr] = store_value & 0xFF
                    ip += 1
                elif op.operand == Intrinsic.LOAD16:
                    load_addr = stack.pop()
                    stack.append(int.from_bytes(mem[load_addr:load_addr+2], byteorder="little"))
                    ip += 1
                elif op.operand == Intrinsic.STORE16:
                    store_addr = stack.pop();
                    store_value = stack.pop()
                    mem[store_addr:store_addr+2] = store_value.to_bytes(length=2, byteorder="little", signed=(store_value < 0));
                    ip += 1
                elif op.operand == Intrinsic.LOAD32:
                    load_addr = stack.pop()
                    stack.append(int.from_bytes(mem[load_addr:load_addr+4], byteorder="little"))
                    ip += 1
                elif op.operand == Intrinsic.STORE32:
                    store_addr = stack.pop();
                    store_value = stack.pop()
                    mem[store_addr:store_addr+4] = store_value.to_bytes(length=4, byteorder="little", signed=(store_value < 0));
                    ip += 1
                elif op.operand == Intrinsic.LOAD64:
                    addr = stack.pop()
                    _bytes = bytearray(8)
                    for offset in range(0,8):
                        _bytes[offset] = mem[addr + offset]
                    stack.append(int.from_bytes(_bytes, byteorder="little"))
                    ip += 1
                elif op.operand == Intrinsic.STORE64:
                    store_addr64 = stack.pop();
                    store_value = stack.pop()
                    store_value64 = store_value.to_bytes(length=8, byteorder="little", signed=(store_value < 0));
                    for byte in store_value64:
                        mem[store_addr64] = byte;
                        store_addr64 += 1;
                    ip += 1
                elif op.operand == Intrinsic.ARGC:
                    stack.append(argc)
                    ip += 1
                elif op.operand == Intrinsic.ARGV:
                    stack.append(argv_buf_ptr)
                    ip += 1
                elif op.operand == Intrinsic.HERE:
                    value = ("%s:%d:%d" % op.token.loc).encode('utf-8')
                    n = len(value)
                    stack.append(n)
                    if ip not in str_ptrs:
                        str_ptr = str_buf_ptr+str_size
                        str_ptrs[ip] = str_ptr
                        mem[str_ptr:str_ptr+n] = value
                        str_size += n
                        assert str_size <= SIM_STR_CAPACITY, "String buffer overflow"
                    stack.append(str_ptrs[ip])
                    ip += 1
                elif op.operand == Intrinsic.CAST_PTR:
                    # Ignore the type casting. It's only useful for type_check_program() phase
                    ip += 1
                elif op.operand == Intrinsic.CAST_INT:
                    # Ignore the type casting. It's only useful for type_check_program() phase
                    ip += 1
                elif op.operand == Intrinsic.SYSCALL0:
                    syscall_number = stack.pop();
                    if syscall_number == 39: # SYS_getpid
                        stack.append(os.getpid());
                    else:
                        assert False, "unknown syscall number %d" % syscall_number
                    ip += 1
                elif op.operand == Intrinsic.SYSCALL1:
                    syscall_number = stack.pop()
                    arg1 = stack.pop()
                    if syscall_number == 60: # SYS_exit
                        return arg1
                    elif syscall_number == 3: # SYS_close
                        fds[arg1].close()
                        stack.append(0)
                    else:
                        assert False, "unknown syscall number %d" % syscall_number
                    ip += 1
                elif op.operand == Intrinsic.SYSCALL2:
                    assert False, "not implemented"
                elif op.operand == Intrinsic.SYSCALL3:
                    syscall_number = stack.pop()
                    arg1 = stack.pop()
                    arg2 = stack.pop()
                    arg3 = stack.pop()
                    if syscall_number == 0: # SYS_read
                        fd = arg1
                        buf = arg2
                        count = arg3
                        # NOTE: trying to behave like a POSIX tty in canonical mode by making the data available
                        # on each newline
                        # https://en.wikipedia.org/wiki/POSIX_terminal_interface#Canonical_mode_processing
                        # TODO: maybe this behavior should be customizable
                        data = fds[fd].readline(count)
                        mem[buf:buf+len(data)] = data
                        stack.append(len(data))
                    elif syscall_number == 1: # SYS_write
                        fd = arg1
                        buf = arg2
                        count = arg3
                        fds[fd].write(mem[buf:buf+count])
                        fds[fd].flush()
                        stack.append(count)
                    elif syscall_number == 257: # SYS_openat
                        dirfd = arg1
                        pathname_ptr = arg2
                        flags = arg3
                        if dirfd != AT_FDCWD:
                            assert False, "openat: unsupported dirfd"
                        if flags != O_RDONLY:
                            assert False, "openat: unsupported flags"
                        pathname = get_cstr_from_mem(mem, pathname_ptr).decode('utf-8')
                        fd = len(fds)
                        try:
                            fds.append(open(pathname, 'rb'))
                            stack.append(fd)
                        except FileNotFoundError:
                            stack.append(-ENOENT)
                    else:
                        assert False, "unknown syscall number %d" % syscall_number
                    ip += 1
                elif op.operand == Intrinsic.SYSCALL4:
                    syscall_number = stack.pop()
                    arg1 = stack.pop()
                    arg2 = stack.pop()
                    arg3 = stack.pop()
                    arg4 = stack.pop()

                    if syscall_number == 230: # clock_nanosleep
                        clock_id = arg1
                        flags = arg2
                        request_ptr = arg3
                        remain_ptr = arg4
                        assert clock_id == CLOCK_MONOTONIC, "Only CLOCK_MONOTONIC is implemented for SYS_clock_nanosleep"
                        assert flags == 0, "Only relative time is supported for SYS_clock_nanosleep"
                        assert request_ptr != 0, "request cannot be NULL for SYS_clock_nanosleep. We should probably return -1 in that case..."
                        assert remain_ptr == 0, "remain is not supported for SYS_clock_nanosleep"
                        seconds = int.from_bytes(mem[request_ptr:request_ptr+8], byteorder='little')
                        nano_seconds = int.from_bytes(mem[request_ptr+8:request_ptr+8+8], byteorder='little')
                        sleep(float(seconds)+float(nano_seconds)*1e-09)
                        stack.append(0)
                    else:
                        assert False, "unknown syscall number %d" % syscall_number
                    ip += 1
                elif op.operand == Intrinsic.SYSCALL5:
                    assert False, "not implemented"
                elif op.operand == Intrinsic.SYSCALL6:
                    assert False, "not implemented"
                else:
                    assert False, "unreachable"
            else:
                assert False, "unreachable"
        except Exception as e:
            eprint("Python Exception during simulation", op.token.loc)
            traceback.print_exception(type(e), e, e.__traceback__)
            exit(1)

    if debug > 1:
        print("[INFO] Memory dump")
        print(mem[:debug])
        print("[INFO] Stack dump")
        print(stack)

class DataType(IntEnum):
    INT = auto()
    PTR = auto()
    BOOL = auto()

def getTypeHuman(i: int) -> str:
    if i == DataType.INT:
        return "int"
    elif i == DataType.PTR:
        return "ptr"
    elif i == DataType.BOOL:
        return "bool"

DataStack: List[DataType]

@dataclass
class Context:
    stack: List[DataType]
    ip: OpAddr

def type_check_program(program: Program):
    visited_dos: Dict[OpAddr, DataStack] = {}
    contexts: List[Context] = [Context(stack=[], ip=0)]
    while len(contexts) > 0:
        ctx = contexts[-1];
        if ctx.ip >= len(program.ops):
            if len(ctx.stack) != 0:
                compiler_error(ctx.stack[-1][1], "unhandled data on the data stack: %s" % list(map(lambda x: x[0], ctx.stack)))
                exit(1)
            contexts.pop()
            continue
        op = program.ops[ctx.ip]
        assert len(OpType) == 11, "Exhaustive ops handling in type_check_program()"
        if op.typ == OpType.PUSH_INT:
            ctx.stack.append((DataType.INT, op.token))
            ctx.ip += 1
        elif op.typ == OpType.PUSH_STR:
            ctx.stack.append((DataType.INT, op.token))
            ctx.stack.append((DataType.PTR, op.token))
            ctx.ip += 1
        elif op.typ == OpType.PUSH_CSTR:
            ctx.stack.append((DataType.PTR, op.token))
            ctx.ip += 1
        elif op.typ == OpType.PUSH_MEM:
            ctx.stack.append((DataType.PTR, op.token))
            ctx.ip += 1
        elif op.typ == OpType.INTRINSIC:
            assert len(Intrinsic) == 42, "Exhaustive intrinsic handling in type_check_program()"
            assert isinstance(op.operand, Intrinsic), "This could be a bug in compilation step"
            if op.operand == Intrinsic.PLUS:
                assert len(DataType) == 3, "Exhaustive type handling in PLUS intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)
                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == DataType.INT and b_type == DataType.INT:
                    ctx.stack.append((DataType.INT, op.token))
                elif a_type == DataType.INT and b_type == DataType.PTR:
                    ctx.stack.append((DataType.PTR, op.token))
                elif a_type == DataType.PTR and b_type == DataType.INT:
                    ctx.stack.append((DataType.PTR, op.token))
                else:
                    compiler_error(op.token, "invalid argument types for PLUS intrinsic. Expected INT or PTR")
                    exit(1)
            elif op.operand == Intrinsic.MINUS:
                assert len(DataType) == 3, "Exhaustive type handling in MINUS intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)
                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and (a_type == DataType.INT or a_type == DataType.PTR):
                    ctx.stack.append((DataType.INT, op.token))
                elif b_type == DataType.PTR and a_type == DataType.INT:
                    ctx.stack.append((DataType.PTR, op.token))
                else:
                    compiler_error(op.token, "invalid argument types fo MINUS intrinsic: %s" % [b_type, a_type])
                    exit(1)
            elif op.operand == Intrinsic.MUL:
                assert len(DataType) == 3, "Exhaustive type handling in MUL intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)
                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.INT, op.token))
                else:
                    compiler_error(op.token, "invalid argument types fo MUL intrinsic. Expected INT.")
                    exit(1)
            elif op.operand == Intrinsic.DIVMOD:
                assert len(DataType) == 3, "Exhaustive type handling in DIVMOD intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)
                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.INT, op.token))
                    ctx.stack.append((DataType.INT, op.token))
                else:
                    compiler_error(op.token, "invalid argument types fo DIVMOD intrinsic. Expected INT.")
                    exit(1)
            elif op.operand == Intrinsic.EQ:
                assert len(DataType) == 3, "Exhaustive type handling in EQ intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)
                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error(op.token, "invalid argument types fo EQ intrinsic. Expected INT.")
                    exit(1)
            elif op.operand == Intrinsic.GT:
                assert len(DataType) == 3, "Exhaustive type handling in GT intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error(op.token, "invalid argument type for GT intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.LT:
                assert len(DataType) == 3, "Exhaustive type handling in LT intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error(op.token, "invalid argument type for LT intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.GE:
                assert len(DataType) == 3, "Exhaustive type handling in GE intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error(op.token, "invalid argument type for GE intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.LE:
                assert len(DataType) == 3, "Exhaustive type handling in LE intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error(op.token, "invalid argument type for LE intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.NE:
                assert len(DataType) == 3, "Exhaustive type handling in NE intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error(op.token, "invalid argument type for NE intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.SHR:
                assert len(DataType) == 3, "Exhaustive type handling in SHR intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.INT, op.token))
                else:
                    compiler_error(op.token, "invalid argument type for SHR intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.SHL:
                assert len(DataType) == 3, "Exhaustive type handling in SHL intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.INT, op.token))
                else:
                    compiler_error(op.token, "invalid argument type for SHL intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.OR:
                assert len(DataType) == 3, "Exhaustive type handling in OR intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.INT, op.token))
                elif a_type == b_type and a_type == DataType.BOOL:
                    ctx.stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error(op.token, "invalid argument type for OR intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.AND:
                assert len(DataType) == 3, "Exhaustive type handling in AND intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.INT, op.token))
                elif a_type == b_type and a_type == DataType.BOOL:
                    ctx.stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error(op.token, "invalid argument type for AND intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.NOT:
                assert len(DataType) == 3, "Exhaustive type handling in NOT intrinsic"
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)
                a_type, a_loc = ctx.stack.pop()

                if a_type == DataType.INT:
                    ctx.stack.append((DataType.INT, op.token))
                elif a_type == DataType.BOOL:
                    ctx.stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error(op.token, "invalid argument type for NOT intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.PRINT:
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)
                ctx.stack.pop()
            elif op.operand == Intrinsic.DUP:
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)
                a = ctx.stack.pop()
                ctx.stack.append(a)
                ctx.stack.append(a)
            elif op.operand == Intrinsic.SWAP:
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)
                a = ctx.stack.pop()
                b = ctx.stack.pop()
                ctx.stack.append(a)
                ctx.stack.append(b)
            elif op.operand == Intrinsic.DROP:
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)
                ctx.stack.pop()
            elif op.operand == Intrinsic.OVER:
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)
                a = ctx.stack.pop()
                b = ctx.stack.pop()
                ctx.stack.append(b)
                ctx.stack.append(a)
                ctx.stack.append(b)
            elif op.operand == Intrinsic.ROT:
                if len(ctx.stack) < 3:
                    not_enough_arguments(op)
                    exit(1)
                a = ctx.stack.pop()
                b = ctx.stack.pop()
                c = ctx.stack.pop()
                ctx.stack.append(b)
                ctx.stack.append(a)
                ctx.stack.append(c)
            elif op.operand == Intrinsic.LOAD8:
                assert len(DataType) == 3, "Exhaustive type handling in LOAD8 intrinsic"
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)
                a_type, a_loc = ctx.stack.pop()

                if a_type == DataType.PTR:
                    ctx.stack.append((DataType.INT, op.token))
                else:
                    compiler_error(op.token, "invalid argument type for LOAD8 intrinsic: %s" % a_type)
                    exit(1)
            elif op.operand == Intrinsic.STORE8:
                assert len(DataType) == 3, "Exhaustive type handling in STORE8 intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == DataType.PTR and b_type == DataType.INT:
                    pass
                else:
                    compiler_error(op.token, "invalid argument type for STORE8 intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.LOAD16:
                assert len(DataType) == 3, "Exhaustive type handling in LOAD16 intrinsic"
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)
                a_type, a_loc = ctx.stack.pop()

                if a_type == DataType.PTR:
                    ctx.stack.append((DataType.INT, op.token))
                else:
                    compiler_error(op.token, "invalid argument type for LOAD16 intrinsic: %s" % a_type)
                    exit(1)
            elif op.operand == Intrinsic.STORE16:
                assert len(DataType) == 3, "Exhaustive type handling in STORE16 intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == DataType.PTR and b_type == DataType.INT:
                    pass
                else:
                    compiler_error(op.token, "invalid argument type for STORE16 intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.LOAD32:
                assert len(DataType) == 3, "Exhaustive type handling in LOAD32 intrinsic"
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)
                a_type, a_loc = ctx.stack.pop()

                if a_type == DataType.PTR:
                    ctx.stack.append((DataType.INT, op.token))
                else:
                    compiler_error(op.token, "invalid argument type for LOAD32 intrinsic: %s" % a_type)
                    exit(1)
            elif op.operand == Intrinsic.STORE32:
                assert len(DataType) == 3, "Exhaustive type handling in STORE32 intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == DataType.PTR and b_type == DataType.INT:
                    pass
                else:
                    compiler_error(op.token, "invalid argument type for STORE32 intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.LOAD64:
                assert len(DataType) == 3, "Exhaustive type handling in LOAD64 intrinsic"
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)
                a_type, a_loc = ctx.stack.pop()

                if a_type == DataType.PTR:
                    ctx.stack.append((DataType.INT, op.token))
                else:
                    compiler_error(op.token, "invalid argument type for LOAD64 intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.STORE64:
                assert len(DataType) == 3, "Exhaustive type handling in STORE64 intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if (b_type == DataType.INT or b_type == DataType.PTR) and a_type == DataType.PTR:
                    pass
                else:
                    compiler_error(op.token, "invalid argument type for STORE64 intrinsic: %s" % [b_type, a_type])
                    exit(1)
            elif op.operand == Intrinsic.CAST_PTR:
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_token = ctx.stack.pop()

                ctx.stack.append((DataType.PTR, a_token))
            elif op.operand == Intrinsic.CAST_BOOL:
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_token = ctx.stack.pop()

                ctx.stack.append((DataType.BOOL, a_token))
            elif op.operand == Intrinsic.CAST_INT:
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_token = ctx.stack.pop()

                ctx.stack.append((DataType.INT, a_token))
            elif op.operand == Intrinsic.CAST_BOOL:
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_token = ctx.stack.pop()

                ctx.stack.append((DataType.BOOL, a_token))
            elif op.operand == Intrinsic.ARGC:
                ctx.stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.ARGV:
                ctx.stack.append((DataType.PTR, op.token))
            elif op.operand == Intrinsic.HERE:
                ctx.stack.append((DataType.INT, op.token))
                ctx.stack.append((DataType.PTR, op.token))
            # TODO: figure out how to type check syscall arguments and return types
            elif op.operand == Intrinsic.SYSCALL0:
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)
                for i in range(1):
                    ctx.stack.pop()
                ctx.stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL1:
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)
                for i in range(2):
                    ctx.stack.pop()
                ctx.stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL2:
                if len(ctx.stack) < 3:
                    not_enough_arguments(op)
                    exit(1)
                for i in range(3):
                    ctx.stack.pop()
                ctx.stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL3:
                if len(ctx.stack) < 4:
                    not_enough_arguments(op)
                    exit(1)
                for i in range(4):
                    ctx.stack.pop()
                ctx.stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL4:
                if len(ctx.stack) < 5:
                    not_enough_arguments(op)
                    exit(1)
                for i in range(5):
                    ctx.stack.pop()
                ctx.stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL5:
                if len(ctx.stack) < 6:
                    not_enough_arguments(op)
                    exit(1)
                for i in range(6):
                    ctx.stack.pop()
                ctx.stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL6:
                if len(ctx.stack) < 7:
                    not_enough_arguments(op)
                    exit(1)
                for i in range(7):
                    ctx.stack.pop()
                ctx.stack.append((DataType.INT, op.token))
            else:
                assert False, "unreachable " + str(op.operand)
            ctx.ip += 1
        elif op.typ == OpType.IF:
            ctx.ip += 1
        elif op.typ == OpType.WHILE:
            ctx.ip += 1
        elif op.typ == OpType.END:
            assert isinstance(op.operand, OpAddr)
            ctx.ip = op.operand
        elif op.typ == OpType.ELSE:
            assert isinstance(op.operand, OpAddr)
            ctx.ip = op.operand
        elif op.typ == OpType.ELIF:
            assert isinstance(op.operand, OpAddr)
            ctx.ip = op.operand
        elif op.typ == OpType.DO:
            assert isinstance(op.operand, OpAddr)
            if len(ctx.stack) < 1:
                not_enough_arguments(op)
                exit(1)
            a_type, a_token = ctx.stack.pop()
            if a_type != DataType.BOOL:
                compiler_error(op.token, "Invalid argument for the while-do condition. Expected BOOL.")
                exit(1)
            if ctx.ip in visited_dos:
                expected_types = list(map(lambda x: x[0], visited_dos[ctx.ip]))
                actual_types = list(map(lambda x: x[0], ctx.stack))
                if expected_types != actual_types:
                    compiler_error(op.token, 'Loops are not allowed to alter types and amount of elements on the stack.')
                    compiler_note(op.token.loc, 'Expected elements: %s' % expected_types)
                    compiler_note(op.token.loc, 'Actual elements: %s' % actual_types)
                    exit(1)
                contexts.pop()
            else:
                visited_dos[ctx.ip] = copy(ctx.stack)
                ctx.ip += 1
                contexts.append(Context(stack=copy(ctx.stack), ip=op.operand))
                ctx = contexts[-1]
        else:
            assert False, "unreachable"


def generate_nasm_linux_x86_64(program: Program, file_path: str):
    strs: List[bytes] = []
    with open(file_path, "w") as out:
        out.write("BITS 64\n")
        out.write("segment .text\n")
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
        out.write("    ; -- init argv\n")
        out.write("    mov [args_ptr], rsp\n")
        out.write("    \n")
        for ip in range(len(program.ops)):
            op = program.ops[ip]
            assert len(OpType) == 11, "Exhaustive ops handling in generate_nasm_linux_x86_64"
            out.write("addr_%d:\n" % ip)
            if op.typ == OpType.PUSH_INT:
                assert isinstance(op.operand, int), "This could be a bug in the compilation step"
                out.write("    ;; -- push int %d --\n" % op.operand)
                out.write("    mov rax, %d\n" % op.operand)
                out.write("    push rax\n")
            elif op.typ == OpType.PUSH_STR:
                assert isinstance(op.operand, str), "This could be a bug in the compilation step"
                value = op.operand.encode('utf-8')
                n = len(value)
                out.write("    ;; -- push str --\n")
                out.write("    mov rax, %d\n" % n)
                out.write("    push rax\n")
                out.write("    push str_%d\n" % len(strs))
                strs.append(value)
            elif op.typ == OpType.PUSH_CSTR:
                assert isinstance(op.operand, str), "This could be a bug in the parsing step"
                value = op.operand.encode('utf-8') + b'\0'
                out.write("    ;; -- push str --\n")
                out.write("    push str_%d\n" % len(strs))
                strs.append(value)
            elif op.typ == OpType.PUSH_MEM:
                out.write("    ;; -- push mem --\n")
                out.write("    mov rax, mem\n")
                out.write("    add rax, %d\n" % op.operand)
                out.write("    push rax\n")
            elif op.typ == OpType.IF:
                out.write("    ;; -- if --\n")
            elif op.typ == OpType.ELSE:
                out.write("    ;; -- else --\n")
                assert isinstance(op.operand, int), "This could be a bug in the compilation step"
                out.write("    jmp addr_%d\n" % op.operand)
            elif op.typ == OpType.ELIF:
                out.write("    ;; -- elif --\n")
                assert isinstance(op.operand, OpAddr), f"This could be a bug in the parsing step: {op.operand}"
                out.write("    jmp addr_%d\n" % op.operand)
            elif op.typ == OpType.END:
                assert isinstance(op.operand, int), "This could be a bug in the compilation step"
                out.write("    ;; -- end --\n")
                if ip + 1 != op.operand:
                    out.write("    jmp addr_%d\n" % op.operand)
            elif op.typ == OpType.WHILE:
                out.write("    ;; -- while --\n")
            elif op.typ == OpType.DO:
                out.write("    ;; -- do --\n")
                out.write("    pop rax\n")
                out.write("    test rax, rax\n")
                assert isinstance(op.operand, int), "This could be a bug in the compilation step"
                out.write("    jz addr_%d\n" % op.operand)
            elif op.typ == OpType.INTRINSIC:
                assert len(Intrinsic) == 42, "Exhaustive intrinsic handling in generate_nasm_linux_x86_64() " + str(len(Intrinsic))
                if op.operand == Intrinsic.PLUS:
                    out.write("    ;; -- plus --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    add rax, rbx\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.MINUS:
                    out.write("    ;; -- minus --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    sub rbx, rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.MUL:
                    out.write("    ;; -- mul --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    mul rbx\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.DIVMOD:
                    out.write("    ;; -- mod --\n")
                    out.write("    xor rdx, rdx\n")
                    out.write("    pop rbx\n")
                    out.write("    pop rax\n")
                    out.write("    div rbx\n")
                    out.write("    push rax\n");
                    out.write("    push rdx\n");
                elif op.operand == Intrinsic.SHR:
                    out.write("    ;; -- shr --\n")
                    out.write("    pop rcx\n")
                    out.write("    pop rbx\n")
                    out.write("    shr rbx, cl\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.SHL:
                    out.write("    ;; -- shl --\n")
                    out.write("    pop rcx\n")
                    out.write("    pop rbx\n")
                    out.write("    shl rbx, cl\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.OR:
                    out.write("    ;; -- or --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    or rbx, rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.ROT:
                    out.write("    ;; -- rot --\n")# b c a
                    out.write("    pop rax\n") # c
                    out.write("    pop rbx\n") # b
                    out.write("    pop rcx\n") # a
                    out.write("    push rbx\n") # b
                    out.write("    push rax\n") # c
                    out.write("    push rcx\n") # a
                elif op.operand == Intrinsic.AND:
                    out.write("    ;; -- and --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    and rbx, rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.PRINT:
                    out.write("    ;; -- print --\n")
                    out.write("    pop rdi\n")
                    out.write("    call print\n")
                elif op.operand == Intrinsic.EQ:
                    out.write("    ;; -- equal -- \n")
                    out.write("    mov rcx, 0\n");
                    out.write("    mov rdx, 1\n");
                    out.write("    pop rax\n");
                    out.write("    pop rbx\n");
                    out.write("    cmp rax, rbx\n");
                    out.write("    cmove rcx, rdx\n");
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.NOT:
                    out.write("    ;; -- not --\n")
                    out.write("    pop rax\n")
                    out.write("    not rax\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.GT:
                    out.write("    ;; -- gt --\n")
                    out.write("    mov rcx, 0\n");
                    out.write("    mov rdx, 1\n");
                    out.write("    pop rbx\n");
                    out.write("    pop rax\n");
                    out.write("    cmp rax, rbx\n");
                    out.write("    cmovg rcx, rdx\n");
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.LT:
                    out.write("    ;; -- lt --\n")
                    out.write("    mov rcx, 0\n");
                    out.write("    mov rdx, 1\n");
                    out.write("    pop rbx\n");
                    out.write("    pop rax\n");
                    out.write("    cmp rax, rbx\n");
                    out.write("    cmovl rcx, rdx\n");
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.GE:
                    out.write("    ;; -- ge --\n")
                    out.write("    mov rcx, 0\n");
                    out.write("    mov rdx, 1\n");
                    out.write("    pop rbx\n");
                    out.write("    pop rax\n");
                    out.write("    cmp rax, rbx\n");
                    out.write("    cmovge rcx, rdx\n");
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.LE:
                    out.write("    ;; -- le --\n")
                    out.write("    mov rcx, 0\n");
                    out.write("    mov rdx, 1\n");
                    out.write("    pop rbx\n");
                    out.write("    pop rax\n");
                    out.write("    cmp rax, rbx\n");
                    out.write("    cmovle rcx, rdx\n");
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.NE:
                    out.write("    ;; -- ne --\n")
                    out.write("    mov rcx, 0\n")
                    out.write("    mov rdx, 1\n")
                    out.write("    pop rbx\n")
                    out.write("    pop rax\n")
                    out.write("    cmp rax, rbx\n")
                    out.write("    cmovne rcx, rdx\n")
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.DUP:
                    out.write("    ;; -- dup -- \n")
                    out.write("    pop rax\n")
                    out.write("    push rax\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SWAP:
                    out.write("    ;; -- swap --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    push rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.DROP:
                    out.write("    ;; -- drop --\n")
                    out.write("    pop rax\n")
                elif op.operand == Intrinsic.OVER:
                    out.write("    ;; -- over --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    push rbx\n")
                    out.write("    push rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.CAST_PTR:
                    out.write("    ;; -- cast(ptr) --\n")
                elif op.operand == Intrinsic.CAST_INT:
                    out.write("    ;; -- cast(int) --\n")
                elif op.operand == Intrinsic.CAST_BOOL:
                    out.write("    ;; -- cast(bool) --\n")
                elif op.operand == Intrinsic.ARGC:
                    out.write("    ; -- argc --\n")
                    out.write("    mov rax, [args_ptr]\n")
                    out.write("    mov rax, [rax]\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.ARGV:
                    out.write("    ; -- argv --\n")
                    out.write("    mov rax, [args_ptr]\n")
                    out.write("    add rax, 8\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.HERE:
                    value = ("%s:%d:%d" % op.token.loc).encode('utf-8')
                    n = len(value)
                    out.write("    ;; -- here --\n")
                    out.write("    mov rax, %d\n" % n)
                    out.write("    push rax\n")
                    out.write("    push str_%d\n" % len(strs))
                    strs.append(value)
                elif op.operand == Intrinsic.LOAD8:
                    out.write("    ;; -- forth load --\n")
                    out.write("    pop rax\n")
                    out.write("    xor rbx, rbx\n")
                    out.write("    mov bl, [rax]\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.STORE8:
                    out.write("    ;; -- store --\n")
                    out.write("    pop rax\n");
                    out.write("    pop rbx\n");
                    out.write("    mov [rax], bl\n");
                elif op.operand == Intrinsic.LOAD64:
                    out.write("    ;; -- forth load64 --\n")
                    out.write("    pop rax\n")
                    out.write("    xor rbx, rbx\n")
                    out.write("    mov rbx, [rax]\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.STORE64:
                    out.write("    ;; -- forth store64 --\n")
                    out.write("    pop rax\n");
                    out.write("    pop rbx\n");
                    out.write("    mov [rax], rbx\n");
                elif op.operand == Intrinsic.SYSCALL0:
                    out.write("    ;; -- syscall0 --\n")
                    out.write("    pop rax\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL1:
                    out.write("    ;; -- syscall1 --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rdi\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL2:
                    out.write("    ;; -- syscall2 -- \n")
                    out.write("    pop rax\n");
                    out.write("    pop rdi\n");
                    out.write("    pop rsi\n");
                    out.write("    syscall\n");
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL3:
                    out.write("    ;; -- syscall3 --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rdi\n")
                    out.write("    pop rsi\n")
                    out.write("    pop rdx\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL4:
                    out.write("    ;; -- syscall4 --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rdi\n")
                    out.write("    pop rsi\n")
                    out.write("    pop rdx\n")
                    out.write("    pop r10\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL5:
                    out.write("    ;; -- syscall5 --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rdi\n")
                    out.write("    pop rsi\n")
                    out.write("    pop rdx\n")
                    out.write("    pop r10\n")
                    out.write("    pop r8\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL6:
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
                else:
                    assert False, "unreachable " + str(op.operand)
            else:
                print(op.typ)
                assert False, "unreachable"

        out.write("addr_%d:\n" % len(program.ops))
        out.write("    mov rax, 60\n")
        out.write("    mov rdi, 0\n")
        out.write("    syscall\n")
        out.write("segment .data\n")

        for index, s in enumerate(strs):
            out.write("; %s\n" % str(s).encode("unicode_escape").decode("utf-8"))
            out.write("str_%d: db %s" % (index, ",".join(map(hex, list(s))) + "\n\n"))
            
        out.write("segment .bss\n")
        out.write("    args_ptr: resq 1\n")
        out.write("    mem: resb %d\n" % program.memory_capacity)


assert len(Keyword) == 9, "Exhaustive KEYWORD_NAMES definition."
KEYWORD_NAMES = {
    'if': Keyword.IF,
    'end': Keyword.END,
    'else': Keyword.ELSE,
    'elif': Keyword.ELIF,
    'while': Keyword.WHILE,
    'do': Keyword.DO,
    'macro': Keyword.MACRO,
    'memory': Keyword.MEMORY,
    'include': Keyword.INCLUDE,
}


assert len(Intrinsic) == 42, "Exhaustive INTRINSIC_NAMES definition"
INTRINSIC_BY_NAMES = {
    '+': Intrinsic.PLUS,
    '-': Intrinsic.MINUS,
    '*': Intrinsic.MUL,
    'divmod': Intrinsic.DIVMOD,
    'print': Intrinsic.PRINT,
    '=': Intrinsic.EQ,
    '>': Intrinsic.GT,
    '<': Intrinsic.LT,
    '>=': Intrinsic.GE,
    '<=': Intrinsic.LE,
    '!=': Intrinsic.NE,
    'not': Intrinsic.NOT,
    'shr': Intrinsic.SHR,
    'shl': Intrinsic.SHL,
    'or': Intrinsic.OR,
    'and': Intrinsic.AND,
    'dup': Intrinsic.DUP,
    'swap': Intrinsic.SWAP,
    'drop': Intrinsic.DROP,
    'over': Intrinsic.OVER,
    '!8': Intrinsic.STORE8,
    '@8': Intrinsic.LOAD8,
    '!16': Intrinsic.STORE16,
    '@16': Intrinsic.LOAD16,
    '!32': Intrinsic.STORE32,
    '@32': Intrinsic.LOAD32,
    '!64': Intrinsic.STORE64,
    '@64': Intrinsic.LOAD64,
    'cast(ptr)': Intrinsic.CAST_PTR,
    'cast(int)': Intrinsic.CAST_INT,
    'cast(bool)': Intrinsic.CAST_BOOL,
    'syscall0': Intrinsic.SYSCALL0,
    'syscall1': Intrinsic.SYSCALL1,
    'syscall2': Intrinsic.SYSCALL2,
    'syscall3': Intrinsic.SYSCALL3,
    'syscall4': Intrinsic.SYSCALL4,
    'syscall5': Intrinsic.SYSCALL5,
    'syscall6': Intrinsic.SYSCALL6,
    'argc': Intrinsic.ARGC,
    'argv': Intrinsic.ARGV,
    'here': Intrinsic.HERE,
    'rot': Intrinsic.ROT,
}
INTRINSIC_NAMES = {v: k for k, v in INTRINSIC_BY_NAMES.items()}

@dataclass
class Macro:
    loc: Loc
    tokens: List[Token]

def human(typ: TokenType) -> str:
    if typ == TokenType.WORD:
        return "word"
    elif typ == TokenType.INT:
        return "int"
    elif typ == TokenType.STR:
        return "string"
    elif typ == TokenType.CHAR:
        return "char"
    elif typ == TokenType.KEYWORD:
        return "keyword"
    else:
        return str(typ)

def expand_macro(macro: Macro, expanded_from: Token) -> List[Token]:
    result = list(map(lambda x: copy(x), macro.tokens))
    for token in result:
        token.expanded_from = expanded_from
        token.expanded_count = expanded_from.expanded_count + 1
    return result


def parse_program_from_tokens(tokens: List[Token], include_paths: List[str], expansion_limit: int, base_path) -> Program:
    stack: List[OpAddr] = []
    program: List[Op] = Program(ops=[], memory_capacity=0)
    rtokens: List[Token] = list(reversed(tokens))
    memories = {}
    mem_cap = 0
    macros: Dict[str, Macro] = {}
    ip: OpAddr = 0;
    while len(rtokens) > 0:
        token = rtokens.pop()
        assert len(TokenType) == 6, "Exhaustive token handling in parse_program_from_tokens"
        if token.typ == TokenType.WORD:
            assert isinstance(token.value, str), "This could be a bug in the lexer"
            if token.value in INTRINSIC_BY_NAMES:
                program.ops.append(Op(typ=OpType.INTRINSIC, token=token, operand=INTRINSIC_BY_NAMES[token.value]))
                ip += 1
            elif token.value in macros:
                if token.expanded_count >= expansion_limit:
                    compiler_error(token, "the macro exceeded the expansion limit (it expanded %d times)" % token.expanded_count)
                    exit(1)
                rtokens += reversed(expand_macro(macros[token.value], token))
            elif token.value in memories:
                program.ops.append(Op(typ=OpType.PUSH_MEM, token=token, operand=memories[token.value]))
                ip += 1
            else:
                compiler_error(token, "unknown word `%s`" % token.value)
                exit(1)
        elif token.typ == TokenType.INT:
            assert isinstance(token.value, int), "This could be a bug in the lexer"
            program.ops.append(Op(typ=OpType.PUSH_INT, operand=token.value, token=token))
            ip += 1
        elif token.typ == TokenType.STR:
            assert isinstance(token.value, str), "This could be a bug in the lexer"
            program.ops.append(Op(typ=OpType.PUSH_STR, operand=token.value, token=token));
            ip += 1
        elif token.typ == TokenType.CSTR:
            assert isinstance(token.value, str), "This could be a bug in the lexer"
            program.ops.append(Op(typ=OpType.PUSH_CSTR, operand=token.value, token=token));
            ip += 1
        elif token.typ == TokenType.CHAR:
            assert isinstance(token.value, int)
            program.ops.append(Op(typ=OpType.PUSH_INT, operand=token.value, token=token));
            ip += 1
        elif token.typ == TokenType.KEYWORD:
            assert len(Keyword) == 9, "Exhaustive keywords handling in parse_program_from_tokens()"
            if token.value == Keyword.IF:
                program.ops.append(Op(typ=OpType.IF, token=token))
                stack.append(ip)
                ip += 1
            elif token.value == Keyword.ELIF:
                program.ops.append(Op(typ=OpType.ELIF, token=token))
                do_ip = stack.pop()
                if program.ops[do_ip].typ != OpType.DO:
                    compiler_error(program.loc[do_ip].token, '`elif` can only close `do`-blocks')
                    exit(1)
                pre_do_ip = program.ops[do_ip].operand
                assert isinstance(pre_do_ip, OpAddr)
                if program.ops[pre_do_ip].typ == OpType.IF:
                    program.ops[do_ip].operand = ip + 1
                    stack.append(ip)
                    ip += 1
                elif program.ops[pre_do_ip].typ == OpType.ELIF:
                    program.ops[pre_do_ip].operand = ip
                    program.ops[do_ip].operand = ip + 1
                    stack.append(ip)
                    ip += 1
                else:
                    compiler_error(program.ops[do_ip].token, '`elif` can only close `do`-blocks that are preceded by `if` or another `elif`')
                    exit(1)
            elif token.value == Keyword.ELSE:
                program.ops.append(Op(typ=OpType.ELSE, token=token))
                do_ip = stack.pop()
                if program.ops[do_ip].typ != OpType.DO:
                    compiler_error(program.ops[do_ip].token, '`else` can only be used in `do` blocks')
                    exit(1)
                pre_do_ip = program.ops[do_ip].operand
                assert isinstance(pre_do_ip, OpAddr)
                if program.ops[pre_do_ip].typ == OpType.IF:
                    program.ops[do_ip].operand = ip + 1
                    stack.append(ip)
                    ip += 1
                elif program.ops[pre_do_ip].typ == OpType.ELIF:
                    program.ops[pre_do_ip].operand = ip
                    program.ops[do_ip].operand = ip + 1
                    stack.append(ip)
                    ip += 1
                else:
                    compiler_error(program.loc[pre_do_ip].token, '`else` can only close `do`-blocks that are preceded by `if` or `elif`')
                    exit(1)
            elif token.value == Keyword.END:
                program.ops.append(Op(typ=OpType.END, token=token))
                block_ip = stack.pop()
                if program.ops[block_ip].typ == OpType.ELSE:
                    program.ops[block_ip].operand = ip
                    program.ops[ip].operand = ip + 1
                elif program.ops[block_ip].typ == OpType.DO:
                    assert program.ops[block_ip].operand is not None
                    pre_do_ip = program.ops[block_ip].operand

                    assert isinstance(pre_do_ip, OpAddr)
                    if program.ops[pre_do_ip].typ == OpType.WHILE:
                        program.ops[ip].operand = pre_do_ip
                        program.ops[block_ip].operand = ip + 1
                    elif program.ops[pre_do_ip].typ == OpType.IF:
                        program.ops[ip].operand = ip + 1
                        program.ops[block_ip].operand = ip + 1
                    elif program.ops[pre_do_ip].typ == OpType.ELIF:
                        program.ops[pre_do_ip].operand = ip
                        program.ops[ip].operand = ip + 1
                        program.ops[block_ip].operand = ip + 1
                    else:
                        compiler_error(program.ops[pre_do_ip].token, '`end` can only close `do` blocks that are preceded by `if`, `while` or `elif`')
                        exit(1)
                else:
                    compiler_error(program.ops[block_ip].token, '`end` can only close `else`, `do` or `macro` blocks for now')
                    exit(1)
                ip += 1
            elif token.value == Keyword.WHILE:
                program.ops.append(Op(typ=OpType.WHILE, token=token))
                stack.append(ip)
                ip += 1
            elif token.value == Keyword.DO:
                program.ops.append(Op(typ=OpType.DO, token=token))
                pre_do_ip = stack.pop()
                assert program.ops[pre_do_ip].typ == OpType.WHILE or program.ops[pre_do_ip].typ == OpType.IF or program.ops[pre_do_ip].typ == OpType.ELIF
                program.ops[ip].operand = pre_do_ip
                stack.append(ip)
                ip += 1
            elif token.value == Keyword.INCLUDE:
                if len(rtokens) == 0:
                    compiler_error(token, "expected path to the include file but found nothing")
                    exit(1)
                token = rtokens.pop()
                if token.typ != TokenType.STR:
                    compiler_error(token, "expected path to the include file to be `%s` but found `%s`" % (human(TokenType.STR), human(token.typ)))
                    exit(1)
                assert isinstance(token.value, str), "This is probably a bug in the lexer"
                
                file_included = False

                if os.path.exists(token.value):
                    if token.expanded_count >= expansion_limit:
                        compiler_error(token, "the include exceeded the expansion limit (it expanded %d times)" % token.expanded_count)
                        exit(1)
                    rtokens += reversed(lex_file(token.value, token))
                    file_included = True
                else: 
                    for include_path in include_paths:
                        try:
                            if token.expanded_count >= expansion_limit:
                                compiler_error(token.loc, "the include exceeded the expansion limit (it expanded %d times)" % token.expanded_count)
                                exit(1)
                            rtokens += reversed(lex_file(os.path.join(include_path, token.value), token))
                            file_included = True
                            break
                        except FileNotFoundError:
                            continue
                if not file_included:
                    compiler_error(token, "file `%s` not found" % token.value)
                    exit(1)
            elif token.value == Keyword.MEMORY:
                if len(rtokens) == 0:
                    compiler_error(token, "expected memory name but found nothing")
                    exit(1)
                token = rtokens.pop()
                if token.typ != TokenType.WORD:
                    compiler_error(token, "expected memory name to be %s but found %s" % (human(TokenType.WORD), human(token.typ)))
                    exit(1)
                assert isinstance(token.value, str), "This is probably a bug in the lexer"
                memory_name = token.value
                if memory_name in memories:
                    assert False, "TODO: redefinition of a memory region"
                if memory_name in INTRINSIC_BY_NAMES:
                    assert False, "TODO: redefinition of an intrinsic"
                if memory_name in macros:
                    assert False, "TODO: redefinition of a macro"
                mem_size_stack: List[int] = []
                while len(rtokens) > 0:
                    token = rtokens.pop()
                    if token.typ == TokenType.KEYWORD:
                        if token.value == Keyword.END:
                            break
                        else:
                            assert False, "TODO: unsupported keyword in memory definition"
                    elif token.typ == TokenType.INT:
                        assert isinstance(token.value, int)
                        mem_size_stack.append(token.value)
                    elif token.typ == TokenType.WORD:
                        if token.value == INTRINSIC_NAMES[Intrinsic.PLUS]:
                            a = mem_size_stack.pop()
                            b = mem_size_stack.pop()
                            mem_size_stack.append(a + b)
                        elif token.value == INTRINSIC_NAMES[Intrinsic.MUL]:
                            a = mem_size_stack.pop()
                            b = mem_size_stack.pop()
                            mem_size_stack.append(a * b)
                        elif token.value in macros:
                            if token.expanded_count >= expansion_limit:
                                compiler_error(token, "the macro exceeded the expansion limit (it expanded %d times)" % token.expanded_count)
                                exit(1)
                            rtokens += reversed(expand_macro(macros[token.value], token))
                        else:
                            assert False, f"TODO: unsupported word in memory definition {token.value}"
                    else:
                        assert False, "TODO: unsupported token in memory definition"
                if len(mem_size_stack) != 1:
                    assert False, "TODO: memory definition expects only one integer"
                memory_size = mem_size_stack.pop()
                memories[memory_name] = program.memory_capacity
                program.memory_capacity += memory_size
            elif token.value == Keyword.MACRO:
                if len(rtokens) == 0:
                    compiler_error(token, "expected macro name but found nothing")
                    exit(1)
                token = rtokens.pop()
                if token.typ != TokenType.WORD:
                    compiler_error(token, "expected macro name to be `%s` but found `%s`" % (human(TokenType.WORD), human(token.typ)))
                    exit(1)
                assert isinstance(token.value, str), "This is probably a bug in the lexer"
                if token.value in macros:
                    compiler_error(token, "redefinition of already existing macro `%s`" % token.value)
                    compiler_note(macros[token.value].loc, "the first definition is located here")
                    exit(1)
                if token.value in INTRINSIC_BY_NAMES:
                    compiler_error(token, "redefinition of an intrinsic word `%s`. Please choose a different name for your macro." % (token.value, ))
                    exit(1)
                if token.value in memories:
                    compiler_error(token, "redefinition of a memory region `%s`. Please choose a different name for your macro." % (token.value, ))
                    exit(1)
                macro = Macro(token.loc, [])
                macros[token.value] = macro
                nesting_depth = 0
                while len(rtokens) > 0:
                    token = rtokens.pop()
                    if token.typ == TokenType.KEYWORD and token.value == Keyword.END and nesting_depth == 0:
                        break
                    else:
                        macro.tokens.append(token)
                        if token.typ == TokenType.KEYWORD:
                            if token.value in [Keyword.IF, Keyword.WHILE, Keyword.MACRO]:
                                nesting_depth += 1
                            elif token.value == Keyword.END:
                                nesting_depth -= 1
                if token.typ != TokenType.KEYWORD or token.value != Keyword.END:
                    compiler_error(token, "expected `end` at the end of the macro definition but got `%s`" % (token.value, ))
                    exit(1)
            else:
                assert False, 'unreachable';
        else:
            assert False, 'unreachable'


    if len(stack) > 0:
        compiler_error(program.ops[stack.pop()].token, 'unclosed block')
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

def find_string_literal_end(line: str, start: int) -> int:
    prev = line[start]
    while start < len(line):
        curr = line[start]
        if curr == '"' and prev != '\\':
            break
        prev = curr
        start += 1
    return start

def lex_lines(file_path: str, lines: List[str]) -> Generator[Token, None, None]:
    assert len(TokenType) == 6, 'Exhaustive handling of token types in lex_lines'

    # Very dumb way of handling multiline comments, but it works
    # _file = "__NUVTYFnTbhBTVbujbYFYUBUU__".join(lines)
    # lines = re.sub("(?s)/\\*.*?\\*/", "", _file).split("__NUVTYFnTbhBTVbujbYFYUBUU__")

    row = 0
    str_literal_buf = ""
    while row < len(lines):
        line = re.sub("(?s)/\\*.*?\\*/", "", lines[row])
        col = find_col(line, 0, lambda x: not x.isspace())
        col_end = 0
        while col < len(line):
            loc = (file_path, row + 1, col + 1)
            if line[col] == '"':
                while row < len(lines):
                    start = col
                    if str_literal_buf == "":
                        start += 1
                    else:
                        line = lines[row]
                    col_end = find_string_literal_end(line, start)
                    if col_end >= len(line) or line[col_end] != '"':
                        str_literal_buf += line[start:]
                        row +=1
                        col = 0
                    else:
                        str_literal_buf += line[start:col_end]
                        break
                if row >= len(lines):
                    eprint("unclosed string literal", loc)
                    exit(1)
                assert line[col_end] == '"'
                col_end += 1
                text_of_token = str_literal_buf
                str_literal_buf = ""
                if col_end < len(line) and line[col_end] == 'c':
                    col_end += 1
                    yield Token(TokenType.CSTR, text_of_token, loc, unescape_string(text_of_token))
                else:
                    yield Token(TokenType.STR, text_of_token, loc, unescape_string(text_of_token))
                col = find_col(line, col_end, lambda x: not x.isspace())
            elif line[col] == "'":
                col_end = find_col(line, col+1, lambda x: x == "'")
                if col_end >= len(line) or line[col_end] != "'":
                    eprint("unclosed character literal", loc)
                    exit(1)
                text_of_token = line[col+1:col_end]
                char_bytes = unescape_string(text_of_token).encode('utf-8')
                if len(char_bytes) != 1:
                    eprint("only a single byte is allowed inside of a character literal", loc)
                    exit(1)
                yield Token(TokenType.CHAR, text_of_token, loc, char_bytes[0])
                col = find_col(line, col_end+1, lambda x: not x.isspace())
            else:
                col_end = find_col(line, col, lambda x: x.isspace())
                text_of_token = line[col:col_end]

                try:
                    yield Token(TokenType.INT, text_of_token, loc, int(text_of_token))
                except ValueError:
                    if text_of_token in KEYWORD_NAMES:
                        yield Token(TokenType.KEYWORD, text_of_token, loc, KEYWORD_NAMES[text_of_token])
                    else:
                        if text_of_token.startswith("//"):
                            break
                        yield Token(TokenType.WORD, text_of_token, loc, text_of_token)
                col = find_col(line, col_end, lambda x: not x.isspace())
        row += 1

def lex_file(file_path: str, expanded_from: Optional[Token] = None) -> List[Token]:
    with open(file_path, "r", encoding='utf-8') as f:
        result = [token for token in lex_lines(file_path, f.readlines())]
        for token in result:
            if expanded_from is not None:
                token.expanded_from = expanded_from
                token.expanded_count = expanded_from.expanded_count + 1
        return result

def compile_file_to_program(file_path: str, include_paths: List[str], expansion_limit: int, src_dir) -> Program:
    return parse_program_from_tokens(lex_file(file_path), include_paths, expansion_limit, src_dir)
        

def generate_control_flow_graph_as_dot_file(program: Program, dot_path: str):
    print(f"[INFO] Generating {dot_path}")
    with open(dot_path, "w") as f:
        f.write("digraph Program {\n")
        for ip in range(len(program)):
            op = program[ip]
            if op.typ == OpType.INTRINSIC:
                assert isinstance(op.operand, Intrinsic)
                f.write(f"    Node_{ip} [label={repr(repr(INTRINSIC_NAMES[op.operand]))}];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.PUSH_STR:
                assert isinstance(op.operand, str)
                f.write(f"    Node_{ip} [label={repr(repr(op.operand))}];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.PUSH_CSTR:
                assert isinstance(op.operand, str)
                f.write(f"    Node_{ip} [label={repr(repr(op.operand))}];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.PUSH_INT:
                assert isinstance(op.operand, int)
                f.write(f"    Node_{ip} [label={op.operand}]\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.IF:
                f.write(f"    Node_{ip} [shape=record label=if];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.WHILE:
                f.write(f"    Node_{ip} [shape=record label=while];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.DO:
                assert isinstance(op.operand, OpAddr)
                f.write(f"    Node_{ip} [shape=record label=do];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1} [label=true];\n")
                f.write(f"    Node_{ip} -> Node_{op.operand} [label=false style=dashed];\n")
            elif op.typ == OpType.ELSE:
                assert isinstance(op.operand, OpAddr)
                f.write(f"    Node_{ip} [shape=record label=else];\n")
                f.write(f"    Node_{ip} -> Node_{op.operand};\n")
            elif op.typ == OpType.ELIF:
                f.write(f"    Node_{ip} [shape=record label=elif];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.END:
                assert isinstance(op.operand, OpAddr)
                f.write(f"    Node_{ip} [shape=record label=end];\n")
                f.write(f"    Node_{ip} -> Node_{op.operand};\n")
            else:
                assert False, f"unimplemented operation {op.typ}"
        f.write(f"    Node_{len(program)} [label=halt];\n")
        f.write("}\n")
    run_cmd(["dot", "-Tsvg", "-O", dot_path])

def usage(exec):
    print("Usage: mclang [SUBCOMMAND] [FLAGS] [FILE]")
    print("SUBCOMMANDS:")
    print("    c, com, compile                     => Compile the program.")
    print("    s, sim, simulate                    => Simulate/interpret the program.")
    print("FLAGS:")
    print("    -h,  --help                         => Show this help text.")
    print("    --unsafe                            => Skip type checking the source code")
    print("    -r,  --run                          => Run the program after compiling. Only relavent in compile mode.")
    print("    -rm, --remove                       => Remove the build files. Only relavent in compile mode.")
    print("    -o   [FILENAME]                     => Output file.")
    print("    -cf, --control-flow                 => Dumps the control flow to a dot file and compiles it to an svg file.")
    print("    -dm, --dump-memory [DUMP_MEM_SIZE]  => Dump memory from address 0 to [DUMP_MEM_SIZE]. Only relavent in simulate mode.")


def run_compiled_prog(outfile, silent, time):
    if silent != True:
        print(colors.VIOLET + ("Running \"%s\":" % " ".join(outfile)) + colors.RESET);
    exit_code = subprocess.call(outfile);
    if silent != True:
        if exit_code == 0:
            print("\n{green}Process exited normally in {time} seconds.{reset}".format(
                                                    green = colors.GREEN,
                                                    reset = colors.RESET,
                                                    time  = round(time, 4)
                                                        ))
        else:
            print("\n{red}Process exited abnormally with {underline}{code}{reset}{red} exit code in {time} seconds.".format(
                                                                    red = colors.RED,
                                                                    reset = colors.RESET,
                                                                    underline = colors.UNDERLINE,
                                                                    code=exit_code,
                                                                    time=round(time, 4)
                                                                        ))
    return exit_code



def setup_build_env(sourcefile, build_dir = "./build", out_dir = "./out"):
    base_dir = os.path.realpath(os.path.dirname(sourcefile))
    (outfile, ext) = os.path.splitext(sourcefile)
    outfile = PurePath(outfile).parts[-1]
    build_dir = PurePath(build_dir)
    out_dir = PurePath(out_dir)

    os.makedirs(Path(base_dir, build_dir), exist_ok = True)
    os.makedirs(Path(base_dir, build_dir, out_dir), exist_ok = True)

    return {
    "exec_path": str(Path(base_dir, build_dir, outfile)),
    "obj_path":  str(Path(base_dir, build_dir, out_dir , outfile)) + ".o",
    "asm_path":  str(Path(base_dir, build_dir, out_dir , outfile)) + ".asm",
    "dot_path":  str(Path(base_dir, build_dir, out_dir , outfile)) + ".dot",
    "src_path":  str(sourcefile),
    "build_dir": str(os.path.join(base_dir, build_dir))
    }

if __name__ == "__main__":
    start_time = time.time()
    argv = sys.argv
    prog, *argv = argv
    if len(argv) < 1:
        usage(prog);
        print("{red}[ERR]: Not enough arguments. Exiting!{reset}".format(
                                                            red = colors.RED,
                                                            reset = colors.RESET,
                                                                ), file=sys.stderr)
        sys.exit(1);

    argv2 = sys.argv[3:]
    subc, *argv = argv
    input_filepath = ""
    global outfile
    outfile = "output"
    b_run = False
    b_outfile = False
    b_remove = False
    b_silent = False
    b_no_type_check = False
    b_control_flow = False
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
                sys.exit(0);

            elif flag == "-r" or flag == "--run":
                argv2.pop(0)
                b_run = True
            elif flag == "--unsafe":
                argv2.pop(0)
                b_no_type_check = True
            elif flag == "-o":
                argv2.pop(0)
                b_outfile = True
            elif flag == "-s":
                argv2.pop(0)
                b_silent = True
            elif flag == "-rm" or flag == "--remove":
                argv2.pop(0)
                b_remove = True
            elif flag == "-cf" or flag == "--control-flow":
                argv2.pop(0)
                b_control_flow = True
            elif flag == "-dm" or flag == "--dump-memory":
                argv2.pop(0)
                i_dumpmem = -1
            else:
                print("{red}[ERR]: Unknown flag {green}{underline}\"{flag}\"{reset}{red}. Exiting!{reset}".format(
                                                                red = colors.RED,
                                                                green = colors.GREEN,
                                                                reset = colors.RESET,
                                                                underline = colors.UNDERLINE,
                                                                flag=flag
                                                                    ), file=sys.stderr);
                sys.exit(1);
        else:
            if input_filepath == "":
                input_filepath = flag
            break
    # print(input_filepath)
    if input_filepath == "":
        usage(prog)
        print("{red}[ERR]: No file supplied. Exiting!{reset}".format(
                                                    red = colors.RED,
                                                    reset = colors.RESET,
                                                        ), file=sys.stderr);
        sys.exit(1)

    env = setup_build_env(input_filepath)
    # print(subc)
    if subc == "s" or subc == "sim" or subc == "simulate":
        # Tokenising
        token_comp_start_time = time.time()
        program = compile_file_to_program(input_filepath, builtin_lib_path, MAX_MACRO_EXPANSION, env["src_path"]);
        token_comp_time = time.time() - token_comp_start_time
        if b_silent != True:
            print("[INFO]: Tokenisation took {} Seconds".format(round(token_comp_time,4)))

        # TC
        if b_no_type_check != True:
            tc_start_time = time.time()
            type_check_program(program)
            tc_time = time.time() - tc_start_time
            if b_silent != True:
                print("[INFO]: Typechecking took {} Seconds".format(round(tc_time,4)))

        # Sim
        sim_start = time.time()
        simulate_little_endian_linux(program, i_dumpmem, [env["exec_path"]] + argv2)
        sim_time = time.time() - sim_start
        if b_silent != True:
            print("[INFO]: Simulation took {} Seconds".format(round(sim_time,4)))
            print("[INFO]: Everything took {} Seconds".format(round((time.time() - start_time), 4)))
    elif subc == "c" or subc == "com" or subc == "compile":
        # Tokenising
        token_comp_start_time = time.time()
        program = compile_file_to_program(input_filepath, builtin_lib_path, MAX_MACRO_EXPANSION, env["src_path"]);
        token_comp_time = time.time() - token_comp_start_time
        if b_silent != True:
            print("[INFO]: Tokenisation took {} Seconds".format(round(token_comp_time,4)))

        # TC
        if b_no_type_check != True:
            tc_start_time = time.time()
            type_check_program(program)
            tc_time = time.time() - tc_start_time
            if b_silent != True:
                print("[INFO]: Typechecking took {} Seconds".format(round(tc_time,4)))
        # Generating
        asm_start_time = time.time()
        generate_nasm_linux_x86_64(program, env["asm_path"])
        asm_time = time.time() - asm_start_time
        if b_silent != True:
            print("[INFO]: ASM Generation took {} Seconds".format(round(asm_time,4)))

        run_cmd(["nasm", "-felf64", "-o", env["obj_path"], env["asm_path"]], b_silent)
        run_cmd(["ld", "-o", env["exec_path"], env["obj_path"]], b_silent)
        if b_control_flow:
            generate_control_flow_graph_as_dot_file(program, env["dot_path"])
        if b_remove == True:
            run_cmd(["rm", "-f", env["asm_path"], env["obj_path"]], b_silent)
        if b_run == True:
            exit_code = run_compiled_prog([env["exec_path"]] + argv2, b_silent, (time.time() - start_time))
            exit(exit_code)
        if b_silent != True:
            print("[INFO]: Everything took {} Seconds".format(round((time.time() - start_time), 4)))
    else:
        usage(prog);

        print("{red}[ERR]: Unknown subcommand {green}{underline}\"{subcommand}\"{reset}{red}. Exiting!{reset}".format(
                                                                red = colors.RED,
                                                                green = colors.GREEN,
                                                                reset = colors.RESET,
                                                                underline = colors.UNDERLINE,
                                                                subcommand = subc
                                                                    ), file=sys.stderr);
        sys.exit(1);
