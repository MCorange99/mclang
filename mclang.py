#!/usr/bin/env python3
from copy import copy
from genericpath import exists
import sys
import subprocess
import os
from typing import *
from enum import Enum, IntEnum, auto
from dataclasses import dataclass
import traceback
from time import sleep

builtin_lib_path = ["./include"]

MEM_CAPACITY = 640_000 # should be enough
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
    eprint(txt, loc)

def compiler_note(loc, txt):
    nprint(txt)

Loc = Tuple[str, int, int]

class Keyword(Enum):

    # Ops that form blocks
    IF = auto();
    ELSE = auto();
    DO = auto();
    END = auto();
    WHILE = auto();
    MACRO = auto();

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
    TRUE=auto()
    FALSE=auto()
    PRINT=auto()

    # stack ops
    DUP=auto()
    SWAP=auto()
    DROP=auto()
    OVER=auto()
    ROT=auto()

    # memory
    MEM=auto()
    LOAD=auto()
    STORE=auto()
    LOAD64=auto()
    STORE64=auto()
    FORTH_LOAD=auto()
    FORTH_STORE=auto()
    FORTH_LOAD64=auto()
    FORTH_STORE64=auto()

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
    HERE=auto()

class OpType(Enum):
    PUSH_INT=auto()
    PUSH_STR=auto()
    INTRINSIC=auto()
    IF=auto()
    END=auto()
    ELSE=auto()
    WHILE=auto()
    DO=auto()

OpAddr = int
class TokenType(Enum):
    WORD = auto();
    INT = auto();
    STR = auto();
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

Program = List[Op]


def run_cmd(cmd, silent):
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
    mem = bytearray(SIM_NULL_POINTER_PADDING + SIM_STR_CAPACITY + SIM_ARGV_CAPACITY + MEM_CAPACITY)

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
    while ip < len(program):
        assert len(OpType) == 8, "Exhaustive op handling in simulate_little_endian_linux"
        op = program[ip]
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
            elif op.typ == OpType.IF:
                a = stack.pop()
                if a == 0:
                    assert isinstance(op.operand, OpAddr), "This could be a bug in the compilation step"
                    ip = op.operand
                else:
                    ip += 1
            elif op.typ == OpType.ELSE:
                assert isinstance(op.operand, OpAddr), "This could be a bug in the compilation step"
                ip = op.operand
            elif op.typ == OpType.END:
                assert isinstance(op.operand, OpAddr), "This could be a bug in the compilation step"
                ip = op.operand
            elif op.typ == OpType.WHILE:
                ip += 1
            elif op.typ == OpType.DO:
                a = stack.pop()
                if a == 0:
                    assert isinstance(op.operand, OpAddr), "This could be a bug in the compilation step"
                    ip = op.operand
                else:
                    ip += 1
            elif op.typ == OpType.INTRINSIC:
                assert len(Intrinsic) == 43, "Exhaustive handling of intrinsic in simulate_little_endian_linux()"
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
                elif op.operand == Intrinsic.TRUE:
                    stack.append(1)
                    ip += 1
                elif op.operand == Intrinsic.FALSE:
                    stack.append(0)
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
                elif op.operand == Intrinsic.MEM:
                    stack.append(mem_buf_ptr)
                    ip += 1
                elif op.operand == Intrinsic.LOAD:
                    addr = stack.pop()
                    byte = mem[addr]
                    stack.append(byte)
                    ip += 1
                elif op.operand == Intrinsic.STORE:
                    store_value = stack.pop()
                    store_addr = stack.pop()
                    mem[store_addr] = store_value & 0xFF
                    ip += 1
                elif op.operand == Intrinsic.FORTH_LOAD:
                    addr = stack.pop()
                    byte = mem[addr]
                    stack.append(byte)
                    ip += 1
                elif op.operand == Intrinsic.FORTH_STORE:
                    store_addr = stack.pop()
                    store_value = stack.pop()
                    mem[store_addr] = store_value & 0xFF
                    ip += 1
                elif op.operand == Intrinsic.LOAD64:
                    addr = stack.pop()
                    _bytes = bytearray(8)
                    for offset in range(0,8):
                        _bytes[offset] = mem[addr + offset]
                    stack.append(int.from_bytes(_bytes, byteorder="little"))
                    ip += 1
                elif op.operand == Intrinsic.STORE64:
                    store_value = stack.pop()
                    store_value64 = store_value.to_bytes(length=8, byteorder="little", signed=(store_value < 0));
                    store_addr64 = stack.pop();
                    for byte in store_value64:
                        mem[store_addr64] = byte;
                        store_addr64 += 1;
                    ip += 1
                elif op.operand == Intrinsic.FORTH_LOAD64:
                    addr = stack.pop()
                    _bytes = bytearray(8)
                    for offset in range(0,8):
                        _bytes[offset] = mem[addr + offset]
                    stack.append(int.from_bytes(_bytes, byteorder="little"))
                    ip += 1
                elif op.operand == Intrinsic.FORTH_STORE64:
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
                        exit(arg1)
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

def type_check_program(program: Program):
    stack: DataStack = []
    block_stack: List[Tuple[DataStack, OpType]] = []
    errors = 0
    for ip in range(len(program)):
        op = program[ip]
        assert len(OpType) == 8, "Exhaustive ops handling in type_check_program()"
        if op.typ == OpType.PUSH_INT:
            stack.append((DataType.INT, op.token))
        elif op.typ == OpType.PUSH_STR:
            stack.append((DataType.INT, op.token))
            stack.append((DataType.PTR, op.token))
        elif op.typ == OpType.INTRINSIC:
            assert len(Intrinsic) == 43, "Exhaustive intrinsic handling in type_check_program()"
            assert isinstance(op.operand, Intrinsic), "This could be a bug in compilation step"
            if op.operand == Intrinsic.PLUS:
                assert len(DataType) == 3, "Exhaustive type handling in PLUS intrinsic"
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1
                a_type, a_loc = stack.pop()
                b_type, b_loc = stack.pop()

                if a_type == DataType.INT and b_type == DataType.INT:
                    stack.append((DataType.INT, op.token))
                elif a_type == DataType.INT and b_type == DataType.PTR:
                    stack.append((DataType.PTR, op.token))
                elif a_type == DataType.PTR and b_type == DataType.INT:
                    stack.append((DataType.PTR, op.token))
                else:
                    compiler_error(op.token.loc, "invalid argument types for PLUS intrinsic. Expected INT or PTR")
                    errors += 1
            elif op.operand == Intrinsic.MINUS:
                assert len(DataType) == 3, "Exhaustive type handling in MINUS intrinsic"
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1
                a_type, a_loc = stack.pop()
                b_type, b_loc = stack.pop()

                if a_type == b_type and (a_type == DataType.INT or a_type == DataType.PTR):
                    stack.append((DataType.INT, op.token))
                elif b_type == DataType.PTR and a_type == DataType.INT:
                    stack.append((DataType.PTR, op.token))
                else:
                    compiler_error(op.token.loc, "invalid argument types fo MINUS intrinsic: %s" % [b_type, a_type])
                    errors += 1
            elif op.operand == Intrinsic.MUL:
                assert len(DataType) == 3, "Exhaustive type handling in MUL intrinsic"
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1
                a_type, a_loc = stack.pop()
                b_type, b_loc = stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    stack.append((DataType.INT, op.token))
                else:
                    compiler_error(op.token.loc, "invalid argument types fo MUL intrinsic. Expected INT.")
                    errors += 1
            elif op.operand == Intrinsic.DIVMOD:
                assert len(DataType) == 3, "Exhaustive type handling in DIVMOD intrinsic"
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1
                a_type, a_loc = stack.pop()
                b_type, b_loc = stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    stack.append((DataType.INT, op.token))
                    stack.append((DataType.INT, op.token))
                else:
                    compiler_error(op.token.loc, "invalid argument types fo DIVMOD intrinsic. Expected INT.")
                    errors += 1
            elif op.operand == Intrinsic.EQ:
                assert len(DataType) == 3, "Exhaustive type handling in EQ intrinsic"
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1
                a_type, a_loc = stack.pop()
                b_type, b_loc = stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error(op.token.loc, "invalid argument types fo EQ intrinsic. Expected INT.")
                    errors += 1
            elif op.operand == Intrinsic.GT:
                assert len(DataType) == 3, "Exhaustive type handling in GT intrinsic"
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1

                a_type, a_loc = stack.pop()
                b_type, b_loc = stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error(op.token.loc, "invalid argument type for GT intrinsic")
                    errors += 1
            elif op.operand == Intrinsic.LT:
                assert len(DataType) == 3, "Exhaustive type handling in LT intrinsic"
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1

                a_type, a_loc = stack.pop()
                b_type, b_loc = stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error(op.token.loc, "invalid argument type for LT intrinsic")
                    errors += 1
            elif op.operand == Intrinsic.TRUE:
                stack.append((DataType.BOOL, op.token))
            elif op.operand == Intrinsic.FALSE:
                stack.append((DataType.BOOL, op.token))
            elif op.operand == Intrinsic.GE:
                assert len(DataType) == 3, "Exhaustive type handling in GE intrinsic"
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1

                a_type, a_loc = stack.pop()
                b_type, b_loc = stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error(op.token.loc, "invalid argument type for GE intrinsic")
                    errors += 1
            elif op.operand == Intrinsic.LE:
                assert len(DataType) == 3, "Exhaustive type handling in LE intrinsic"
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1

                a_type, a_loc = stack.pop()
                b_type, b_loc = stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error(op.token.loc, "invalid argument type for LE intrinsic")
                    errors += 1
            elif op.operand == Intrinsic.NE:
                assert len(DataType) == 3, "Exhaustive type handling in NE intrinsic"
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1

                a_type, a_loc = stack.pop()
                b_type, b_loc = stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error(op.token.loc, "invalid argument type for NE intrinsic")
                    errors += 1
            elif op.operand == Intrinsic.SHR:
                assert len(DataType) == 3, "Exhaustive type handling in SHR intrinsic"
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1

                a_type, a_loc = stack.pop()
                b_type, b_loc = stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    stack.append((DataType.INT, op.token))
                else:
                    compiler_error(op.token.loc, "invalid argument type for SHR intrinsic")
                    errors += 1
            elif op.operand == Intrinsic.SHL:
                assert len(DataType) == 3, "Exhaustive type handling in SHL intrinsic"
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1

                a_type, a_loc = stack.pop()
                b_type, b_loc = stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    stack.append((DataType.INT, op.token))
                else:
                    compiler_error(op.token.loc, "invalid argument type for SHL intrinsic")
                    errors += 1
            elif op.operand == Intrinsic.OR:
                assert len(DataType) == 3, "Exhaustive type handling in OR intrinsic"
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1

                a_type, a_loc = stack.pop()
                b_type, b_loc = stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    stack.append((DataType.INT, op.token))
                elif a_type == b_type and a_type == DataType.BOOL:
                    stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error(op.token.loc, "invalid argument type for OR intrinsic")
                    errors += 1
            elif op.operand == Intrinsic.AND:
                assert len(DataType) == 3, "Exhaustive type handling in AND intrinsic"
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1

                a_type, a_loc = stack.pop()
                b_type, b_loc = stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    stack.append((DataType.INT, op.token))
                elif a_type == b_type and a_type == DataType.BOOL:
                    stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error(op.token.loc, "invalid argument type for AND intrinsic")
                    errors += 1
            elif op.operand == Intrinsic.NOT:
                assert len(DataType) == 3, "Exhaustive type handling in NOT intrinsic"
                if len(stack) < 1:
                    not_enough_arguments(op)
                    errors += 1
                a_type, a_loc = stack.pop()

                if a_type == DataType.INT:
                    stack.append((DataType.INT, op.token))
                elif a_type == DataType.BOOL:
                    stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error(op.token.loc, "invalid argument type for NOT intrinsic")
                    errors += 1
            elif op.operand == Intrinsic.PRINT:
                if len(stack) < 1:
                    not_enough_arguments(op)
                    errors += 1
                stack.pop()
            elif op.operand == Intrinsic.DUP:
                if len(stack) < 1:
                    not_enough_arguments(op)
                    errors += 1
                a = stack.pop()
                stack.append(a)
                stack.append(a)
            elif op.operand == Intrinsic.SWAP:
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1
                a = stack.pop()
                b = stack.pop()
                stack.append(a)
                stack.append(b)
            elif op.operand == Intrinsic.DROP:
                if len(stack) < 1:
                    not_enough_arguments(op)
                    errors += 1
                stack.pop()
            elif op.operand == Intrinsic.OVER:
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1
                a = stack.pop()
                b = stack.pop()
                stack.append(b)
                stack.append(a)
                stack.append(b)
            elif op.operand == Intrinsic.ROT:
                if len(stack) < 3:
                    not_enough_arguments(op)
                    errors += 1
                a = stack.pop()
                b = stack.pop()
                c = stack.pop()
                stack.append(b)
                stack.append(a)
                stack.append(c)
            elif op.operand == Intrinsic.MEM:
                stack.append((DataType.PTR, op.token))
            elif op.operand == Intrinsic.LOAD:
                assert len(DataType) == 3, "Exhaustive type handling in LOAD intrinsic"
                if len(stack) < 1:
                    not_enough_arguments(op)
                    errors += 1
                a_type, a_loc = stack.pop()

                if a_type == DataType.PTR:
                    stack.append((DataType.INT, op.token))
                else:
                    compiler_error(op.token.loc, "invalid argument type for LOAD intrinsic: %s" % a_type)
                    errors += 1
            elif op.operand == Intrinsic.STORE:
                assert len(DataType) == 3, "Exhaustive type handling in STORE intrinsic"
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1

                a_type, a_loc = stack.pop()
                b_type, b_loc = stack.pop()

                if a_type == DataType.INT and b_type == DataType.PTR:
                    pass
                else:
                    compiler_error(op.token.loc, "invalid argument type for STORE intrinsic")
                    errors += 1
            elif op.operand == Intrinsic.FORTH_LOAD:
                assert len(DataType) == 3, "Exhaustive type handling in LOAD intrinsic"
                if len(stack) < 1:
                    not_enough_arguments(op)
                    errors += 1
                a_type, a_loc = stack.pop()

                if a_type == DataType.PTR:
                    stack.append((DataType.INT, op.token))
                else:
                    compiler_error(op.token.loc, "invalid argument type for LOAD intrinsic: %s" % a_type)
                    errors += 1
            elif op.operand == Intrinsic.FORTH_STORE:
                assert len(DataType) == 3, "Exhaustive type handling in STORE intrinsic"
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1

                a_type, a_loc = stack.pop()
                b_type, b_loc = stack.pop()

                if a_type == DataType.PTR and b_type == DataType.INT:
                    pass
                else:
                    compiler_error(op.token.loc, "invalid argument type for STORE intrinsic")
                    errors += 1
            elif op.operand == Intrinsic.LOAD64:
                assert len(DataType) == 3, "Exhaustive type handling in LOAD64 intrinsic"
                if len(stack) < 1:
                    not_enough_arguments(op)
                    errors += 1
                a_type, a_loc = stack.pop()

                if a_type == DataType.PTR:
                    stack.append((DataType.INT, op.token))
                else:
                    compiler_error(op.token.loc, "invalid argument type for LOAD64 intrinsic")
                    errors += 1
            elif op.operand == Intrinsic.STORE64:
                assert len(DataType) == 3, "Exhaustive type handling in STORE64 intrinsic"
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1

                a_type, a_loc = stack.pop()
                b_type, b_loc = stack.pop()

                if (a_type == DataType.INT or a_type == DataType.PTR) and b_type == DataType.PTR:
                    pass
                else:
                    compiler_error(op.token.loc, "invalid argument type for STORE64 intrinsic: %s" % [b_type, a_type])
                    errors += 1
            elif op.operand == Intrinsic.FORTH_LOAD64:
                assert len(DataType) == 3, "Exhaustive type handling in LOAD64 intrinsic"
                if len(stack) < 1:
                    not_enough_arguments(op)
                    errors += 1
                a_type, a_loc = stack.pop()

                if a_type == DataType.PTR:
                    stack.append((DataType.INT, op.token))
                else:
                    compiler_error(op.token.loc, "invalid argument type for LOAD64 intrinsic")
                    errors += 1
            elif op.operand == Intrinsic.FORTH_STORE64:
                assert len(DataType) == 3, "Exhaustive type handling in STORE64 intrinsic"
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1

                a_type, a_loc = stack.pop()
                b_type, b_loc = stack.pop()

                if (b_type == DataType.INT or b_type == DataType.PTR) and a_type == DataType.PTR:
                    pass
                else:
                    compiler_error(op.token.loc, "invalid argument type for STORE64 intrinsic: %s" % [b_type, a_type])
                    errors += 1
            elif op.operand == Intrinsic.CAST_PTR:
                if len(stack) < 1:
                    not_enough_arguments(op)
                    errors += 1

                a_type, a_token = stack.pop()

                stack.append((DataType.PTR, a_token))
            elif op.operand == Intrinsic.ARGC:
                stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.ARGV:
                stack.append((DataType.PTR, op.token))
            elif op.operand == Intrinsic.HERE:
                stack.append((DataType.INT, op.token))
                stack.append((DataType.PTR, op.token))
            # TODO: figure out how to type check syscall arguments and return types
            elif op.operand == Intrinsic.SYSCALL0:
                if len(stack) < 1:
                    not_enough_arguments(op)
                    errors += 1
                for i in range(1):
                    stack.pop()
                stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL1:
                if len(stack) < 2:
                    not_enough_arguments(op)
                    errors += 1
                for i in range(2):
                    stack.pop()
                stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL2:
                if len(stack) < 3:
                    not_enough_arguments(op)
                    errors += 1
                for i in range(3):
                    stack.pop()
                stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL3:
                if len(stack) < 4:
                    not_enough_arguments(op)
                    errors += 1
                for i in range(4):
                    stack.pop()
                stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL4:
                if len(stack) < 5:
                    not_enough_arguments(op)
                    errors += 1
                for i in range(5):
                    stack.pop()
                stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL5:
                if len(stack) < 6:
                    not_enough_arguments(op)
                    errors += 1
                for i in range(6):
                    stack.pop()
                stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL6:
                if len(stack) < 7:
                    not_enough_arguments(op)
                    errors += 1
                for i in range(7):
                    stack.pop()
                stack.append((DataType.INT, op.token))
            else:
                assert False, "unreachable"
        elif op.typ == OpType.IF:
            if len(stack) < 1:
                not_enough_arguments(op)
                errors += 1
            a_type, a_token = stack.pop()
            if a_type != DataType.BOOL:
                compiler_error(op.token.loc, "Invalid argument for the if-block condition. Expected BOOL.")
                errors += 1
            block_stack.append((copy(stack), op.typ))
        elif op.typ == OpType.END:
            block_snapshot, block_type = block_stack.pop()
            assert len(OpType) == 8, "Exhaustive handling of op types"
            if block_type == OpType.IF:
                expected_types = list(map(lambda x: x[0], block_snapshot))
                actual_types = list(map(lambda x: x[0], stack))
                if expected_types != actual_types:
                    compiler_error(op.token.loc, 'else-less if block is not allowed to alter the types of the arguments on the data stack')
                    compiler_note(op.token.loc, 'Expected types: %s' % expected_types)
                    compiler_note(op.token.loc, 'Actual types: %s' % actual_types)
                    errors += 1
            elif block_type == OpType.ELSE:
                expected_types = list(map(lambda x: x[0], block_snapshot))
                actual_types = list(map(lambda x: x[0], stack))
                if expected_types != actual_types:
                    compiler_error(op.token.loc, 'both branches of the if-block must produce the same types of the arguments on the data stack')
                    compiler_note(op.token.loc, 'Expected types: %s' % expected_types)
                    compiler_note(op.token.loc, 'Actual types: %s' % actual_types)
                    errors += 1
            elif block_type == OpType.DO:
                while_snapshot, while_type = block_stack.pop()
                assert while_type == OpType.WHILE

                expected_types = list(map(lambda x: x[0], while_snapshot))
                actual_types = list(map(lambda x: x[0], stack))

                if expected_types != actual_types:
                    compiler_error(op.token.loc, 'while-do body is not allowed to alter the types of the arguments on the data stack')
                    compiler_note(op.token.loc, 'Expected types: %s' % expected_types)
                    compiler_note(op.token.loc, 'Actual types: %s' % actual_types)
                    errors += 1

                stack = block_snapshot
            else:
                assert "unreachable"
        elif op.typ == OpType.ELSE:
            stack_snapshot, block_type = block_stack.pop()
            assert block_type == OpType.IF
            block_stack.append((copy(stack), op.typ))
            stack = stack_snapshot
        elif op.typ == OpType.WHILE:
            block_stack.append((copy(stack), op.typ))
        elif op.typ == OpType.DO:
            if len(stack) < 1:
                not_enough_arguments(op)
                errors += 1
            a_type, a_token = stack.pop()
            if a_type != DataType.BOOL:
                compiler_error(op.token, "Invalid argument for the while-do condition. Expected BOOL.")
                errors += 1
            block_stack.append((copy(stack), op.typ))
        else:
            assert False, "unreachable"
    if len(stack) != 0:
        compiler_error(stack[-1][1], "unhandled data on the stack: %s" % list(map(lambda x: x[0], stack)))
        errors += 1

    if errors > 0:
        eprint("Could not compile program due to {} previous errors.".format(errors))
        exit(1)


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
        for ip in range(len(program)):
            op = program[ip]
            assert len(OpType) == 8, "Exhaustive ops handling in generate_nasm_linux_x86_64"
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
            elif op.typ == OpType.IF:
                out.write("    ;; -- if --\n")
                out.write("    pop rax\n")
                out.write("    test rax, rax\n")
                assert isinstance(op.operand, int), "This could be a bug in the compilation step"
                out.write("    jz addr_%d\n" % op.operand)
            elif op.typ == OpType.ELSE:
                out.write("    ;; -- else --\n")
                assert isinstance(op.operand, int), "This could be a bug in the compilation step"
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
                assert len(Intrinsic) == 43, "Exhaustive intrinsic handling in generate_nasm_linux_x86_64()"
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
                elif op.operand == Intrinsic.TRUE:
                    out.write("    ;; -- true --\n")
                    out.write("    mov rax, 1\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.FALSE:
                    out.write("    ;; -- false --\n")
                    out.write("    mov rax, 0\n")
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
                elif op.operand == Intrinsic.MEM:
                    out.write("    ;; -- mem --\n")
                    out.write("    push mem\n")
                elif op.operand == Intrinsic.LOAD:
                    out.write("    ;; -- load --\n")
                    out.write("    pop rax\n")
                    out.write("    xor rbx, rbx\n")
                    out.write("    mov bl, [rax]\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.STORE:
                    out.write("    ;; -- store --\n")
                    out.write("    pop rbx\n");
                    out.write("    pop rax\n");
                    out.write("    mov [rax], bl\n");
                elif op.operand == Intrinsic.FORTH_LOAD:
                    out.write("    ;; -- forth load --\n")
                    out.write("    pop rax\n")
                    out.write("    xor rbx, rbx\n")
                    out.write("    mov bl, [rax]\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.FORTH_STORE:
                    out.write("    ;; -- store --\n")
                    out.write("    pop rax\n");
                    out.write("    pop rbx\n");
                    out.write("    mov [rax], bl\n");
                elif op.operand == Intrinsic.LOAD64:
                    out.write("    ;; -- load --\n")
                    out.write("    pop rax\n")
                    out.write("    xor rbx, rbx\n")
                    out.write("    mov rbx, [rax]\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.STORE64:
                    out.write("    ;; -- store --\n")
                    out.write("    pop rbx\n");
                    out.write("    pop rax\n");
                    out.write("    mov [rax], rbx\n");
                elif op.operand == Intrinsic.FORTH_LOAD64:
                    out.write("    ;; -- forth load64 --\n")
                    out.write("    pop rax\n")
                    out.write("    xor rbx, rbx\n")
                    out.write("    mov rbx, [rax]\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.FORTH_STORE64:
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
                    assert False, "unreachable"
            else:
                assert False, "unreachable"

        out.write("addr_%d:\n" % len(program))
        out.write("    mov rax, 60\n")
        out.write("    mov rdi, 0\n")
        out.write("    syscall\n")
        out.write("segment .data\n")

        for index, s in enumerate(strs):
            out.write("; %s\n" % str(s).encode("unicode_escape").decode("utf-8"))
            out.write("str_%d: db %s" % (index, ",".join(map(hex, list(s))) + "\n\n"))
            
        out.write("segment .bss\n")
        out.write("    args_ptr: resq 1\n")
        out.write("    mem: resb %d\n" % MEM_CAPACITY)


assert len(Keyword) == 7, "Exhaustive KEYWORD_NAMES definition."
KEYWORD_NAMES = {
    'if': Keyword.IF,
    'end': Keyword.END,
    'else': Keyword.ELSE,
    'while': Keyword.WHILE,
    'do': Keyword.DO,
    'macro': Keyword.MACRO,
    'include': Keyword.INCLUDE,
}


assert len(Intrinsic) == 43, "Exhaustive INTRINSIC_NAMES definition"
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
    '>>': Intrinsic.SHR,
    'shr': Intrinsic.SHL,
    '<<': Intrinsic.SHL,
    'or': Intrinsic.OR,
    '|': Intrinsic.OR,
    'and': Intrinsic.AND,
    '&': Intrinsic.AND,
    'dup': Intrinsic.DUP,
    'swap': Intrinsic.SWAP,
    'drop': Intrinsic.DROP,
    'over': Intrinsic.OVER,
    'mem': Intrinsic.MEM,
    'store': Intrinsic.STORE,
    'load': Intrinsic.LOAD,
    'store64': Intrinsic.STORE64,
    'load64': Intrinsic.LOAD64,
    '!8': Intrinsic.FORTH_STORE,
    '@8': Intrinsic.FORTH_LOAD,
    '!64': Intrinsic.FORTH_STORE64,
    '@64': Intrinsic.FORTH_LOAD64,
    'cast(ptr)': Intrinsic.CAST_PTR,
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
    'true': Intrinsic.TRUE,
    'false': Intrinsic.FALSE,
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
    else:
        return "UNKNOWN"

def expand_macro(macro: Macro, expanded_from: Token) -> List[Token]:
    result = list(map(lambda x: copy(x), macro.tokens))
    for token in result:
        token.expanded_from = expanded_from
        token.expanded_count = expanded_from.expanded_count + 1
    return result


def compile_tokens_to_program(tokens: List[Token], include_paths: List[str], expansion_limit: int, src_dir) -> Program:
    stack: List[OpAddr] = []
    program: List[Op] = []
    rtokens: List[Token] = list(reversed(tokens))
    macros: Dict[str, Macro] = {}
    errors = 0
    ip: OpAddr = 0;
    while len(rtokens) > 0:
        token = rtokens.pop()
        assert len(TokenType) == 5, "Exhaustive token handling in compile_tokens_to_program"
        if token.typ == TokenType.WORD:
            assert isinstance(token.value, str), "This could be a bug in the lexer"
            if token.value in INTRINSIC_BY_NAMES:
                program.append(Op(typ=OpType.INTRINSIC, token=token, operand=INTRINSIC_BY_NAMES[token.value]))
                ip += 1
            elif token.value in macros:
                if token.expanded_count >= expansion_limit:
                    eprint("the macro exceeded the expansion limit (it expanded %d times)" % token.expanded_count, token.loc)
                    exit(1)
                rtokens += reversed(expand_macro(macros[token.value], token))
            else:
                eprint("Unknown word %s" % token.value, token.loc)
                exit(1)
        elif token.typ == TokenType.INT:
            assert isinstance(token.value, int), "This could be a bug in the lexer"
            program.append(Op(typ=OpType.PUSH_INT, operand=token.value, token=token))
            ip += 1
        elif token.typ == TokenType.STR:
            assert isinstance(token.value, str), "This could be a bug in the lexer"
            program.append(Op(typ=OpType.PUSH_STR, operand=token.value, token=token));
            ip += 1
        elif token.typ == TokenType.CHAR:
            assert isinstance(token.value, int)
            program.append(Op(typ=OpType.PUSH_INT, operand=token.value, token=token));
            ip += 1
        elif token.typ == TokenType.KEYWORD:
            assert len(Keyword) == 7, "Exhaustive keywords handling in compile_tokens_to_program()"
            if token.value == Keyword.IF:
                program.append(Op(typ=OpType.IF, token=token))
                stack.append(ip)
                ip += 1
            elif token.value == Keyword.ELSE:
                program.append(Op(typ=OpType.ELSE, token=token))
                if_ip = stack.pop()
                if program[if_ip].typ != OpType.IF:
                    eprint('`else` can only be used in `if`-blocks', token.loc)
                    errors += 1
                program[if_ip].operand = ip + 1
                stack.append(ip)
                ip += 1
            elif token.value == Keyword.END:
                program.append(Op(typ=OpType.END, token=token))
                block_ip = stack.pop()
                if program[block_ip].typ == OpType.IF or program[block_ip].typ == OpType.ELSE:
                    program[block_ip].operand = ip
                    program[ip].operand = ip + 1
                elif program[block_ip].typ == OpType.DO:
                    assert program[block_ip].operand is not None
                    program[ip].operand = program[block_ip].operand
                    program[block_ip].operand = ip + 1
                else:
                    eprint('`end` can only close `if`, `else` or `do` blocks for now', program[block_ip].token.loc)
                    errors += 1
                ip += 1
            elif token.value == Keyword.WHILE:
                program.append(Op(typ=OpType.WHILE, token=token))
                stack.append(ip)
                ip += 1
            elif token.value == Keyword.DO:
                program.append(Op(typ=OpType.DO, token=token))
                while_ip = stack.pop()
                program[ip].operand = while_ip
                stack.append(ip)
                ip += 1
            elif token.value == Keyword.INCLUDE:
                if len(rtokens) == 0:
                    eprint("expected path to the include file but found nothing", token.loc)
                    exit(1)
                token = rtokens.pop()
                if token.typ != TokenType.STR:
                    eprint("expected path to the include file to be %s but found %s" % (human(TokenType.STR), human(token.typ)), token.loc)
                    exit(1)
                assert isinstance(token.value, str), "This is probably a bug in the lexer"
                file_included = False

                if token.expanded_count >= expansion_limit:
                    eprint("the include exceeded the expansion limit (it expanded %d times)" % token.expanded_count, token.loc)
                    exit(1)
                if exists(os.path.join(src_dir, token.value)):
                    if token.expanded_count >= expansion_limit:
                            eprint("the include exceeded the expansion limit (it expanded %d times)" % token.expanded_count, token.loc)
                            exit(1)
                    rtokens += reversed(lex_file(os.path.join(src_dir, token.value), token))
                    file_included = True
                if file_included == False:
                    for include_path in include_paths:
                        try:
                            if token.expanded_count >= expansion_limit:
                                eprint("the include exceeded the expansion limit (it expanded %d times)" % token.expanded_count, token.loc)
                                exit(1)
                            rtokens += reversed(lex_file(os.path.join(include_path, token.value), token))
                            file_included = True
                            break
                        except FileNotFoundError:
                            continue
                if not file_included:
                    eprint("file `%s` not found" % token.value, token.loc)
                    exit(1)
            elif token.value == Keyword.MACRO:
                if len(rtokens) == 0:
                    eprint("expected macro name but found nothing", token.loc)
                    exit(1)
                token = rtokens.pop()
                if token.typ != TokenType.WORD:
                    eprint("expected macro name to be %s but found %s" % (human(TokenType.WORD), human(token.typ)), token.loc)
                    exit(1)
                assert isinstance(token.value, str), "This is probably a bug in the lexer"
                if token.value in macros:
                    eprint("redefinition of already existing macro `%s`" % token.value, token.loc)
                    eprint("the first definition is located here", macros[token.value].loc)
                    exit(1)
                # print(INTRINSIC_BY_NAMES)
                # print(token.value)
                if token.value in INTRINSIC_BY_NAMES:
                    eprint("redefinition of an intrinsic word `%s`. Please choose a different name for your macro." % (token.value, ), token.loc)
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
                    eprint("expected `end` at the end of the macro definition but got `%s`" % (token.value, ), token.loc)
                    exit(1)
            else:
                assert False, 'unreachable';
        else:
            assert False, 'unreachable'


    if len(stack) > 0:
        eprint('unclosed block', program[stack.pop()].token.loc)
        errors += 1
    if errors > 0:
        eprint("Could not compile program due to {} previous errors.".format(errors))
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
    assert len(TokenType) == 5, 'Exhaustive handling of token types in lex_lines'
    row = 0
    str_literal_buf = ""
    while row < len(lines):
        line = lines[row]
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
                    eprint("unclosed string literal",loc)
                    exit(1)
                text_of_token = str_literal_buf
                str_literal_buf = ""
                yield Token(TokenType.STR, text_of_token, loc, unescape_string(text_of_token))
                col = find_col(line, col_end+1, lambda x: not x.isspace())
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
    return compile_tokens_to_program(lex_file(file_path), include_paths, expansion_limit, src_dir)
        

# simulate_program(program)

def usage(exec):
    print("Usage: %s [SUBCOMMAND] [FLAGS] [FILE]" % exec)
    print("SUBCOMMANDS:")
    print("    c, com, compile                     => Compile the program.")
    print("    s, sim, simulate                    => Simulate/interpret the program.")
    print("FLAGS:")
    print("    -h, --help                          => Show this help text.")
    print("    --no-typecheck                      => Skip type checking the source code")
    print("    -r, --run                           => Run the program after compiling. Only relavent in compile mode.")
    print("    -rm, --remove                       => Remove the out.asm and out.o files. Only relavent in compile mode.")
    print("    -o [FILENAME]                       => The name of the compile program.")
    print("    -dm, --dump-memory [DUMP_MEM_SIZE]  => Dump memory from address 0 to [DUMP_MEM_SIZE]. Only relavent in simulate mode.")


def run_compiled_prog(outfile, silent):
    if silent != True:
        print("Running \"%s\":" % " ".join(outfile));
    exit_code = subprocess.call(outfile);
    if silent != True:
        if exit_code == 0:
            print("\n{green}Process exited normally.{reset}".format(
                                                    green = colors.GREEN,
                                                    reset = colors.RESET,
                                                        ))
        else:
            print("\n{red}Process exited abnormally with {underline}{code}{reset}{red} exit code.".format(
                                                                    red = colors.RED,
                                                                    reset = colors.RESET,
                                                                    underline = colors.UNDERLINE,
                                                                    code=exit_code
                                                                        ))
    return exit_code



def setup_build_env(outfile, build_dir = "build", obj_dir = "build/obj", asm_dir = "build/asm"):
    basepath = ""
    if "/" in outfile:
        basepath = "/".join(outfile.split("/")[:-1]) + "/"

    elif "\\" in outfile:
        assert False, "{red}Windows support is not implemented{reset}".format(
                                                                red = colors.RED,
                                                                reset = colors.RESET,
                                                                    )

    os.makedirs(basepath + build_dir, exist_ok = True)
    os.makedirs(basepath + obj_dir, exist_ok = True)
    os.makedirs(basepath + asm_dir, exist_ok = True)
        
    return (basepath + build_dir + "/" + outfile.split("/")[-1], 
            basepath + obj_dir + "/" + outfile.split("/")[-1] + ".o", 
            basepath + asm_dir + "/" + outfile.split("/")[-1] + ".asm",
            os.path.realpath(basepath), 
            )

if __name__ == "__main__":
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
            elif flag == "--no-typecheck":
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
                b_noremove = True
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
    outfile = ".".join(input_filepath.split(".")[:-1])

    (build_path, obj_path, asm_path, source_dir) = setup_build_env(outfile)

    # print(subc)
    if subc == "s" or subc == "sim" or subc == "simulate":

        program = compile_file_to_program(input_filepath, builtin_lib_path, MAX_MACRO_EXPANSION, source_dir);
        if b_no_type_check != True:
            type_check_program(program)
        simulate_little_endian_linux(program, i_dumpmem, [build_path] + argv2)
    elif subc == "c" or subc == "com" or subc == "compile":
        program = compile_file_to_program(input_filepath, builtin_lib_path, MAX_MACRO_EXPANSION, source_dir);
        if b_no_type_check != True:
            type_check_program(program)
        generate_nasm_linux_x86_64(program, asm_path)
        run_cmd(["nasm", "-felf64", "-o", obj_path, asm_path], b_silent)
        run_cmd(["ld", "-o", build_path, obj_path], b_silent)

        if b_remove == True:
            run_cmd(["rm", "-f", asm_path, obj_path], b_silent)
        if b_run == True:
            exit_code = run_compiled_prog([build_path] + argv2, b_silent)
            exit(exit_code)
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
