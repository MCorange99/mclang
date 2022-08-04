#!/usr/bin/env python3
from audioop import add
import sys
import subprocess
import os

MEMORY_SIZE = 640_000 # should be enough

class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def run_cmd(cmd):
    print("[CMD]: %s" % ' '.join(cmd));
    subprocess.call(cmd);

IOTA_COUNTER = 0
def iota(reset=False):
    global IOTA_COUNTER
    if reset:
        IOTA_COUNTER = 0
    result = IOTA_COUNTER
    IOTA_COUNTER += 1
    return result

OP_PUSH = iota(True);
OP_PLUS = iota();
OP_MINUS = iota();
OP_EQUAL = iota();
OP_IF = iota();
OP_END = iota();
OP_ELSE = iota();
OP_DUMP = iota();
OP_DUP = iota();
OP_GT = iota();
OP_LT = iota();
OP_WHILE = iota();
OP_DO = iota();
OP_MEM = iota();
OP_LOAD = iota();
OP_STORE = iota();
OP_SYSCALL1 = iota();
OP_SYSCALL2 = iota();
OP_SYSCALL3 = iota();
OP_SYSCALL4 = iota();
OP_SYSCALL5 = iota();
OP_SYSCALL6 = iota();
OP_2DUP=iota();
OP_SWAP=iota();
OP_DROP=iota();
OP_SHR=iota();
OP_SHL=iota();
OP_BOR=iota();
OP_BAND=iota();
OP_OVER=iota();
COUNT_OPS = iota();


TOKEN_WORD = iota(True);
TOKEN_INT = iota();
COUNT_TOKENS = iota();


def simulate_program(program, dump_mem=0):
    stack = []
    mem = bytearray(MEMORY_SIZE)
    ip = 0
    while ip < len(program):
        assert COUNT_OPS == 30, "Exhaustive handling of operations in simulation"
        op = program[ip]
        if op['type'] == OP_PUSH:
            stack.append(op['value'])
            ip += 1
        elif op['type'] == OP_PLUS:
            a = stack.pop()
            b = stack.pop()
            stack.append(a + b)
            ip += 1
        elif op['type'] == OP_MINUS:
            a = stack.pop()
            b = stack.pop()
            stack.append(b - a)
            ip += 1
        elif op['type'] == OP_EQUAL:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(a == b))
            ip += 1
        elif op['type'] == OP_SHR:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(b >> a))
            ip += 1
        elif op['type'] == OP_SHL:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(b << a))
            ip += 1
        elif op['type'] == OP_BOR:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(a | b))
            ip += 1
        elif op['type'] == OP_BAND:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(a & b))
            ip += 1
        elif op['type'] == OP_IF:
            a = stack.pop()
            if a == 0:
                assert len(op) >= 2, "`if` instruction does not have a reference to the end of its block. Please call crossreference_blocks() on the program before trying to simulate it"
                ip = op['jmp']
            else:
                ip += 1
        elif op['type'] == OP_ELSE:
            assert len(op) >= 2, "`else` instruction does not have a reference to the end of its block. Please call crossreference_blocks() on the program before trying to simulate it"
            ip = op['jmp']
        elif op['type'] == OP_END:
            assert len(op) >= 2, "`end` instruction does not have a reference to the next instruction to jump to. Please call crossreference_blocks() on the program before trying to simulate it"
            ip = op['jmp']
        elif op['type'] == OP_DUMP:
            a = stack.pop()
            print(a)
            ip += 1
        elif op['type'] == OP_DUP:
            a = stack.pop()
            stack.append(a)
            stack.append(a)
            ip += 1
        elif op['type'] == OP_2DUP:
            b = stack.pop()
            a = stack.pop()
            stack.append(a)
            stack.append(b)
            stack.append(a)
            stack.append(b)
            ip += 1
        elif op['type'] == OP_SWAP:
            a = stack.pop()
            b = stack.pop()
            stack.append(a)
            stack.append(b)
            ip += 1
        elif op['type'] == OP_DROP:
            stack.pop()
            ip += 1
        elif op['type'] == OP_GT:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(a < b))
            ip += 1
        elif op['type'] == OP_LT:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(a > b))
            ip += 1
        elif op['type'] == OP_WHILE:
            ip += 1
        elif op['type'] == OP_DO:
            a = stack.pop()
            if a == 0:
                assert len(op) >= 2, "`end` instruction does not have a reference to the next instruction to jump to. Please call crossreference_blocks() on the program before trying to simulate it"
                ip = op['jmp']
            else:
                ip += 1
        elif op['type'] == OP_MEM:
            stack.append(0)
            ip += 1
        elif op['type'] == OP_LOAD:
            addr = stack.pop()
            byte = mem[addr]
            stack.append(byte)
            ip += 1
        elif op['type'] == OP_STORE:
            value = stack.pop()
            addr = stack.pop()
            mem[addr] = value % 0xFF
            ip += 1
        elif op['type'] == OP_SYSCALL1:
            assert False, "Not implemented"
        elif op['type'] == OP_SYSCALL2:
            assert False, "Not implemented"
        elif op['type'] == OP_SYSCALL3:
            syscall_num = stack.pop()
            arg1 = stack.pop()
            arg2 = stack.pop()
            arg3 = stack.pop()
            if syscall_num == 1:
                fd = arg1
                buf = arg2
                count = arg3
                s = mem[buf:buf+count].decode("utf-8")
                if fd == 1:
                    print(s, end='')
                elif fd == 2:
                    print(s, end='', file=sys.stderr)
                else:
                    assert False, "Unknown file descriptor %d" % arg1
            else:
                assert False, "Unknown syscall number %d" % syscall_num
            ip += 1
        elif op['type'] == OP_SYSCALL4:
            assert False, "Not implemented"
        elif op['type'] == OP_SYSCALL5:
            assert False, "Not implemented"
        elif op['type'] == OP_SYSCALL6:
            assert False, "Not implemented"
        elif op['type'] == OP_OVER:
            a = stack.pop()
            b = stack.pop()
            stack.append(b)
            stack.append(a)
            stack.append(b)
            ip += 1
        else:
            assert False, "Unreachable"
    if dump_mem > 0:
        print(mem[:dump_mem])

def compile_program(program, file_path):
    print("[INFO]: Generating %s" % file_path)
    with open(file_path, "w") as out:
        out.write("segment .text\n\n")
        out.write("dump:\n")
        out.write("    mov r9, -3689348814741910323\n")
        out.write("    sub rsp, 40\n")
        out.write("    mov BYTE [rsp+31], 10\n")
        out.write("    lea rcx, [rsp+30]\n")
        out.write(".L2:\n")
        out.write("    mov rax, rdi\n")
        out.write("    lea r8, [rsp+32]\n")
        out.write("    mul r9\n")
        out.write("    mov rax, rdi\n")
        out.write("    sub r8, rcx\n")
        out.write("    shr rdx, 3\n")
        out.write("    lea rsi, [rdx+rdx*4]\n")
        out.write("    add rsi, rsi\n")
        out.write("    sub rax, rsi\n")
        out.write("    add eax, 48\n")
        out.write("    mov BYTE [rcx], al\n")
        out.write("    mov rax, rdi\n")
        out.write("    mov rdi, rdx\n")
        out.write("    mov rdx, rcx\n")
        out.write("    sub rcx, 1\n")
        out.write("    cmp rax, 9\n")
        out.write("    ja  .L2\n")
        out.write("    lea rax, [rsp+32]\n")
        out.write("    mov edi, 1\n")
        out.write("    sub rdx, rax\n")
        out.write("    xor eax, eax\n")
        out.write("    lea rsi, [rsp+32+rdx]\n")
        out.write("    mov rdx, r8\n")
        out.write("    mov rax, 1\n")
        out.write("    syscall\n")
        out.write("    add rsp, 40\n")
        out.write("    ret\n")
        out.write("global _start\n")
        out.write("_start:\n")
        for ip in range(len(program)):
            op = program[ip]
            assert COUNT_OPS == 30, "Exhaustive handling of ops in compilation"
            out.write("addr_%d:\n" % ip)
            if op['type'] == OP_PUSH:
                out.write("    ;; -- push %d --\n" % op['value'])
                out.write("    push %d\n" % op['value'])
            elif op['type'] == OP_PLUS:
                out.write("    ;; -- plus --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    add rax, rbx\n")
                out.write("    push rax\n")
            elif op['type'] == OP_MINUS:
                out.write("    ;; -- minus --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    sub rbx, rax\n")
                out.write("    push rbx\n")
            elif op['type'] == OP_SHR:
                out.write("    ;; -- shr --\n")
                out.write("    pop rcx\n")
                out.write("    pop rbx\n")
                out.write("    shr rbx, cl\n")
                out.write("    push rbx\n")
            elif op['type'] == OP_SHL:
                out.write("    ;; -- shl --\n")
                out.write("    pop rcx\n")
                out.write("    pop rbx\n")
                out.write("    shl rbx, cl\n")
                out.write("    push rbx\n")
            elif op['type'] == OP_BOR:
                out.write("    ;; -- bor --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    or rbx, rax\n")
                out.write("    push rbx\n")
            elif op['type'] == OP_BAND:
                out.write("    ;; -- band --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    and rbx, rax\n")
                out.write("    push rbx\n")
            elif op['type'] == OP_DUMP:
                out.write("    ;; -- dump --\n")
                out.write("    pop rdi\n")
                out.write("    call dump\n")
            elif op['type'] == OP_EQUAL:
                out.write("    ;; -- equal -- \n")
                out.write("    mov rcx, 0\n");
                out.write("    mov rdx, 1\n");
                out.write("    pop rax\n");
                out.write("    pop rbx\n");
                out.write("    cmp rax, rbx\n");
                out.write("    cmove rcx, rdx\n");
                out.write("    push rcx\n")
            elif op['type'] == OP_IF:
                out.write("    ;; -- if --\n")
                out.write("    pop rax\n")
                out.write("    test rax, rax\n")
                assert 'jmp' in op, "`if` instruction does not have a reference to the end of its block. Please call crossreference_blocks() on the program before trying to compile it"
                out.write("    jz addr_%d\n" % op['jmp'])
            elif op['type'] == OP_ELSE:
                out.write("    ;; -- else --\n")
                assert 'jmp' in op, "`else` instruction does not have a reference to the end of its block. Please call crossreference_blocks() on the program before trying to compile it"
                out.write("    jmp addr_%d\n" % op['jmp'])
            elif op['type'] == OP_END:
                assert 'jmp' in op, "`end` instruction does not have a reference to the next instruction to jump to. Please call crossreference_blocks() on the program before trying to compile it"
                out.write("    ;; -- end --\n")
                if ip + 1 != op['jmp']:
                    out.write("    jmp addr_%d\n" % op['jmp'])
            elif op['type'] == OP_DUP:
                out.write("    ;; -- dup -- \n")
                out.write("    pop rax\n")
                out.write("    push rax\n")
                out.write("    push rax\n")
            elif op['type'] == OP_2DUP:
                out.write("    ;; -- 2dup -- \n")
                out.write("    pop rbx\n")
                out.write("    pop rax\n")
                out.write("    push rax\n")
                out.write("    push rbx\n")
                out.write("    push rax\n")
                out.write("    push rbx\n")
            elif op['type'] == OP_SWAP:
                out.write("    ;; -- swap --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    push rax\n")
                out.write("    push rbx\n")
            elif op['type'] == OP_DROP:
                out.write("    ;; -- drop --\n")
                out.write("    pop rax\n")
            elif op['type'] == OP_GT:
                out.write("    ; -- greater than (>) --\n")
                out.write("    mov rcx, 0\n");
                out.write("    mov rdx, 1\n");
                out.write("    pop rbx\n");
                out.write("    pop rax\n");
                out.write("    cmp rax, rbx\n");
                out.write("    cmovg rcx, rdx\n");
                out.write("    push rcx\n")
            elif op['type'] == OP_LT:
                out.write("    ; -- greater than (>) --\n")
                out.write("    mov rcx, 0\n");
                out.write("    mov rdx, 1\n");
                out.write("    pop rbx\n");
                out.write("    pop rax\n");
                out.write("    cmp rax, rbx\n");
                out.write("    cmovl rcx, rdx\n");
                out.write("    push rcx\n")
            elif op['type'] == OP_WHILE:
                out.write("    ;; -- while --\n")
            elif op['type'] == OP_DO:
                out.write("    ;; -- do --\n")
                out.write("    pop rax\n")
                out.write("    test rax, rax\n")
                assert 'jmp' in op, "`do` instruction does not have a reference to the end of its block. Please call crossreference_blocks() on the program before trying to compile it"
                out.write("    jz addr_%d\n" % op['jmp'])
            elif op['type'] == OP_MEM:
                out.write("    ; -- mem --\n")
                out.write("    push mem\n")
            elif op['type'] == OP_LOAD:
                out.write("    ; -- mem load --\n")
                out.write("    pop rax\n")
                out.write("    xor rbx, rbx\n")
                out.write("    mov bl, [rax]\n")
                out.write("    push rbx\n")
            elif op['type'] == OP_STORE:
                out.write("    ; -- mem store --\n")
                out.write("    pop rbx\n")
                out.write("    pop rax\n")
                out.write("    mov [rax], bl\n")
            elif op['type'] == OP_SYSCALL1:
                out.write("    ;; -- syscall1 --\n")
                out.write("    pop rax\n")
                out.write("    pop rdi\n")
                out.write("    syscall\n")
            elif op['type'] == OP_SYSCALL2:
                out.write("    ;; -- syscall2 -- \n")
                out.write("    pop rax\n");
                out.write("    pop rdi\n");
                out.write("    pop rsi\n");
                out.write("    syscall\n");
            elif op['type'] == OP_SYSCALL3:
                out.write("    ;; -- syscall3 --\n")
                out.write("    pop rax\n")
                out.write("    pop rdi\n")
                out.write("    pop rsi\n")
                out.write("    pop rdx\n")
                out.write("    syscall\n")
            elif op['type'] == OP_SYSCALL4:
                out.write("    ;; -- syscall4 --\n")
                out.write("    pop rax\n")
                out.write("    pop rdi\n")
                out.write("    pop rsi\n")
                out.write("    pop rdx\n")
                out.write("    pop r10\n")
                out.write("    syscall\n")
            elif op['type'] == OP_SYSCALL5:
                out.write("    ;; -- syscall5 --\n")
                out.write("    pop rax\n")
                out.write("    pop rdi\n")
                out.write("    pop rsi\n")
                out.write("    pop rdx\n")
                out.write("    pop r10\n")
                out.write("    pop r8\n")
                out.write("    syscall\n")
            elif op['type'] == OP_SYSCALL6:
                out.write("    ;; -- syscall6 --\n")
                out.write("    pop rax\n")
                out.write("    pop rdi\n")
                out.write("    pop rsi\n")
                out.write("    pop rdx\n")
                out.write("    pop r10\n")
                out.write("    pop r8\n")
                out.write("    pop r9\n")
                out.write("    syscall\n")
            elif op['type'] == OP_OVER:
                out.write("    ;; -- over --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    push rbx\n")
                out.write("    push rax\n")
                out.write("    push rbx\n")
            else:
                assert False, "Unreachable"
        out.write("addr_%d:\n" % len(program))
        out.write("    mov rax, 60\n")
        out.write("    mov rdi, 0\n")
        out.write("    syscall\n")

        out.write("segment .bss\n")
        out.write("mem: resb %d\n" % MEMORY_SIZE)



BUILT_IN_WORDS = {
                    "+":OP_PLUS,
                    "-":OP_MINUS,
                    "dump":OP_DUMP,
                    "=":OP_DUMP,
                    "if":OP_IF,
                    "end":OP_END,
                    "else":OP_ELSE,
                    "dup":OP_DUP,
                    ">":OP_GT,
                    "<":OP_LT,
                    "while":OP_WHILE,
                    "do":OP_DO,
                    "mem":OP_MEM,
                    "store":OP_STORE,
                    "load":OP_LOAD,
                    "syscall1":OP_SYSCALL1,
                    "syscall2":OP_SYSCALL2,
                    "syscall3":OP_SYSCALL3,
                    "syscall4":OP_SYSCALL4,
                    "syscall5":OP_SYSCALL5,
                    "syscall6":OP_SYSCALL6,
                    '>>':OP_SHR,
                    '<<':OP_SHL,
                    '|':OP_BOR,
                    '&':OP_BAND,
                    '2dup':OP_2DUP,
                    'swap':OP_SWAP,
                    'drop':OP_DROP,
                    'over':OP_OVER
                }
assert COUNT_OPS == len(BUILT_IN_WORDS) + 1, "Exaustive BUILT_IN_WORDS definitions. Keep in mind that not all of the new words have to be defined here only those that introduce new builtin words"


        
def parse_token_as_op(token):
    assert COUNT_TOKENS == 2, "Exaustive handling of tokens in parse_token_as_op"
    if token['type'] == TOKEN_WORD:
        if token['value'] in BUILT_IN_WORDS:
            return {'type': BUILT_IN_WORDS[token['value']], 'loc': token['loc']}
        else:
            print("[ERR]: %s:%d:%d: %s" % (token['loc'] + token['value']))

    elif token['type'] == TOKEN_INT:
        return {'type': OP_PUSH, 'value': token['value'], 'loc': token['loc']}
    else:
        assert False, "Unreachable"

def crossreference_blocks(program):
    stack = []
    for ip in range(len(program)):
        op = program[ip]
        assert COUNT_OPS == 30, "Exhaustive handling of ops in crossreference_program. Keep in mind that not all of the ops need to be handled in here. Only those that form blocks."
        if op['type'] == OP_IF:
            stack.append(ip)
        elif op['type'] == OP_ELSE:
            if_ip = stack.pop()
            # TODO: report block mismatch errors as compiler errors not asserts
            assert program[if_ip]['type'] == OP_IF, "`else` can only be used in `if`-blocks"
            program[if_ip]['jmp'] = ip + 1
            stack.append(ip)
        elif op['type'] == OP_END:
            block_ip = stack.pop()
            if program[block_ip]['type'] == OP_IF or program[block_ip]['type'] == OP_ELSE:
                program[block_ip]['jmp'] = ip
                program[ip]['jmp'] = ip + 1
            elif program[block_ip]['type'] == OP_DO:
                assert len(program[block_ip]) >= 2
                program[ip]['jmp'] = program[block_ip]['jmp']
                program[block_ip]['jmp'] = ip + 1
            else:
                # TODO: report block mismatch errors as compiler errors not asserts
                assert False, "`end` can only close `if`, `else` or `do` blocks for now"
        elif op['type'] == OP_WHILE:
            stack.append(ip)
        elif op['type'] == OP_DO:
            while_ip = stack.pop()
            program[ip]['jmp'] = while_ip
            stack.append(ip)

    # TODO: report unclosed blocks errors as compiler errors not asserts
    assert len(stack) == 0, "unclosed blocks"

    return program

def find_col(line, start, predicate):
    while start < len(line) and not predicate(line[start]):
        start += 1
    return start

def lex_word(text):
    try:
        return (TOKEN_INT, int(text))
    except ValueError:
        return (TOKEN_WORD, text)

def lex_line(line):
    col = find_col(line, 0, lambda x: not x.isspace())
    while col < len(line):
        col_end = find_col(line, col, lambda x: x.isspace())
        yield (col, lex_word(line[col:col_end]))
        col = find_col(line, col_end, lambda x: not x.isspace())

def lex_file(file_path):
    with open(file_path, "r") as f:
        return [{
                'type': token_type,
                 'loc': (file_path, row + 1, col + 1),
                 'value': token_value
                }
            for (row, line) in enumerate(f.readlines())
            for (col, (token_type, token_value)) in lex_line(line.split("//")[0])]


def load_program(fd):
     return crossreference_blocks([parse_token_as_op(token) for token in lex_file(fd)])
        

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
        print("\n" + colors.OKGREEN + "Process exited normally.")
    else:
        print("\n" + colors.FAIL + "Process exited abnormally with exit code " + colors.UNDERLINE + str(exit_code) + colors.ENDC + colors.FAIL + "." )


    


global outfile
outfile = "output"
b_run = False
b_outfile = False
b_remove = False
i_dumpmem = 0

def setup_build_env(outfile, build_dir = "build", obj_dir = "build/obj", asm_dir = "build/asm"):
    basepath = ""
    if "/" in outfile:
        basepath = "/".join(outfile.split("/")[:-1]) + "/"

    elif "\\" in outfile:
        assert False, "Windows support is not implemented"
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
        print("[ERR]: Not enough arguments. Exiting!")
        sys.exit(1);


    subc, *argv = argv
    input_filepath = ""

    for flag in argv:
        if flag.startswith("-"):
            if b_outfile == True:
                b_outfile == False
                
                outfile = flag
                continue

            if i_dumpmem == -1:
                
                i_dumpmem = flag
                continue

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
                print("[ERR]: Unknown flag \"%s\". Exiting!" % flag);
                sys.exit(1);
        else:
            input_filepath = flag
        
    if input_filepath == "":
        usage(prog)
        print("[ERR]: No file supplied. Exiting!")
        sys.exit(1)
    outfile = ".".join(input_filepath.split(".")[:-1])

    (build_path, obj_path, asm_path) = setup_build_env(outfile)

    # print(subc)
    if subc == "s" or subc == "sim" or subc == "simulate":

        program = load_program(input_filepath)
        simulate_program(program, i_dumpmem);
    elif subc == "c" or subc == "com" or subc == "compile":

        program = load_program(input_filepath)
        compile_program(program, asm_path);
        run_cmd(["nasm", "-felf64", "-o", obj_path, asm_path])
        run_cmd(["ld", "-o", build_path, obj_path])

        if b_remove == True:
            run_cmd(["rm", "-f", asm_path, obj_path])
        if b_run == True:
            run_compiled_prog(build_path)
    else:
        usage(prog);

        print("[ERR]: Unknown subcommand \"%s\". Exiting!" % subc);
        sys.exit(1);

    
