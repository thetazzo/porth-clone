#!/usr/bin/env python3

# Token is a dictionary with the following possible fields:
# * `type`  - the type of the token [TOKEN_WORD | TOKN_INT, etc.]
# * `loc`   - the location of the token within a file. It is a tuple of 3 elements `(file_path, row, col)`, `row` and `col` are 1-based indices
# * `value` - the value of the token depending on the type of the token [TOKEN_WORD : `str` | TOKEN_INT : `int`]

import sys;
import subprocess;
from os import path;
import shlex

iota_counter=0;

def iota(reset=False):
    global iota_counter;
    if (reset):
        iota_counter = 0;
    result = iota_counter;
    iota_counter += 1;
    return result;

OP_PUSH_INT=iota(True);
OP_PUSH_STR=iota();
OP_PLUS=iota();
OP_MINUS=iota();
OP_EQUAL=iota();
OP_SHR=iota();
OP_SHL=iota();
OP_BOR=iota();
OP_BAND=iota();
OP_DUMP=iota();
OP_OVER=iota();
OP_IF=iota();
OP_ELSE=iota();
OP_END=iota();
OP_DUP=iota();
OP_2DUP=iota();
OP_DROP=iota();
OP_SWAP=iota();
OP_GT=iota();
OP_LT=iota();
OP_WHILE=iota();
OP_DO=iota();
OP_MEM=iota();
OP_LOAD=iota();
OP_STORE=iota();
OP_SYSCALL1=iota();
OP_SYSCALL3=iota();
COUNT_OPS=iota();

TOKEN_WORD=iota(True);
TOKEN_INT=iota();
TOKEN_STR=iota();
COUNT_TOKENS=iota();

STR_CAPACITY = 640_000;
MEM_CAPACITY = 640_000;

# Does not compile it just simulates the program
# - dump_memory_range: {[integer, integer]}{[0, 0]} - prints as many bytes of memory as specified [lower_bound, upper_bound] 
def simulate_program(program, dump_memory_range=[0,0]):
    stack = [];
    mem = bytearray(STR_CAPACITY+MEM_CAPACITY);
    str_size = 0;
    ip = 0;
    while ip < len(program):
        assert COUNT_OPS == 27, "Exhaustive handling of operations in simulation"
        op = program[ip];
        if op['type'] == OP_PUSH_INT:
            stack.append(op['value']);
            ip += 1;
        elif op['type'] == OP_PUSH_STR:
            bs = bytes(op['value'], 'utf-8');
            n = len(bs); 
            stack.append(len(op['value']));
            if 'addr' not in op:
                op['addr'] = str_size;
                mem[str_size:str_size+n] = bs;
                str_size += n;
                assert str_size <= STR_CAPACITY, "String buffer overflow";
            stack.append(op['addr']);
            ip += 1;
        elif op['type'] == OP_PLUS:
            a = stack.pop();
            b = stack.pop();
            stack.append(a + b);
            ip += 1;
        elif op['type'] == OP_MINUS:
            a = stack.pop();
            b = stack.pop();
            stack.append(b - a);
            ip += 1;
        elif op['type'] == OP_EQUAL:
            a = stack.pop();
            b = stack.pop();
            stack.append(int(a == b));
            ip += 1;
        elif op['type'] == OP_SHR:
            a = stack.pop();
            b = stack.pop();
            stack.append(int(b >> a));
            ip += 1;
        elif op['type'] == OP_SHL:
            a = stack.pop();
            b = stack.pop();
            stack.append(int(b << a));
            ip += 1;
        elif op['type'] == OP_BOR:
            a = stack.pop();
            b = stack.pop();
            stack.append(int(b | a));
            ip += 1;
        elif op['type'] == OP_BAND:
            a = stack.pop();
            b = stack.pop();
            stack.append(int(b & a));
            ip += 1;
        elif op['type'] == OP_IF:
            a = stack.pop();
            if a == 0:
                assert 'jmp' in op, "`if` instruction does not have a reference to the end of it's block. Please call crossreference_blocks() on the program before you simulate it!";
                ip = op['jmp'];
            else:
                ip += 1;
        elif op['type'] == OP_ELSE:
            assert 'jmp' in op, "`else` instruction does not have a reference to the end of it's block. Please call crossreference_blocks() on the program before you simulate it!";
            ip = op['jmp'];
        elif op['type'] == OP_END:
            assert 'jmp' in op, "`end` instruction does not have a reference to the next instruction to jump to. Please call crossreference_blocks() on the program before you simulate it!";
            ip = op['jmp'];
        elif op['type'] == OP_DUP:
            a = stack.pop();
            stack.append(a);
            stack.append(a);
            ip += 1;
        elif op['type'] == OP_2DUP:
            b = stack.pop();
            a = stack.pop();
            stack.append(a);
            stack.append(b);
            stack.append(a);
            stack.append(b);
            ip += 1;
        elif op['type'] == OP_SWAP:
            a = stack.pop();
            b = stack.pop();
            stack.append(a);            
            stack.append(b);
            ip += 1;
        elif op['type'] == OP_DROP:
            stack.pop();
            ip += 1;
        elif op['type'] == OP_GT:
            b = stack.pop();
            a = stack.pop();
            stack.append(int(a > b));
            ip += 1;
        elif op['type'] == OP_LT:
            b = stack.pop();
            a = stack.pop();
            stack.append(int(a < b));
            ip += 1;
        elif op['type'] == OP_LT:
            b = stack.pop();
            a = stack.pop();
            stack.append(int(a < b));
            ip += 1;
        elif op['type'] == OP_WHILE:
            ip += 1;
        elif op['type'] == OP_DO:
            a = stack.pop();
            if a == 0:
                assert 'jmp' in op, "`do` instruction does not have a reference to the next instruction to jump to. Please call crossreference_blocks() on the program before you simulate it!";
                ip = op['jmp'];
            else:
                ip += 1;
        elif op['type'] == OP_OVER:
            a = stack.pop();
            b = stack.pop();
            stack.append(b);
            stack.append(a);
            stack.append(b);
            ip += 1;
        elif op['type'] == OP_DUMP:
            a = stack.pop();
            print(a);
            ip += 1;
        elif op['type'] == OP_MEM:
            stack.append(STR_CAPACITY);
            ip += 1;
        elif op['type'] == OP_LOAD:
            addr = stack.pop();
            byte = mem[addr];
            stack.append(byte);
            ip += 1;
        elif op['type'] == OP_STORE:
            value = stack.pop();
            addr = stack.pop();
            mem[addr] = value & 0xFF;
            ip += 1;
        elif op['type'] == OP_SYSCALL1:
            assert False, "not implemented";
        elif op['type'] == OP_SYSCALL3:
            syscall_number = stack.pop();
            arg1 = stack.pop();
            arg2 = stack.pop();
            arg3 = stack.pop();
            if syscall_number == 1:
                fd = arg1;
                buf = arg2;
                count = arg3;
                s = mem[buf:buf+count].decode("utf-8");
                if fd == 1:
                    print(s, end='');
                elif fd == 2:
                    print(s, file=sys.stderr);
                else:
                    assert False, "unknown file descriptor '%d'" % fd;
            else:
                assert False, "unknown syscall number '%d'" % syscall_number;
            ip += 1;
        else:
            assert False, "unreachable";

        if dump_memory_range[1] > 0:
            print(mem[dump_memory_range[0]:dump_memory_range[1]]);

# Does not simulte it just compiles
def compile_program(program, out_file_path):
    strs = [];
    with open(out_file_path, "w") as out:
        out.write("dump:\n");
        out.write("    mov     r8, -3689348814741910323\n");
        out.write("    sub     rsp, 40\n");
        out.write("    mov     BYTE [rsp+31], 10\n");
        out.write("    lea     rcx, [rsp+30]\n");
        out.write(".L2:\n");
        out.write("    mov     rax, rdi\n");
        out.write("    mul     r8\n");
        out.write("    mov     rax, rdi\n");
        out.write("    shr     rdx, 3\n");
        out.write("    lea     rsi, [rdx+rdx*4]\n");
        out.write("    add     rsi, rsi\n");
        out.write("    sub     rax, rsi\n");
        out.write("    mov     rsi, rcx\n");
        out.write("    sub     rcx, 1\n");
        out.write("    add     eax, 48\n");
        out.write("    mov     BYTE [rcx+1], al\n");
        out.write("    mov     rax, rdi\n");
        out.write("    mov     rdi, rdx\n");
        out.write("    cmp     rax, 9\n");
        out.write("    ja      .L2\n");
        out.write("    lea     rdx, [rsp+32]\n");
        out.write("    mov     edi, 1\n");
        out.write("    sub     rdx, rsi\n");
        out.write("    mov     rax, 1\n");
        out.write("    syscall\n");
        out.write("    add     rsp, 40\n");
        out.write("    ret\n");
        out.write("%define SYS_EXIT 60\n");
        out.write("segment .text\n");
        out.write("global _start\n");
        out.write("_start:\n");
        for ip in range(len(program)):
            assert COUNT_OPS == 27, "Exhaustive handling of operations in compilation"
            op = program[ip];
            out.write("addr_%d:\n" % ip);
            if op['type'] == OP_PUSH_INT:
                out.write(";;  -- push int %d --\n" % op['value']);
                out.write("    push %d\n" % op['value']);
            elif op['type'] == OP_PUSH_STR:
                out.write(";;  -- push str --\n");
                out.write("    mov rax, %d\n" % len(op['value']));
                out.write("    push rax\n");
                out.write("    push str_%d\n" % len(strs));
                strs.append(op['value']);
            elif op['type'] == OP_PLUS:
                out.write(";;  -- plus --\n");
                out.write("    pop rax\n");
                out.write("    pop rbx\n");
                out.write("    add rax, rbx\n");
                out.write("    push rax\n");
            elif op['type'] == OP_MINUS:
                out.write(";;  -- minus --\n");
                out.write("    pop rax\n");
                out.write("    pop rbx\n");
                out.write("    sub rbx, rax\n");
                out.write("    push rbx\n");
            elif op['type'] == OP_EQUAL:
                out.write(";;  --  equal --\n");
                out.write("    mov rcx, 0\n");
                out.write("    mov rdx, 1\n");
                out.write("    pop rax\n");
                out.write("    pop rbx\n");
                out.write("    cmp rax, rbx\n");
                # move 1 to rcx when rax == rbx
                out.write("    cmove rcx, rdx\n");
                out.write("    push rcx\n");
            elif op['type'] == OP_SHR:
                out.write(";;  -- shr --\n");
                out.write("    pop rcx\n");
                out.write("    pop rbx\n");
                out.write("    shr rbx, cl\n");
                out.write("    push rbx\n");
            elif op['type'] == OP_SHL:
                out.write(";;  -- shl --\n");
                out.write("    pop rcx\n");
                out.write("    pop rbx\n");
                out.write("    shl rbx, cl\n");
                out.write("    push rbx\n");
            elif op['type'] == OP_BOR:
                out.write(";;  -- bor --\n");
                out.write("    pop rax\n");
                out.write("    pop rbx\n");
                out.write("    or rbx, rax\n");
                out.write("    push rbx\n");
            elif op['type'] == OP_BAND:
                out.write(";;  -- banband-\n");
                out.write("    pop rax\n");
                out.write("    pop rbx\n");
                out.write("    and rbx, rax\n");
                out.write("    push rbx\n");
            elif op['type'] == OP_IF:
                out.write(";;  -- if --\n");
                out.write("    pop rax\n");
                out.write("    test rax, rax\n");
                assert 'jmp' in op, "`if` instruction does not have a reference to the end of it's block. Please call crossreference_blocks() on the program before you compile it!"
                out.write("    jz addr_%d\n" % op['jmp']);
            elif op['type'] == OP_ELSE:
                out.write(";;  -- else --\n");
                assert 'jmp' in op, "`else` instruction does not have a reference to the end of it's block. Please call crossreference_blocks() on the program before you compile it!"
                out.write("   jmp addr_%d\n" % op['jmp']);
            elif op['type'] == OP_END:
                assert 'jmp' in op, "`end` instruction does not have a reference to the next instruction to jump to. Please call crossreference_blocks() on the program before you compile it!";
                out.write(";;  -- end --\n");
                if ip + 1 != op['jmp']:
                    out.write("   jmp addr_%d\n" % op['jmp']);
            elif op['type'] == OP_DUP:
                out.write(";;  -- dup --\n");
                out.write("    pop rax\n");
                out.write("    push rax\n");
                out.write("    push rax\n");
            elif op['type'] == OP_2DUP:
                out.write(";;  -- 2dup --\n");
                out.write("    pop rbx\n");
                out.write("    pop rax\n");
                out.write("    push rax\n");
                out.write("    push rbx\n");
                out.write("    push rax\n");
                out.write("    push rbx\n");
            elif op['type'] == OP_SWAP:
                out.write(";;  -- swap --\n");
                out.write("    pop rax\n");
                out.write("    pop rbx\n");
                out.write("    push rax\n");
                out.write("    push rbx\n");
            elif op['type'] == OP_DROP:
                out.write(";;  -- drop --\n");
                out.write("    pop rax\n");
            elif op['type'] == OP_GT:
                out.write(";;  -- gt --\n");
                out.write("    mov rcx, 0\n");
                out.write("    mov rdx, 1\n");
                out.write("    pop rbx\n");
                out.write("    pop rax\n");
                out.write("    cmp rax, rbx\n");
                # move 1 to rcx when rax == rbx
                out.write("    cmovg rcx, rdx\n");
                out.write("    push rcx\n");
            elif op['type'] == OP_LT:
                out.write(";;  -- lt --\n");
                out.write("    mov rcx, 0\n");
                out.write("    mov rdx, 1\n");
                out.write("    pop rbx\n");
                out.write("    pop rax\n");
                out.write("    cmp rax, rbx\n");
                # move 1 to rcx when rax == rbx
                out.write("    cmovl rcx, rdx\n");
                out.write("    push rcx\n");
            elif op['type'] == OP_WHILE:
                out.write(";;  -- while --\n");
            elif op['type'] == OP_DO:
                out.write(";;  -- do --\n");
                out.write("    pop rax\n");
                out.write("    test rax, rax\n");
                assert 'jmp' in op, "`do` instruction does not have a reference to the end of it's block. Please call crossreference_blocks() on the program before you compile it!"
                out.write("    jz addr_%d\n" % op['jmp']);
            elif op['type'] == OP_OVER:
                out.write(";;  -- over --\n");
                out.write("    pop rax\n");
                out.write("    pop rbx\n");
                out.write("    push rbx\n");
                out.write("    push rax\n");
                out.write("    push rbx\n");
            elif op['type'] == OP_DUMP:
                out.write(";;  -- dump %d --\n");
                out.write("    pop rdi\n");
                out.write("    call dump\n");
            elif op['type'] == OP_MEM:
                out.write(";;  -- mem --\n");
                out.write("    push mem\n");
            elif op['type'] == OP_LOAD:
                out.write(";;  -- load --\n");
                out.write("    pop rax\n");
                out.write("    xor rbx, rbx\n"); # cleans the rbx register
                out.write("    mov bl, [rax]\n");
                out.write("    push rbx\n");
            elif op['type'] == OP_STORE:
                out.write(";;  -- store --\n");
                out.write("    pop rbx\n");
                out.write("    pop rax\n");
                out.write("    mov [rax], bl\n");
            elif op['type'] == OP_SYSCALL1:
                out.write(";;  -- syscall1 --\n");
                out.write("    pop rax\n");
                out.write("    pop rdi\n");
                out.write("    syscall\n");
            elif op['type'] == OP_SYSCALL3:
                out.write(";;  -- syscall3 --\n");
                out.write("    pop rax\n");
                out.write("    pop rdi\n");
                out.write("    pop rsi\n");
                out.write("    pop rdx\n");
                out.write("    syscall\n");
            else:
                assert False, "unreachable";

        out.write("addr_%d:\n" % len(program));
        out.write("    mov rax, SYS_EXIT\n");
        out.write("    mov rdi, 0\n");
        out.write("    syscall\n");
        # A segement for strings 
        out.write("segment .data\n");
        for index, s in enumerate(strs):
            out.write("str_%d: db %s\n" % (index, ','.join(map(hex, list(bytes(s, 'utf-8'))))));
        # A segement for memory
        out.write("segment .bss\n");
        out.write("mem: resb %d\n" % MEM_CAPACITY);

assert COUNT_OPS == 27, "Exhaustive BUIL definition. Keep in mind that not all new ops need to be defined here only those who introduce new bulitin words!"
BUILTIN_WORDS = {
    '+': OP_PLUS,
    '-': OP_MINUS,
    '=': OP_EQUAL,
    'shr': OP_SHR,
    'shl': OP_SHL,
    'bor': OP_BOR,
    'band': OP_BAND,
    'if': OP_IF,
    'else': OP_ELSE,
    'end': OP_END,
    'dup': OP_DUP,
    '2dup': OP_2DUP,
    'swap': OP_SWAP,
    'drop': OP_DROP,
    '>': OP_GT,
    '<': OP_LT,
    'while': OP_WHILE,
    'do': OP_DO,
    'dump': OP_DUMP,
    'over': OP_OVER,
    'mem': OP_MEM,
    '.': OP_STORE,
    ',': OP_LOAD,
    'syscall1': OP_SYSCALL1,
    'syscall3': OP_SYSCALL3,
};

def parse_token_as_op(token):
    assert COUNT_TOKENS == 3, "Exhaustive token handling in parse_token_as_op";
    if token['type'] == TOKEN_WORD:
        if token['value'] in BUILTIN_WORDS:
            return {'type': BUILTIN_WORDS[token['value']], 'loc': token['loc']};
        else: 
            print("%s:%d:%d: unknown word `%s`" % (token['loc'] + (token['value'], )));
            exit(1);
    elif token['type'] == TOKEN_INT:
        return {'type': OP_PUSH_INT, 'value': token['value'], 'loc': token['loc']};
    elif token['type'] == TOKEN_STR:
        return {'type': OP_PUSH_STR, 'value': token['value'], 'loc': token['loc']};
    else:
        assert False, "unreachable";

def crossreference_blocks(program):
    stack = [];
    for ip in range(len(program)):
        assert COUNT_OPS == 27, "Exhaustive handling of ops in crossreference_blocks"
        op = program[ip]; 
        if op['type'] == OP_IF:
            stack.append(ip);
        elif op['type'] == OP_ELSE:
            if_ip = stack.pop();
            if program[if_ip]['type'] != OP_IF:
                print("%s:%d:%d:  Error `else` can only be used in `if`-blocks" % program[if_ip]['loc']);
                exit(1);
            program[if_ip]['jmp'] = ip + 1;
            stack.append(ip);
        elif op['type'] == OP_END:
            block_ip = stack.pop();
            if program[block_ip]['type'] == OP_IF or program[block_ip]['type'] == OP_ELSE:
                program[block_ip]['jmp'] = ip;
                program[ip]['jmp'] = ip + 1;
            elif program[block_ip]['type'] == OP_DO:
                assert len(program[block_ip]) >= 2;
                program[ip]['jmp'] = program[block_ip]['jmp'];
                program[block_ip]['jmp'] = ip + 1;
            else: 
                print("%s:%d:%d: ERROR: `end` can only close `if`, `else` or `do` blocks" % program[block_ip]['loc']);
                exit(1);
        elif op['type'] == OP_WHILE:
            stack.append(ip);
        elif op['type'] == OP_DO:
            while_ip = stack.pop();
            program[ip]['jmp'] = while_ip;
            stack.append(ip);

    if len(stack) > 0:
        print('%s:%d:%d: ERROR: unclosed block' % program[stack.pop()]['loc'])
        exit(1)

    return program;

def find_col(line, start, predicate):
    while start < len(line) and not predicate(line[start]):
        start += 1;
    return start;

# TODO: lexer does not support multiline string literals
def lex_line(line):
    col = find_col(line, 0, lambda x: not x.isspace());
    while col < len(line):
        col_end = None;
        if line[col] == '"':
            col_end = find_col(line, col+1, lambda x: x == '"');
            # TODO: report unclosed string literals as proper compiler errors instead of python assertions
            assert line[col_end] == '"';
            # TODO: converted text_of_token to bytes and back just to unescape things is kind of sus
            # Maybe let's try opening the file with "rb" in lex_file()
            text_of_token = bytes(line[col+1:col_end], 'utf-8').decode('unicode_escape');
            yield (col, (TOKEN_STR, text_of_token));
            col = find_col(line, col_end+1, lambda x: not x.isspace());
        else:
            col_end = find_col(line, col, lambda x: x.isspace());
            text_of_token=line[col:col_end];
            try:
                yield (col, (TOKEN_INT, int(text_of_token)));
            except ValueError:
                yield (col, (TOKEN_WORD, text_of_token));
            col = find_col(line, col_end, lambda x: not x.isspace());

def lex_file(file_path):
    with open(file_path, 'r') as f:
        return [{'type': token_type, 'loc': (file_path, row + 1, col + 1), 'value': token_value}
                for (row, line) in enumerate(f.readlines())
                for (col, (token_type, token_value)) in lex_line(line.split('//')[0])];

def load_program_from_file(file_path):
        return crossreference_blocks([parse_token_as_op(token) for token in lex_file(file_path)]);

def print_usage(program):
    print("Usage: %s <SUBCOMMAND> [ARGS]" % (program));
    print("SUBCOMMAND:");
    print("    sim <file>           ... Simulate the program");
    print("    com [OPTIONS] <file> ... Compile the ptogram");
    print("      OPTIONS:");
    print("        -r               ... Run the program after successful compilation");
    print("        -o <file|dir>    ... Customize the output path")
    print("    help                 ... Print this help to stdout and exit with 0 code")

def call_cmd(cmd):
    print("[CMD] %s" % " ".join(map(shlex.quote, cmd)))
    return subprocess.call(cmd)

if __name__ == '__main__':
    argv = sys.argv;
    assert len(argv) >= 1;
    compiler_name, *argv = argv;
    if len(argv) < 1:
        print_usage(compiler_name);
        print("ERROR: no subcommand provided");
        exit(1);

    subcommand, *argv = argv;

    if subcommand == "sim":
        if len(argv) < 1:
            print_usage(compiler_name);
            print("ERROR: No input file was provided for the simulation");
            exit(1);
        program_path, *argv = argv;
        program = load_program_from_file(program_path);
        simulate_program(program); 
    elif subcommand == "com":
        should_execute = False;
        program_path = None;
        output_path  = None;
        while len(argv) > 0:
            flag, *argv = argv;
            if flag == '-r':
                should_execute = True;
            elif flag == '-o':
                if len(argv) == 0:
                    print_usage(compiler_name)
                    print("ERROR: no argument is provided for parameter -o")
                    exit(1)
                output_path, *argv = argv
            else:
                program_path = flag;
                break;

        if program_path is None:
            print_usage(compiler_name);
            print("ERROR: no input file provided for compilation");
            exit(1);

        out_basename = None
        out_basedir = None
        if output_path is not None:
            if path.isdir(output_path):
                out_basename = path.basename(program_path)
                porth_ext = '.porth'
                if out_basename.endswith(porth_ext):
                    out_basename = out_basename[:-len(porth_ext)]
                out_basedir = path.dirname(output_path)
            else:
                out_basename = path.basename(output_path)
                out_basedir = path.dirname(output_path)
        else:
            out_basename = path.basename(program_path)
            porth_ext = '.porth'
            if out_basename.endswith(porth_ext):
                out_basename = out_basename[:-len(porth_ext)]
            out_basedir = path.dirname(program_path)
        out_basepath = path.join(out_basedir, out_basename)

        print("[INFO] Generating %s" % (out_basepath + ".asm"))
        program = load_program_from_file(program_path);
        compile_program(program, out_basepath + ".asm")
        call_cmd(["nasm", "-felf64", out_basepath + ".asm"])
        call_cmd(["ld", "-o", out_basepath, out_basepath + ".o"])
        if should_execute:
            call_cmd([out_basepath])

    else:
        print_usage(compiler_name);
        print("ERROR: unknown subcommand '%s'" % (subcommand));
        exit(1);
