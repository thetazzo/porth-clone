#!/usr/bin/env python3

import sys;
import subprocess;

iota_counter=0;

def iota(reset=False):
    global iota_counter;
    if (reset):
        iota_counter = 0;
    result = iota_counter;
    iota_counter += 1;
    return result;

OP_PUSH=iota();
OP_PLUS=iota();
OP_MINUS=iota();
OP_EQUAL=iota();
OP_DUMP=iota();
OP_IF=iota();
OP_ELSE=iota();
OP_END=iota();
COUNT_OPS=iota();

def push(x):
    return (OP_PUSH, x);

def plus():
    return (OP_PLUS,);

def minus():
    return (OP_MINUS,);

def equal():
    return (OP_EQUAL,);

def dump():
    return (OP_DUMP,);

def iff():
    return (OP_IF,);

def elsee():
    return (OP_ELSE,);

def end():
    return (OP_END,);

# Does not compile it just simulates the program
def simulate_program(program):
    stack = [];
    ip = 0;
    while ip < len(program):
        assert COUNT_OPS == 8, "Exhaustive handling of operations in simulation"
        op = program[ip];
        if op[0] == OP_PUSH:
            stack.append(op[1]);
            ip += 1;
        elif op[0] == OP_PLUS:
            a = stack.pop();
            b = stack.pop();
            stack.append(a + b);
            ip += 1;
        elif op[0] == OP_MINUS:
            a = stack.pop();
            b = stack.pop();
            stack.append(b - a);
            ip += 1;
        elif op[0] == OP_EQUAL:
            a = stack.pop();
            b = stack.pop();
            stack.append(int(a == b));
            ip += 1;
        elif op[0] == OP_IF:
            a = stack.pop();
            if a == 0:
                assert len(op) >= 2, "'if' instruction does not have a reference to the end of it's block. Please call crossreference_blocks() on the program before you simulate it!";
                ip = op[1];
            else:
                ip += 1;
        elif op[0] == OP_ELSE:
            assert len(op) >= 2, "'else' instruction does not have a reference to the end of it's block. Please call crossreference_blocks() on the program before you simulate it!";
            ip = op[1];
        elif op[0] == OP_END:
            ip += 1;
        elif op[0] == OP_DUMP:
            a = stack.pop();
            print(a);
            ip += 1;
        else:
            assert False, "unreachable";

# Does not simulte it just compiles
def compile_program(program, out_file_path):
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
            assert COUNT_OPS == 8, "Exhaustive handling of operations in compilation"
            op = program[ip];
            if op[0] == OP_PUSH:
                out.write(";;  -- push %d --\n" % op[1]);
                out.write("    push %d\n" % op[1]);
            elif op[0] == OP_PLUS:
                out.write(";;  -- plus --\n");
                out.write("    pop rax\n");
                out.write("    pop rbx\n");
                out.write("    add rax, rbx\n");
                out.write("    push rax\n");
            elif op[0] == OP_MINUS:
                out.write(";;  -- minus --\n");
                out.write("    pop rax\n");
                out.write("    pop rbx\n");
                out.write("    sub rbx, rax\n");
                out.write("    push rbx\n");
            elif op[0] == OP_EQUAL:
                out.write(";;  --  equal --\n");
                out.write("    mov rcx, 0\n");
                out.write("    mov rdx, 1\n");
                out.write("    pop rax\n");
                out.write("    pop rbx\n");
                out.write("    cmp rax, rbx\n");
                # move 1 to rcx when rax == rbx
                out.write("    cmove rcx, rdx\n");
                out.write("    push rcx\n");
            elif op[0] == OP_IF:
                out.write(";;  -- if --\n");
                out.write("    pop rax\n");
                out.write("    test rax, rax\n");
                assert len(op) >= 2, "`if` instruction does not have a reference to the end of it's block. Please call crossreference_blocks() on the program before you compile it!"
                out.write("    je addr_%d\n" % op[1]);
            elif op[0] == OP_ELSE:
                out.write(";;  -- else --\n");
                assert len(op) >= 2, "`else` instruction does not have a reference to the end of it's block. Please call crossreference_blocks() on the program before you compile it!"
                out.write("   jmp addr_%d\n" % op[1]);
                out.write("addr_%d:\n" % (ip + 1));
            elif op[0] == OP_END:
                out.write("addr_%d:\n" % ip);
            elif op[0] == OP_DUMP:
                out.write(";;  -- dump %d --\n");
                out.write("    pop rdi\n");
                out.write("    call dump\n");
            else:
                assert False, "unreachable";
        out.write("    mov rax, SYS_EXIT\n");
        out.write("    mov rdi, 0\n");
        out.write("    syscall\n");

def parse_token_as_op(token):
    (file_path, row, col, word) = token;
    assert COUNT_OPS == 8, "Exhaustive op handling in parse_token_as_op";
    if word == '+':
        return plus();
    elif word == '-':
        return minus();
    elif word == '=':
        return equal();
    elif word == 'if':
        return iff();
    elif word == 'else':
        return elsee();
    elif word == 'end':
        return end();
    elif word == '.':
        return dump();
    else: 
        try:
            return push(int(word));
        except ValueError as err:
            print("%s:%d:%d: %s" % (file_path, row, col, err));
            exit(1);

def crossreference_blocks(program):
    stack = [];
    for ip in range(len(program)):
        assert COUNT_OPS == 8, "Exhaustive handling of ops in crossreference_blocks"
        op = program[ip]; 
        if op[0] == OP_IF:
            stack.append(ip);
        elif op[0] == OP_ELSE:
            if_ip = stack.pop();
            assert program[if_ip][0] == OP_IF, "`else` can only be used in `if` blocks"
            program[if_ip] = (OP_IF, ip + 1);
            stack.append(ip);
        elif op[0] == OP_END:
            block_ip = stack.pop();
            if program[block_ip][0] == OP_IF or program[block_ip][0] == OP_ELSE:
                program[block_ip] = (program[block_ip][0], ip)
            else: 
                assert False, "`end` can only close `if-else` blocks for now"
    return program;

def find_col(line, start, predicate):
    while start < len(line) and not predicate(line[start]):
        start += 1;
    return start;

def lex_line(line):
    col = find_col(line, 0, lambda x: not x.isspace());
    while col < len(line):
        col_end = find_col(line, col, lambda x: x.isspace());
        yield (col, line[col:col_end]);
        col = find_col(line, col_end, lambda x: not x.isspace());

def lex_file(file_path):
    with open(file_path, 'r') as f:
        return [(file_path, row, col, token)
            for (row, line) in enumerate(f.readlines())
            for (col, token) in lex_line(line)];

def load_program_from_file(file_path):
        return crossreference_blocks([parse_token_as_op(token) for token in lex_file(file_path)]);

def print_usage(program):
    print("Usage: %s <SUBCOMMAND> [ARGS]" % (program));
    print("SUBCOMMAND:");
    print("    sim <file> ... Simulate the program");
    print("    com <file> ... Compile the ptogram");
    print();

def call_cmd(cmd):
    print("+", ' '.join(cmd));
    subprocess.call(cmd);

def uncons(xs):
    return (xs[0], xs[1:]);

if __name__ == '__main__':
    argv = sys.argv;
    assert len(argv) >= 1;
    (program_name, argv) = uncons(argv);
    if len(argv) < 2:
        print_usage(program_name);
        print("ERROR: no subcommand provided");
        exit(1);

    (subcommand, argv) = uncons(argv);

    if (subcommand == "sim"):
        if len(argv) < 1:
            print_usage(program_name);
            print("ERROR: No input file was provided for the simulation");
            exit(1);
        (program_path, argv) = uncons(argv);
        program = load_program_from_file(program_path);
        simulate_program(program); 
    elif (subcommand == "com"):
        if len(argv) < 1:
            print_usage(program_name);
            print("ERROR: No input file was provided for the compilation");
            exit(1);
        (program_path, argv) = uncons(argv);
        program = load_program_from_file(program_path);
        compile_program(program, "./build/output.asm");
        call_cmd(["nasm", "-f", "elf64", "./build/output.asm"]);
        call_cmd(["ld", "-o", "output", "./build/output.o"]);
    else:
        print_usage(program_name);
        print("ERROR: unknown subcommand '%s'" % (subcommand));
        exit(1);
