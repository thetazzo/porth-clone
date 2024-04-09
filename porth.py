#!/usr/bin/env python3

import os
import sys
import subprocess
import shlex
from os import path
from typing import *
from enum import IntEnum, Enum, auto
from dataclasses import dataclass
from copy import copy
from time import sleep
import traceback

PORTH_EXT = ".porth" 
DEFAULT_EXPANSION_LIMIT=1000
EXPANSION_DIAGNOSTIC_LIMIT=10
MEM_CAPACITY = 640_000
SIM_NULL_POINTER_PADDING = 1 # a bit of padding at the begginig of the memory to make 0 an invalid address
SIM_STR_CAPACITY = 640_000
SIM_ARGV_CAPACITY = 640_000

debug=False

Loc=Tuple[str, int, int]

class Keyword(Enum):
    IF=auto()
    END=auto()
    ELSE=auto()
    WHILE=auto()
    DO=auto()
    MACRO=auto()
    INCLUDE=auto()

class Intrinsic(IntEnum):
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
    DUP=auto()
    SWAP=auto()
    DROP=auto()
    OVER=auto()
    ROT=auto()
    MEM=auto()
    LOAD=auto()
    FORTH_LOAD=auto()
    LOAD64=auto()
    FORTH_LOAD64=auto()
    STORE=auto()
    FORTH_STORE=auto()
    STORE64=auto()
    FORTH_STORE64=auto()
    CAST_PTR=auto()
    ARGC=auto()
    ARGV=auto()
    HERE=auto()
    SYSCALL0=auto()
    SYSCALL1=auto()
    SYSCALL2=auto()
    SYSCALL3=auto()
    SYSCALL4=auto()
    SYSCALL5=auto()
    SYSCALL6=auto()

class OpType(IntEnum):
    PUSH_INT=auto()
    PUSH_STR=auto()
    PUSH_CSTR=auto()
    INTRINSIC=auto()
    IF=auto()
    END=auto()
    ELSE=auto()
    WHILE=auto()
    DO=auto()

class TokenType(Enum):
    WORD=auto()
    INT=auto()
    STR=auto()
    CSTR=auto()
    CHAR=auto()
    KEYWORD=auto()

assert len(TokenType) == 6, "Exhaustive TokenType definition. The `value` filed may need to be updated!: %d" % len(TokenType)
@dataclass
class Token:
    typ: TokenType
    text: str
    loc: Loc
    value: Union[int, str, Keyword]
    expanded_from: Optional['Token'] = None
    expanded_count: int = 0

OpAddr=int

@dataclass
class Op:
    typ: OpType
    token: Token
    operand: Optional[Union[int, str, Intrinsic, OpAddr]] = None

Program=List[Op]

def get_cstr_from_mem(mem: bytearray, ptr: int) -> bytes:
    end = ptr
    while mem[end] != 0:
        end += 1
    return mem[ptr:end]

def compiler_diagnostic(loc: Loc, tag: str, message: str):
    print("%s:%d:%d: %s: %s" % (loc + (tag, message)), file=sys.stderr)

def compiler_diagnostic_with_expansion_stack(token: Token, tag: str, message: str):
    compiler_diagnostic(token.loc, tag, message)
    stack = token.expanded_from
    limit = 0

    while stack is not None and limit <= EXPANSION_DIAGNOSTIC_LIMIT:
        compiler_note_(stack.loc, "expanded from `%s`" % stack.text)
        stack = stack.expanded_from
        limit += 1
    if limit > EXPANSION_DIAGNOSTIC_LIMIT:
        print("...", file=sys.stderr)
        print("... too many expansions ...", file=sys.stderr)
        print("...", file=sys.stderr)

def compiler_error_(loc: Loc, message: str):
    compiler_diagnostic(loc, "ERROR", message)

def compiler_error_with_expansion_stack(token: Token, message: str):
    compiler_diagnostic_with_expansion_stack(token, "ERROR", message)

def compiler_note_(loc: Loc, message: str):
    compiler_diagnostic(loc, "NOTE", message)

def simulate_little_endian_linux(program: Program, argv: List[str]):
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
        assert len(OpType) == 9, "Exhaustive op handling in simulate_little_endian_linux"
        op = program[ip]
        try:
            if op.typ == OpType.PUSH_INT:
                assert isinstance(op.operand, int), "This could be a bug in the parsing step"
                stack.append(op.operand)
                ip += 1
            elif op.typ == OpType.PUSH_STR:
                assert isinstance(op.operand, str), "This could be a bug in the parsing step"
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
            elif op.typ == OpType.IF:
                ip += 1
            elif op.typ == OpType.ELSE:
                assert isinstance(op.operand, OpAddr), "This could be a bug in the parsing step"
                ip = op.operand
            elif op.typ == OpType.END:
                assert isinstance(op.operand, OpAddr), "This could be a bug in the parsing step"
                ip = op.operand
            elif op.typ == OpType.WHILE:
                ip += 1
            elif op.typ == OpType.DO:
                a = stack.pop()
                if a == 0:
                    assert isinstance(op.operand, OpAddr), "This could be a bug in the parsing step"
                    ip = op.operand
                else:
                    ip += 1
            elif op.typ == OpType.INTRINSIC:
                assert len(Intrinsic) == 41, "Exhaustive handling of intrinsic in simulate_little_endian_linux()"
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
                elif op.operand == Intrinsic.MEM:
                    stack.append(mem_buf_ptr)
                    ip += 1
                elif op.operand == Intrinsic.LOAD:
                    addr = stack.pop()
                    byte = mem[addr]
                    stack.append(byte)
                    ip += 1
                elif op.operand == Intrinsic.FORTH_LOAD:
                    addr = stack.pop()
                    byte = mem[addr]
                    stack.append(byte)
                    ip += 1
                elif op.operand == Intrinsic.STORE:
                    store_value = stack.pop()
                    store_addr = stack.pop()
                    mem[store_addr] = store_value & 0xFF
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
                elif op.operand == Intrinsic.FORTH_LOAD64:
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
                    value = ("%s:%d:%d" % op.token.loc).encode("utf-8")
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
                        # https://en.wikipedia.org/wiki/POSIX_terminal_interface#Canonical_mode_processing
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

                    if syscall_number == 230: # SYS_clock_nanosleep
                        clock_id = arg1
                        flags = arg2
                        req_ptr = arg3
                        rem_ptr = arg4
                        assert clock_id == CLOCK_MONOTONIC, "Only CLOCK_MONOTONIC is implemented in SYS_clock_nanosleep"
                        assert flags == 0, "Only relative time is supported for SYS_clock_nanosleep"
                        assert req_ptr != 0, "request cannot be NULL for SYS_clock_nanosleep. 1 should probably be returend in that case"
                        assert rem_ptr == 0, "remain is not supported for SYS_clock_nanosleep"
                        seconds = int.from_bytes(mem[req_ptr:req_ptr+8], byteorder="little")
                        nano_seconds = int.from_bytes(mem[req_ptr+8:req_ptr+8+8], byteorder="little")
                        sleep(float(seconds) + float(nano_seconds)*1e-09)
                        stack.append(0)
                    else: 
                        assert False, "unknown syscall_number %d" % syscall_number
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
            compiler_error_with_expansion_stack(op.token, "Python Exception during simulation")
            traceback.print_exception(type(e), e, e.__traceback__)
            exit(1)
    if debug:
        print("[INFO] Memory dump")
        print(mem[:20])

class DataType(IntEnum):
    INT=auto()
    BOOL=auto() # tha boolean monster
    PTR=auto()

def print_missing_op_args(op: Op):
    if op.typ == OpType.INTRINSIC:
        assert isinstance(op.operand, Intrinsic)
        compiler_error_with_expansion_stack(op.token, "Not enough arguments for the `%s` intrinsic" % INTRINSIC_NAMES[op.operand]) 
    elif op.typ == OpType.IF:
        compiler_error_with_expansion_stack(op.token, "Not enough arguments for the IF-block") 
    else:
        assert False, "unsupported type of operation"

DataStack=List[Tuple[DataType, Token]]

def type_check_program(program: Program):
    stack: DataStack = []
    block_stack: List[Tuple[DataStack, OpType]] = []
    for ip in range(len(program)):
        op = program[ip]
        assert len(OpType) == 9, "Exhaustive ops handling in type_check_program: %d" % len(OpType)
        assert len(DataType) == 3, "Exhaustive type handling in type_check_program(): %d" % len(DataType)
        if op.typ == OpType.PUSH_INT:
            stack.append((DataType.INT, op.token))
        elif op.typ == OpType.PUSH_STR:
            stack.append((DataType.INT, op.token))
            stack.append((DataType.PTR, op.token))
        elif op.typ == OpType.PUSH_CSTR:
            stack.append((DataType.PTR, op.token))
        elif op.typ == OpType.IF:
            block_stack.append((copy(stack), op.typ))
        elif op.typ == OpType.WHILE:
            block_stack.append((copy(stack), op.typ))
        elif op.typ == OpType.END:
            block_snapshot, block_type = block_stack.pop()
            assert len(OpType) == 9, "Exhaustive handling of op types"
            if block_type == OpType.ELSE:
                expected_types = list(map(lambda x: x[0], block_snapshot))
                actual_types = list(map(lambda x: x[0], stack))
                if expected_types != actual_types:
                    compiler_error_with_expansion_stack(op.token, 'both branches of the if-block must produce the same types of the arguments on the data stack')
                    compiler_note_(op.token.loc, 'Expected types: %s' % expected_types)
                    compiler_note_(op.token.loc, 'Actual types: %s' % actual_types)
                    exit(1)
            elif block_type == OpType.DO:
                begin_snapshot, begin_typ = block_stack.pop()

                if begin_typ == OpType.WHILE:
                    expected_types = list(map(lambda x: x[0], begin_snapshot))
                    actual_types = list(map(lambda x: x[0], stack))

                    if expected_types != actual_types:
                        compiler_error_with_expansion_stack(op.token, 'while-do body is not allowed to alter the types of the arguments on the data stack')
                        compiler_note_(op.token.loc, 'Expected types: %s' % expected_types)
                        compiler_note_(op.token.loc, 'Actual types: %s' % actual_types)
                        exit(1)
                    stack = block_snapshot
                elif begin_typ == OpType.IF:
                    expected_types = list(map(lambda x: x[0], begin_snapshot))
                    actual_types = list(map(lambda x: x[0], stack))

                    if expected_types != actual_types:
                        compiler_error_with_expansion_stack(op.token, 'else-less if block is not allowed to alter the types of the arguments on the data stack')
                        compiler_note_(op.token.loc, 'Expected types: %s' % expected_types)
                        compiler_note_(op.token.loc, 'Actual types: %s' % actual_types)
                        exit(1)

                    stack = block_snapshot
                else:
                    assert False, "unreachable"
            else:
                assert "unreachable"
        elif op.typ == OpType.ELSE:
            do_snapshot, do_typ = block_stack.pop()
            assert do_typ == OpType.DO, "I smell a bug somwhere"

            if_snapshot, if_typ = block_stack.pop()
            assert if_typ == OpType.IF, "I smell a bug somewhere"

            block_stack.append((stack.copy(), op.typ))
            stack = do_snapshot
        elif op.typ == OpType.DO:
            if len(stack) < 1:
                print_missing_op_args(op)
                exit(1)
            a_typ, a_token = stack.pop()
            if a_typ != DataType.BOOL:
                compiler_error_with_expansion_stack(op.token, "invalid agrument for the WHILE-DO condition. Expected BOOL.")
                exit(1)
            block_stack.append((stack.copy(), op.typ))
        elif op.typ == OpType.INTRINSIC:
            assert len(Intrinsic) == 41, "Exhaustive handling of intrinsic in generate_nasm_linux_x86_64: %d" % len(Intrinsic)
            assert isinstance(op.operand, Intrinsic), "There is a bug in parsing step (probably)"
            assert len(DataType) == 3, "Exhaustive type handling in for `%s` in type_check_program(): %d" % (INTRINSIC_NAMES[op.operand], len(DataType))
            if op.operand == Intrinsic.PLUS:
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_loc = stack.pop()
                b_typ, b_loc = stack.pop()

                if a_typ == b_typ and (a_typ == DataType.INT or a_typ == DataType.PTR):
                    stack.append((DataType.INT, op.token))
                elif a_typ == DataType.INT and b_typ == DataType.PTR:
                    stack.append((DataType.PTR, op.token))
                elif a_typ == DataType.PTR and b_typ == DataType.INT:
                    stack.append((DataType.PTR, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for PLUS intrinsic. Expected INT or PTR.")
                    exit(1)
            elif op.operand == Intrinsic.MINUS:
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_loc = stack.pop()
                b_typ, b_loc = stack.pop()
                if a_typ == b_typ and (a_typ == DataType.INT or a_typ == DataType.PTR):
                    stack.append((DataType.INT, op.token))
                elif b_typ == DataType.PTR and a_typ == DataType.INT:
                    stack.append((DataType.PTR, op.token))
                elif a_typ == DataType.PTR and b_typ == DataType.INT:
                    compiler_error_with_expansion_stack(op.token, "Subtracting a PTR from INT is not allowed")
                    exit(1)
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for MINUS intrinsic. Expected INT, PTR")
                    exit(1)
            elif op.operand == Intrinsic.MUL:
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_loc = stack.pop()
                b_typ, b_loc = stack.pop()
                if a_typ == DataType.INT and b_typ == DataType.INT:
                    stack.append((DataType.INT, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for MUL intrinsic. Expected INT")
                    exit(1)
            elif op.operand == Intrinsic.DIVMOD:
                # TODO: remove PTR support why would i MOD the PTR?
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_loc = stack.pop()
                b_typ, b_loc = stack.pop()
                if a_typ == DataType.INT and b_typ == DataType.INT:
                    stack.append((DataType.INT, op.token))
                    stack.append((DataType.INT, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for DIVMOD intrinsic. Expected INT")
                    exit(1)
            elif op.operand == Intrinsic.EQ:
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_loc = stack.pop()
                b_typ, b_loc = stack.pop()
                if a_typ == DataType.INT and b_typ == DataType.INT:
                    stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for EQ intrinsic. Expected INT")
                    exit(1)
            elif op.operand == Intrinsic.GT:
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_loc = stack.pop()
                b_typ, b_loc = stack.pop()
                if a_typ == DataType.INT and b_typ == DataType.INT:
                    stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for GT intrinsic. Expected INT")
                    exit(1)
            elif op.operand == Intrinsic.LT:
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_loc = stack.pop()
                b_typ, b_loc = stack.pop()
                if a_typ == DataType.INT and b_typ == DataType.INT:
                    stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for LT intrinsic. Expected INT")
                    exit(1)
            elif op.operand == Intrinsic.GE:
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_loc = stack.pop()
                b_typ, b_loc = stack.pop()
                if a_typ == DataType.INT and b_typ == DataType.INT:
                    stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for GE intrinsic. Expected INT")
                    exit(1)
            elif op.operand == Intrinsic.LE:
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_loc = stack.pop()
                b_typ, b_loc = stack.pop()
                if a_typ == DataType.INT and b_typ == DataType.INT:
                    stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for LE intrinsic. Expected INT")
                    exit(1)
            elif op.operand == Intrinsic.NE:
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_loc = stack.pop()
                b_typ, b_loc = stack.pop()
                if a_typ == DataType.INT and b_typ == DataType.INT:
                    stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for NE intrinsic. Expected INT")
                    exit(1)
            elif op.operand == Intrinsic.SHR:
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_pos = stack.pop()
                b_typ, b_pos = stack.pop()
                if a_typ == DataType.INT and b_typ == DataType.INT:
                    stack.append((DataType.INT, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for SHR intrinsic. Expected INT")
                    exit(1)
            elif op.operand == Intrinsic.SHL:
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_pos = stack.pop()
                b_typ, b_pos = stack.pop()
                if a_typ == DataType.INT and b_typ == DataType.INT:
                    stack.append((DataType.INT, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for SHL intrinsic. Expected INT")
                    exit(1)
            elif op.operand == Intrinsic.OR:
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_pos = stack.pop()
                b_typ, b_pos = stack.pop()

                if a_typ == b_typ and a_typ == DataType.INT:
                    stack.append((DataType.INT, op.token))
                elif a_typ == b_typ and a_typ == DataType.BOOL:
                    stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for OR intrinsic: %s" % [a_typ, b_typ])
                    exit(1)
            elif op.operand == Intrinsic.AND:
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_pos = stack.pop()
                b_typ, b_pos = stack.pop()
                if a_typ == DataType.INT and b_typ == DataType.INT:
                    stack.append((DataType.INT, op.token))
                elif a_typ == DataType.BOOL and b_typ == DataType.BOOL:
                    stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for AND intrinsic.")
                    exit(1)
            elif op.operand == Intrinsic.NOT:
                if len(stack) < 1:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_token = stack.pop()
                if a_typ == DataType.INT:
                    stack.append((DataType.INT, op.token))
                elif a_typ == DataType.BOOL:
                    stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for NOT intrinsic.")
                    exit(1)
            elif op.operand == Intrinsic.PRINT:
                if len(stack) < 1:
                    print_missing_op_args(op)
                    exit(1)
                stack.pop()
            elif op.operand == Intrinsic.DUP:
                if len(stack) < 1:
                    print_missing_op_args(op)
                a = stack.pop()
                stack.append(a)
                stack.append(a)
            elif op.operand == Intrinsic.SWAP:
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                a = stack.pop()
                b = stack.pop()
                stack.append(a)
                stack.append(b)
            elif op.operand == Intrinsic.DROP:
                if len(stack) < 1:
                    print_missing_op_args(op)
                    exit(1)
                stack.pop()
            elif op.operand == Intrinsic.OVER:
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                a = stack.pop()
                b = stack.pop()
                stack.append(b)
                stack.append(a)
                stack.append(b)
            elif op.operand == Intrinsic.ROT:
                if len(stack) < 3:
                    print_missing_op_args(op)
                    exit(1)
                a = stack.pop()
                b = stack.pop()
                c = stack.pop()
                stack.append(b)
                stack.append(a)
                stack.append(c)
            elif op.operand == Intrinsic.MEM:
                stack.append((DataType.PTR, op.token))
            elif op.operand == Intrinsic.LOAD:
                if len(stack) < 1:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_loc = stack.pop()
                
                if a_typ == DataType.PTR:
                    stack.append((DataType.INT, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for LOAD intrinsic. Expected PTR")
                    exit(1)
            elif op.operand == Intrinsic.FORTH_LOAD:
                if len(stack) < 1:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_loc = stack.pop()
                
                if a_typ == DataType.PTR:
                    stack.append((DataType.INT, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for LOAD intrinsic. Expected PTR")
                    exit(1)
            elif op.operand == Intrinsic.LOAD64:
                if len(stack) < 1:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_loc = stack.pop()
                
                if a_typ == DataType.PTR:
                    stack.append((DataType.INT, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for LOAD64 intrinsic. Expected PTR")
                    exit(1)
            elif op.operand == Intrinsic.FORTH_LOAD64:
                if len(stack) < 1:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_loc = stack.pop()
                
                if a_typ == DataType.PTR:
                    stack.append((DataType.INT, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for LOAD64 intrinsic. Expected PTR")
                    exit(1)
            elif op.operand == Intrinsic.STORE:
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_loc = stack.pop() 
                b_typ, b_loc = stack.pop() 

                if a_typ == DataType.INT and b_typ == DataType.PTR:
                    pass
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for STORE intrinsic: %s" % [a_typ,  b_typ])
                    exit(1)
            elif op.operand == Intrinsic.FORTH_STORE:
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_loc = stack.pop() 
                b_typ, b_loc = stack.pop() 

                if a_typ == DataType.PTR and b_typ == DataType.INT:
                    pass
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for STORE intrinsic: %s" % [a_typ,  b_typ])
                    exit(1)
            elif op.operand == Intrinsic.STORE64:
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_loc = stack.pop() 
                b_typ, b_loc = stack.pop() 

                if (a_typ == DataType.INT or a_typ == DataType.PTR) and b_typ == DataType.PTR:
                    pass
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for STORE64 intrinsic: %s" % [a_typ, b_typ])
                    exit(1)
            elif op.operand == Intrinsic.FORTH_STORE64:
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_loc = stack.pop() 
                b_typ, b_loc = stack.pop() 

                if (b_typ == DataType.INT or b_typ == DataType.PTR) and a_typ == DataType.PTR:
                    pass
                else:
                    compiler_error_with_expansion_stack(op.token, "Invalid argument types for STORE64 intrinsic: %s" % [a_typ, b_typ])
                    exit(1)
            elif op.operand == Intrinsic.CAST_PTR:
                if len(stack) < 1:
                    print_missing_op_args(op)
                    exit(1)
                a_typ, a_token = stack.pop()
                stack.append((DataType.PTR, a_token))
            elif op.operand == Intrinsic.ARGC:
                stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.ARGV:
                stack.append((DataType.PTR, op.token))
            elif op.operand == Intrinsic.HERE:
               stack.append((DataType.INT, op.token)) 
               stack.append((DataType.PTR, op.token)) 
            elif op.operand == Intrinsic.SYSCALL0:
                if len(stack) < 1:
                    print_missing_op_args(op)
                    exit(1)
                for i in range(1):
                    stack.pop()
                stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL1:
                if len(stack) < 2:
                    print_missing_op_args(op)
                    exit(1)
                for i in range(2):
                    stack.pop()
                stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL2:
                if len(stack) < 3:
                    print_missing_op_args(op)
                    exit(1)
                for i in range(3):
                    stack.pop()
            elif op.operand == Intrinsic.SYSCALL3:
                if len(stack) < 4:
                    print_missing_op_args(op)
                    exit(1)
                for i in range(4):
                    stack.pop()
                stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL4:
                if len(stack) < 5:
                    print_missing_op_args(op)
                    exit(1)
                for i in range(5):
                    stack.pop()
                stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL5:
                if len(stack) < 6:
                    print_missing_op_args(op)
                    exit(1)
                for i in range(6):
                    stack.pop()
                stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL6:
                if len(stack) < 7:
                    print_missing_op_args(op)
                    exit(1)
                for i in range(7):
                    stack.pop()
                stack.append((DataType.INT, op.token))
            else:
                assert False, "unreachable"
        else:
            assert False, "unreachable"
    if len(stack) != 0:
        compiler_error_with_expansion_stack(stack[-1][1], "unhandled data on the stack: %s" % list(map(lambda x: x[0], stack)))
        exit(1)

def generate_nasm_linux_x86_64(program: Program, out_file_path: str):
    strs: List[bytes] = []
    with open(out_file_path, "w") as out:
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
        out.write("    mov [args_ptr], rsp\n")
        for ip in range(len(program)):
            op = program[ip]
            assert len(OpType) == 9, "Exhaustive ops handling in generate_nasm_linux_x86_64: %d" % len(OpType)
            out.write("addr_%d:\n" % ip)
            if op.typ == OpType.PUSH_INT:
                out.write(";;  -- push int --\n")
                assert isinstance(op.operand, int), "There is a bug in the parsing step (probably)"
                out.write("    mov rax, %d\n" % op.operand)
                out.write("    push rax\n")
            elif op.typ == OpType.PUSH_STR:
                assert isinstance(op.operand, str), "There is a bug in the parsing step (probably)"
                value = op.operand.encode('utf-8')
                n = len(value)
                out.write(";;  -- push str --\n")
                out.write("    mov rax, %d\n" % n)
                out.write("    push rax\n")
                out.write("    push str_%d\n" % len(strs))
                strs.append(value)
            elif op.typ == OpType.PUSH_CSTR:
                assert isinstance(op.operand, str), "There is a bug in the parsing step (probably)"
                value = op.operand.encode('utf-8') + b'\0'
                out.write(";;  -- push str --\n")
                out.write("    push str_%d\n" % len(strs))
                strs.append(value)
            elif op.typ == OpType.IF:
                out.write(";;  -- if --\n")
            elif op.typ == OpType.WHILE:
                out.write(";;  -- while --\n")
            elif op.typ == OpType.ELSE:
                out.write(";;  -- else --\n")
                assert isinstance(op.operand, int), "There is a bug in the parsing step (probably)"
                out.write("    jmp addr_%d\n" % op.operand)
            elif op.typ == OpType.END:
                assert isinstance(op.operand, int), "There is a bug in the parsing step (probably)"
                out.write(";;  -- end --\n")
                if ip + 1 != op.operand:
                    out.write("    jmp addr_%d\n" % op.operand)
            elif op.typ == OpType.DO:
                out.write(";;  -- do --\n")
                out.write("    pop rax\n")
                out.write("    test rax, rax\n")
                assert isinstance(op.operand, int), "There is a bug in the parsing step (probably)"
                out.write("    jz addr_%d\n" % op.operand)
            elif op.typ == OpType.INTRINSIC:
                assert len(Intrinsic) == 41, "Exhaustive handling of intrinsic in generate_nasm_linux_x86_64: %d" % len(Intrinsic)
                if op.operand == Intrinsic.PLUS:
                    out.write(";;  -- plus --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    add rax, rbx\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.MINUS:
                    out.write(";;  -- minus --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    sub rbx, rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.MUL:
                    out.write(";;  -- mul --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    mul rbx\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.DIVMOD:
                    out.write(";;  -- divmod --\n")
                    out.write("    xor rdx, rdx\n")
                    out.write("    pop rbx\n")
                    out.write("    pop rax\n")
                    out.write("    div rbx\n")
                    out.write("    push rax\n")
                    out.write("    push rdx\n")
                elif op.operand == Intrinsic.SHR:
                    out.write(";;  -- shr --\n")
                    out.write("    pop rcx\n")
                    out.write("    pop rbx\n")
                    out.write("    shr rbx, cl\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.SHL:
                    out.write(";;  -- shl --\n")
                    out.write("    pop rcx\n")
                    out.write("    pop rbx\n")
                    out.write("    shl rbx, cl\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.OR:
                    out.write(";;  -- or --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    or rbx, rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.AND:
                    out.write(";;  -- and --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    and rbx, rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.NOT:
                    out.write(";;  -- not --\n")
                    out.write("    pop rax\n")
                    out.write("    not rax\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.PRINT:
                    out.write(";;  -- print --\n")
                    out.write("    pop rdi\n")
                    out.write("    call print\n")
                elif op.operand == Intrinsic.EQ:
                    out.write(";;  -- equal -- \n")
                    out.write("    mov rcx, 0\n");
                    out.write("    mov rdx, 1\n");
                    out.write("    pop rax\n");
                    out.write("    pop rbx\n");
                    out.write("    cmp rax, rbx\n");
                    out.write("    cmove rcx, rdx\n");
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.GT:
                    out.write(";;  -- gt --\n")
                    out.write("    mov rcx, 0\n");
                    out.write("    mov rdx, 1\n");
                    out.write("    pop rbx\n");
                    out.write("    pop rax\n");
                    out.write("    cmp rax, rbx\n");
                    out.write("    cmovg rcx, rdx\n");
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.LT:
                    out.write(";;  -- gt --\n")
                    out.write("    mov rcx, 0\n");
                    out.write("    mov rdx, 1\n");
                    out.write("    pop rbx\n");
                    out.write("    pop rax\n");
                    out.write("    cmp rax, rbx\n");
                    out.write("    cmovl rcx, rdx\n");
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.GE:
                    out.write(";;  -- gt --\n")
                    out.write("    mov rcx, 0\n");
                    out.write("    mov rdx, 1\n");
                    out.write("    pop rbx\n");
                    out.write("    pop rax\n");
                    out.write("    cmp rax, rbx\n");
                    out.write("    cmovge rcx, rdx\n");
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.LE:
                    out.write(";;  -- gt --\n")
                    out.write("    mov rcx, 0\n");
                    out.write("    mov rdx, 1\n");
                    out.write("    pop rbx\n");
                    out.write("    pop rax\n");
                    out.write("    cmp rax, rbx\n");
                    out.write("    cmovle rcx, rdx\n");
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.NE:
                    out.write(";;  -- ne --\n")
                    out.write("    mov rcx, 0\n")
                    out.write("    mov rdx, 1\n")
                    out.write("    pop rbx\n")
                    out.write("    pop rax\n")
                    out.write("    cmp rax, rbx\n")
                    out.write("    cmovne rcx, rdx\n")
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.DUP:
                    out.write(";;  -- dup -- \n")
                    out.write("    pop rax\n")
                    out.write("    push rax\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SWAP:
                    out.write(";;  -- swap --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    push rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.DROP:
                    out.write(";;  -- drop --\n")
                    out.write("    pop rax\n")
                elif op.operand == Intrinsic.OVER:
                    out.write(";;  -- over --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    push rbx\n")
                    out.write("    push rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.ROT:
                    out.write(";;  -- rot --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    pop rcx\n")
                    out.write("    push rbx\n")
                    out.write("    push rax\n")
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.MEM:
                    out.write(";;  -- mem --\n")
                    out.write("    push mem\n")
                elif op.operand == Intrinsic.LOAD:
                    out.write(";;  -- load --\n")
                    out.write("    pop rax\n")
                    out.write("    xor rbx, rbx\n")
                    out.write("    mov bl, [rax]\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.FORTH_LOAD:
                    out.write(";;  -- forth load --\n")
                    out.write("    pop rax\n")
                    out.write("    xor rbx, rbx\n")
                    out.write("    mov bl, [rax]\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.STORE:
                    out.write(";;  -- store --\n")
                    out.write("    pop rbx\n");
                    out.write("    pop rax\n");
                    out.write("    mov [rax], bl\n");
                elif op.operand == Intrinsic.FORTH_STORE:
                    out.write(";;  -- forth store --\n")
                    out.write("    pop rax\n");
                    out.write("    pop rbx\n");
                    out.write("    mov [rax], bl\n");
                elif op.operand == Intrinsic.LOAD64:
                    out.write(";;  -- load64 --\n")
                    out.write("    pop rax\n")
                    out.write("    xor rbx, rbx\n")
                    out.write("    mov rbx, [rax]\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.FORTH_LOAD64:
                    out.write(";;  -- forth load64 --\n")
                    out.write("    pop rax\n")
                    out.write("    xor rbx, rbx\n")
                    out.write("    mov rbx, [rax]\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.STORE64:
                    out.write(";;  -- store64 --\n")
                    out.write("    pop rbx\n");
                    out.write("    pop rax\n");
                    out.write("    mov [rax], rbx\n");
                elif op.operand == Intrinsic.FORTH_STORE64:
                    out.write(";;  -- forth store64 --\n")
                    out.write("    pop rax\n");
                    out.write("    pop rbx\n");
                    out.write("    mov [rax], rbx\n");
                elif op.operand == Intrinsic.CAST_PTR:
                    pass
                elif op.operand == Intrinsic.ARGC:
                    out.write(";;  -- argc --\n")
                    out.write("    mov rax, [args_ptr]\n")
                    out.write("    mov rax, [rax]\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.ARGV:
                    out.write(";;  -- argv --\n")
                    out.write("    mov rax, [args_ptr]\n")
                    out.write("    add rax, 8\n")
                    out.write("    push rax\n") 
                elif op.operand == Intrinsic.HERE:
                    value = ("%s:%d:%d" % op.token.loc).encode("utf-8")
                    n = len(value)
                    out.write(";; -- here --\n")
                    out.write("    mov rax, %d\n" % n)
                    out.write("    push rax\n")
                    out.write("    push str_%d\n" % len(strs))
                    strs.append(value)
                elif op.operand == Intrinsic.SYSCALL0:
                    out.write(";;  -- syscall0 --\n")
                    out.write("    pop rax\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL1:
                    out.write(";;  -- syscall1 --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rdi\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL2:
                    out.write(";;  -- syscall2 -- \n")
                    out.write("    pop rax\n");
                    out.write("    pop rdi\n");
                    out.write("    pop rsi\n");
                    out.write("    syscall\n");
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL3:
                    out.write(";;  -- syscall3 --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rdi\n")
                    out.write("    pop rsi\n")
                    out.write("    pop rdx\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL4:
                    out.write(";;  -- syscall4 --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rdi\n")
                    out.write("    pop rsi\n")
                    out.write("    pop rdx\n")
                    out.write("    pop r10\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL5:
                    out.write(";;  -- syscall5 --\n")
                    out.write("    pop rax\n")
                    out.write("    pop rdi\n")
                    out.write("    pop rsi\n")
                    out.write("    pop rdx\n")
                    out.write("    pop r10\n")
                    out.write("    pop r8\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL6:
                    out.write(";;  -- syscall6 --\n")
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
        out.write(";;  -- allocated data --\n")
        out.write("segment .data\n")               # segment for staticaly allocated elements
        for index, s in enumerate(strs):
            out.write("str_%d: db %s\n" % (index, ','.join(map(hex, list(bytes(s))))))
        out.write(";;  -- not yet allocated data --\n")
        out.write("segment .bss\n")                # segment of statically allocated declared variables that have no value assigned to them yet
        out.write("args_ptr: resq 1\n")            # reserve space for arguments(argv)
        out.write("mem: resb %d\n" % MEM_CAPACITY) # reserve space for program memory

assert len(Keyword) == 7, "Exhaustive KEYWORD_NAMES definition: %d" % len(Keyword) 
KEYWORD_NAMES= {
    'if': Keyword.IF,
    'end': Keyword.END,
    'else': Keyword.ELSE,
    'while': Keyword.WHILE,
    'do': Keyword.DO,
    'macro': Keyword.MACRO,
    'include': Keyword.INCLUDE,
}

assert len(Intrinsic) == 41, "Exhaustive INTRINSIC_BY_NAMES definition.: %d" % len(Intrinsic)
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
    'shr': Intrinsic.SHR,
    'shl': Intrinsic.SHL,
    'or': Intrinsic.OR,
    'and': Intrinsic.AND,
    'not': Intrinsic.NOT,
    'dup': Intrinsic.DUP,
    'swap': Intrinsic.SWAP,
    'drop': Intrinsic.DROP,
    'over': Intrinsic.OVER,
    'rot' : Intrinsic.ROT,
    'mem': Intrinsic.MEM,
    '.': Intrinsic.STORE,
    '!': Intrinsic.FORTH_STORE,
    '.64': Intrinsic.STORE64,
    '!64': Intrinsic.FORTH_STORE64,
    ',': Intrinsic.LOAD,
        ',64': Intrinsic.LOAD64,
    '@': Intrinsic.FORTH_LOAD,
    '@64': Intrinsic.FORTH_LOAD64,
    'cast(ptr)': Intrinsic.CAST_PTR,
    'argc': Intrinsic.ARGC,
    'argv': Intrinsic.ARGV,
    'here': Intrinsic.HERE,
    'syscall0': Intrinsic.SYSCALL0,
    'syscall1': Intrinsic.SYSCALL1,
    'syscall2': Intrinsic.SYSCALL2,
    'syscall3': Intrinsic.SYSCALL3,
    'syscall4': Intrinsic.SYSCALL4,
    'syscall5': Intrinsic.SYSCALL5,
    'syscall6': Intrinsic.SYSCALL6,
}

INTRINSIC_NAMES = {v: k for k, v in INTRINSIC_BY_NAMES.items()}

@dataclass
class Macro:
    loc: Loc
    tokens: List[Token]
    
def token_name(typ: TokenType) -> str:
    assert len(TokenType) == 6, "Exhaustive handling of TokenType in token_name(): %d" % len(TokenType)
    if typ == TokenType.WORD:
        return "word"
    elif typ == TokenType.INT:
        return "integer"
    elif typ == TokenType.STR:
        return "string"
    elif typ == TokenType.CSTR:
        return "c-string"
    elif typ == TokenType.CHAR:
        return "character"
    else:
        assert False, "unreachable"

def expand_macro(macro: Macro, expanded_from: Token) -> List[Token]:
    result = list(map(copy, macro.tokens))
    for token in result:
        token.expanded_from = expanded_from
        token.expanded_count = expanded_from.expanded_count + 1
    return result

def parse_program_from_tokens(tokens: List[Token], include_paths: List[str], expansion_limit: int) -> Program:
    stack = []
    program: List[Op] = []
    rtokens = list(reversed(tokens))
    macros: Dict[str, Macro] = {}
    ip = 0;
    while len(rtokens) > 0:
        # TODO: some sort of safety mechanisem for recursive macros
        token = rtokens.pop()
        assert len(TokenType) == 6, "Exhaustive token handling in parse_program_from_tokens: %d" % len(TokenType)
        if token.typ == TokenType.WORD:
            if token.value in INTRINSIC_BY_NAMES:
                assert isinstance(token.value, str)
                program.append(Op(typ=OpType.INTRINSIC, token=token, operand=INTRINSIC_BY_NAMES[token.value]))
                ip += 1
            elif token.value in macros:
                if token.expanded_count >= expansion_limit:
                    compiler_error_with_expansion_stack(token, "the macro exceeded the expansion limit (it expanded %d times)" % token.expanded_count)
                    exit(1)
                assert isinstance(token.value, str)
                rtokens += reversed(expand_macro(macros[token.value], token))
                continue
            else:
                compiler_error_with_expansion_stack(token, "unknown word `%s`" % token.value)
                exit(1)
        elif token.typ == TokenType.INT:
            assert isinstance(token.value, int), "This is a lexer bug (probably)"
            program.append(Op(typ=OpType.PUSH_INT, operand=token.value, token=token))
            ip += 1
        elif token.typ == TokenType.STR:
            assert isinstance(token.value, str), "This is a lexer bug (probably)"
            program.append(Op(typ=OpType.PUSH_STR, operand=token.value, token=token))
            ip += 1
        elif token.typ == TokenType.CSTR:
            assert isinstance(token.value, str), "This is a lexer bug (probably)"
            program.append(Op(typ=OpType.PUSH_CSTR, operand=token.value, token=token))
            ip += 1
        elif token.typ == TokenType.CHAR:
            assert isinstance(token.value, int), "This is a lexer bug (probably)"
            program.append(Op(typ=OpType.PUSH_INT, operand=token.value, token=token))
            ip += 1
        elif token.typ == TokenType.KEYWORD:
            assert len(Keyword) == 7, "Exhaustive keywords handling in compile_file_to_program(): %d" % len(Keyword)

            if token.value == Keyword.IF:
                program.append(Op(typ=OpType.IF, token=token))
                stack.append(ip)
                ip += 1
            elif token.value == Keyword.ELSE:
                program.append(Op(typ=OpType.ELSE, token=token))
                do_ip = stack.pop()
                if program[do_ip].typ != OpType.DO:
                    compiler_error_with_expansion_stack(program[do_ip].token, "`else` can only be used in `if-do` blocks")
                    exit(1)
                program[do_ip].operand = ip + 1
                stack.append(ip)
                ip += 1
            elif token.value == Keyword.END:
                program.append(Op(typ=OpType.END, token=token))
                block_ip = stack.pop()
                if program[block_ip].typ == OpType.ELSE:
                    program[block_ip].operand = ip
                    program[ip].operand = ip + 1
                elif program[block_ip].typ == OpType.DO:
                    assert program[block_ip].operand is not None
                    block_begin_ip = program[block_ip].operand

                    assert isinstance(block_begin_ip, OpAddr)
                    if program[block_begin_ip].typ == OpType.WHILE:
                        program[ip].operand = block_begin_ip
                        program[block_ip].operand = ip + 1
                    elif program[block_begin_ip].typ == OpType.IF:
                        program[ip].operand = ip + 1
                        program[block_ip].operand = ip + 1
                    else:
                        compiler_error_with_expansion_stack(program[block_begin_ip].token, "`end` can only close `do` blocks that are part of `if` or `while`")
                        exit(1)
                else:
                    compiler_error_with_expansion_stack(program[block_ip].token, "`end` can only close `else`, `do` or `macro` blocks")
                    exit(1)
                ip += 1
            elif token.value == Keyword.WHILE:
                program.append(Op(typ=OpType.WHILE, token=token))
                stack.append(ip)
                ip += 1
            elif token.value == Keyword.DO:
                program.append(Op(typ=OpType.DO, token=token))
                while_or_if_ip = stack.pop()
                program[ip].operand = while_or_if_ip
                stack.append(ip)
                ip += 1
            elif token.value == Keyword.INCLUDE:
                if len(rtokens) == 0:
                    compiler_error_with_expansion_stack(token, "expected path to include file but found nothing")
                    exit(1)
                token = rtokens.pop()
                if token.typ != TokenType.STR:
                    compiler_error_with_expansion_stack(token, "expected path to include file to be %s but found %s" % (token_name(TokenType.STR), token_name(token.typ)))
                    exit(1)
                assert isinstance(token.value, str), "This is probably a bug in the lexer"
                file_included = False
                for include_path in include_paths:
                    try:
                        if token.expanded_count >= expansion_limit:
                            compiler_error_with_expansion_stack(token, "the include exceeded the expansion limit (it expanded %d times)" % token.expanded_count)
                            exit(1)
                        rtokens += reversed(lex_file(path.join(include_path, token.value), token))
                        file_included = True
                        break
                    except FileNotFoundError:
                        continue
                if not file_included:
                    compiler_error_with_expansion_stack(token, "File `%s` not found" % token.value)
                    exit(1)
            elif token.value == Keyword.MACRO:
                if len(rtokens) == 0:
                    compiler_error_with_expansion_stack(token, "expected macro name but found nothing")
                    exit(1)
                token = rtokens.pop()
    
                if token.typ != TokenType.WORD:
                    compiler_error_with_expansion_stack(token, "expected macro name to be %s but found %s" % (token_name(TokenType.WORD), token_name(token.typ)))
                    exit(1)
                assert isinstance(token.value, str), "This is a bug in the lexer (probably)"
                if token.value in macros:
                    compiler_error_with_expansion_stack(token, "redefinition of already existing macro `%s`" % token.value)
                    compiler_note_(macros[token.value].loc, "the first definition is located here")
                    exit(1)
                if token.value in INTRINSIC_BY_NAMES:
                    compiler_error_with_expansion_stack(token, "redefinition of a intrinsic word `%s`" % token.value)
                    exit(1)
    
                macro = Macro(token.loc, [])
                macro_name = token.value
                macros[macro_name] = macro
    
                nesting_depth = 0
                while len(rtokens) > 0:
                    token = rtokens.pop()
                    if token.typ == TokenType.KEYWORD and token.value == Keyword.END and nesting_depth == 0: 
                        break
                    else:
                        macro.tokens.append(token)
                        if token.value in [Keyword.IF, Keyword.WHILE, Keyword.MACRO]:
                            nesting_depth += 1
                        elif token.value == Keyword.END:
                            nesting_depth -= 1
    
                if token.typ != TokenType.KEYWORD and token.value != Keyword.END:
                    compiler_error_with_expansion_stack(token, "expected `end` at the end of the macro definition but got `%s`" % (token.value,))
                    exit(1)
            else:
                assert False, "unreachable"
        else:
            assert False, "unreachable"


    if len(stack) > 0:
        compiler_error_with_expansion_stack(program[stack.pop()].token, "unclosed block")
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
                    compiler_error_(loc, "unclosed string literal")
                    exit(1)
                assert line[col_end] == '"'
                col_end += 1
                text_of_token = str_literal_buf
                str_literal_buf = ""
                if col_end < len(line) and line[col_end] == "c":
                    col_end += 1
                    yield Token(TokenType.CSTR, text_of_token, loc, unescape_string(text_of_token))
                else:
                    yield Token(TokenType.STR, text_of_token, loc, unescape_string(text_of_token))
                col = find_col(line, col_end+1, lambda x: not x.isspace())
            elif line[col] == "'":
                col_end = find_col(line, col+1, lambda x: x == "'")
                if col_end >= len(line) or line[col_end] != "'":
                    compiler_error_(loc, "unclosed character literal") 
                    exit(1)
                char_bytes = unescape_string(line[col+1:col_end]).encode('utf-8')
                if len(char_bytes) != 1:
                    compiler_error_(loc, "only a single byte is allowed inside of a character literal")
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

def compile_file_to_program(file_path: str, include_paths: List[str], expansion_limit: int) -> Program:
    return parse_program_from_tokens(lex_file(file_path), include_paths, expansion_limit)

def cmd_call_echoed(cmd: List[str], silent: bool=False) -> int:
    if not silent:
        print("[CMD] %s" % " ".join(map(shlex.quote, cmd)))
    return subprocess.call(cmd)

def generate_control_flow_graph_as_dot_file(program: Program, dot_path: str):
    print(f"[INFO] Generating {dot_path}")
    with open(dot_path, "w") as f:
        f.write("digraph Program {\n")
        for ip in range(len(program)):
            op = program[ip]
            if op.typ == OpType.INTRINSIC:
                f.write(f"    Node_{ip} [label={repr(repr(INTRINSIC_NAMES[op.operand]))}];\n")
                f.write(f"    Node_{ip} -> Node_{ip+1};\n")
            elif op.typ == OpType.PUSH_INT:
                f.write(f"    Node_{ip} [label=\"INT: {op.operand}\"];")
                f.write(f"    Node_{ip} -> Node_{ip+1};\n")
            elif op.typ == OpType.PUSH_STR:
                f.write(f"    Node_{ip} [label={repr(repr(op.operand))}];\n")
                f.write(f"    Node_{ip} -> Node_{ip+1};\n")
            elif op.typ == OpType.PUSH_CSTR:
                f.write(f"    Node_{ip} [label={repr(repr(op.operand))}];\n")
                f.write(f"    Node_{ip} -> Node_{ip+1};\n")
            elif op.typ == OpType.IF:
                f.write(f"    Node_{ip} [shape=record label=if];\n")
                f.write(f"    Node_{ip} -> Node_{ip+1};\n")
            elif op.typ == OpType.WHILE:
                f.write(f"    Node_{ip} [shape=record label=while];\n")
                f.write(f"    Node_{ip} -> Node_{ip+1};\n")
            elif op.typ == OpType.DO:
                f.write(f"    Node_{ip} [shape=record label=do];\n")
                f.write(f"    Node_{ip} -> Node_{ip+1} [label=true];\n")
                f.write(f"    Node_{ip} -> Node_{op.operand} [label=false style=dashed];\n")
            elif op.typ == OpType.ELSE:
                f.write(f"    Node_{ip} [shape=record label=else];\n")
                f.write(f"    Node_{ip} -> Node_{op.operand};\n")
            elif op.typ == OpType.END:
                f.write(f"    Node_{ip} [shape=record label=end];\n")
                f.write(f"    Node_{ip} -> Node_{op.operand};\n")
            else:
                assert False, f"unimplemented operation {[op.typ]}"
        f.write(f"    Node_{len(program)} [label=halt]")
        f.write("}\n")
    cmd_call_echoed(["dot", "-Tsvg", "-O", dot_path])

def print_usage(compiler_name: str):
    print("Usage: %s [OPTIONS] <SUBCOMMAND> [ARGS]" % compiler_name)
    print("  options:")
    print("    --debug                Enable debug mode")
    print("    --unsafe               Disable type checking")
    print("    -I <path>             Add the path to the include search list")
    print("    -E <expansion-limit>  Macro and include expansion limit (Default %d)" % DEFAULT_EXPANSION_LIMIT)
    print("  SUBCOMMAND:")
    print("    sim <file>            Simulate the program")
    print("    com [OPTIONS] <file>  Compile the program")
    print("      OPTIONS:")
    print("        -r                  Run the program after successful compilation")
    print("        -o <file|dir>       Customize the output path")
    print("        -s                  Silent mode ~ Don't print any info about compilation phases")
    print("        -cf                 Dump Control Flow graph of the program in dot format")
    print("    help                  Print this help to stdout and exit with 0 code")

unsafe=False

if __name__ == '__main__' and '__file__' in globals():
    argv = sys.argv
    assert len(argv) >= 1
    compiler_name, *argv = argv

    include_paths = ['.', './std/']
    expansion_limit = DEFAULT_EXPANSION_LIMIT

    while len(argv) > 0:
        if argv[0] == '--debug':
            argv = argv[1:]
            debug = True
        if argv[0] == '--unsafe':
            argv = argv[1:]
            unsafe = True
        elif argv[0] == '-I':
            argv = argv[1:]
            if len(argv) == 0:
                print_usage(compiler_name)
                print("[ERROR] no path is provided for `-I` flag", file=sys.stderr)
                exit(1)
            include_path, *argv = argv
            include_paths.append(include_path)
        elif argv[0] == '-E':
            argv = argv[1:]
            if len(argv) == 0:
                print_usage(compiler_name)
                print("[ERROR] no value is provided for `-E` flag", file=sys.stderr)
                exit(1)
            arg, *argv = argv
            expansion_limit = int(arg)
        else:
            break

    if debug:
        print("[INFO] Debug mode is enabled")
        print("[INFO] Type checking enabled")

    if len(argv) < 1:
        print_usage(compiler_name)
        print("[ERROR] no subcommand is provided", file=sys.stderr)
        exit(1)
    subcommand, *argv = argv

    program_path: Optional[str] = None

    if subcommand == "sim":
        if len(argv) < 1:
            print_usage(compiler_name)
            print("[ERROR] no input file is provided for the simulation", file=sys.stderr)
            exit(1)
        program_path, *argv = argv
        program = compile_file_to_program(program_path, include_paths, expansion_limit);
        if not unsafe:
            type_check_program(program)
        else:
            print("[INFO] Simulating in UNSAFE mode")
        simulate_little_endian_linux(program, [program_path]+argv)
    elif subcommand == "com":
        silent = False
        control_flow = False
        run = False
        output_path = None
        while len(argv) > 0:
            arg, *argv = argv
            if arg == '-r':
                run = True
            elif arg == '-s':
                silent = True
            elif arg == '-o':
                if len(argv) == 0:
                    print_usage(compiler_name)
                    print("[ERROR] no argument is provided for parameter -o", file=sys.stderr)
                    exit(1)
                output_path, *argv = argv
            elif arg == '-cf':
                control_flow = True
            else:
                program_path = arg
                break

        if program_path is None:
            print_usage(compiler_name)
            print("[ERROR] no input file is provided for the compilation", file=sys.stderr)
            exit(1)

        basename = None
        basedir = None
        if output_path is not None:
            if path.isdir(output_path):
                basename = path.basename(program_path)
                if basename.endswith(PORTH_EXT):
                    basename = basename[:-len(PORTH_EXT)]
                basedir = path.dirname(output_path)
            else:
                basename = path.basename(output_path)
                basedir = path.dirname(output_path)
        else:
            basename = path.basename(program_path)
            if basename.endswith(PORTH_EXT):
                basename = basename[:-len(PORTH_EXT)]
            basedir = path.dirname(program_path)

        # if basedir is empty we should "fix" the path appending the current working directory.
        # So we avoid `com -r` to run command from $PATH.
        if basedir == "":
            basedir = os.getcwd()
        basepath = path.join(basedir, basename)

        if not silent:
            print("[INFO] Generating %s" % (basepath + ".asm"))
        program = compile_file_to_program(program_path, include_paths, expansion_limit);

        if control_flow:
            generate_control_flow_graph_as_dot_file(program, basepath + ".dot")
        if not unsafe:
            type_check_program(program)
        else:
            print("[INFO] Compiling in UNSAFE mode")
        generate_nasm_linux_x86_64(program, basepath + ".asm")
        cmd_call_echoed(["nasm", "-felf64", basepath + ".asm"], silent)
        cmd_call_echoed(["ld", "-o", basepath, basepath + ".o"], silent)
        if run:
            exit(cmd_call_echoed([basepath] + argv, silent))
    elif subcommand == "help":
        print_usage(compiler_name)
        exit(0)
    else:
        print_usage(compiler_name)
        print("[ERROR] unknown subcommand %s" % (subcommand), file=sys.stderr)
        exit(1)

