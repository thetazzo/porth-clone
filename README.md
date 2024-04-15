# PORTH-clone

* A clone of TSoding Porth programming language
* Developed for education purposes
* It is supposed to be a stack-based language which is a clone of Forth

### Example

* Hello World
```pascal
include "std.porth"

"Hello World!\n" puts
```

* A program that prints numbers from 0 to 69
```pascal
include "std.porth"

69 0 while 2dup >= do
    dup print
    1 +
end 2drop
```

### Compilation

Compilation generates assembly code, compiles it with [nasm](https://www.nasm.us/), and then links it with [GNU ld](https://www.gnu.org/software/binutils/). So make sure you have both available in your `$PATH`.

```console
$ cat program.porth
34 35 + print
$ ./porth.py com program.porth
[INFO] Generating ./program.asm
[CMD] nasm -felf64 ./program.asm
[CMD] ld -o ./program ./program.o
$ ./program
69
```

### Testing

Test cases are located in [./tests/](./tests/) folder. The `*.txt` files are the expected outputs of the corresponding programs.

Run [./test.py](./test.py) script to execute the programs and assert their outputs:

```console
$ ./test.py
```

To updated expected output files run the `record` subcommand:

```console
$ ./test.py record
```

The [./examples/](./examples/) contains programs that are ment for showcasing the language rather then testing it, but we still can them for testing just like the stuff in [./tests/](./tests/):

```console
$ ./test.py -f ./examples/
$ ./test.py -f ./examples/ record
```

---

### Rule 110
* Proving the language is turing complete or whatever
```console
$ ./porth.py sim ./examples/rule-110.porth
$ ./porth.py com ./examples/rule-110.porth
$ ./examples/rule-110
```

---

## Documentation

### Data types

#### Integer

Currently an integer is anything that is parsable by [int](https://docs.python.org/3/library/functions.html#int) function of Python. When the compiler encounters an integer it pushes it onto the data stack for processing by the relevant operations.

Example:

```pascal
10 20 +
```

The code above pushes 10 and 20 onto the data stack and sums them up with `+` operation.

#### String

Currently a string is any sequence of bytes sandwiched between two `"`. No newlines inside of the strings are allowed. Escaping is done by [unicode_escape codec](https://docs.python.org/3/library/codecs.html#text-encodings) of Python. No way to escape `"` themselves for now. No special support for Unicode is provided right now too.

When the compiler encounters a string:
1. the size of the string in bytes is pushed onto the data stack,
2. the bytes of the string are copied somewhere into the memory (the exact location is implementation specific),
3. the pointer to the beginning of the string is pushed onto the data stack.

Those, a single string pushes two values onto the data stack: the size and the pointer.

Example:

```
include "std.porth"
"Hello, World" puts
```

The `puts` macro from `std.porth` module expects two values on the data stack:
1. the size of the buffer it needs to print,
2. the pointer to the beginning of the buffer.

The size and the pointer are provided by the string `"Hello, World"`.

#### C-style String

It's like a regular string but it does not push its size on the stack and implicitly ends with [NULL-terminator](https://en.wikipedia.org/wiki/Null-terminated_string). Designed specifically to interact with C code or any other kind of code that expects NULL-terminated strings.

```
include "std.porth"

O_RDONLY "input.txt"c AT_FDCWD openat
//                  ^
//                  |
//                  postfix that indicates a C-style string

if dup 0 < do
    "ERROR: could not open the file\n" eputs
    1 exit
else
    "Successfully opened the file!\n" puts
end

close
```

Here we are using [openat(2)](https://linux.die.net/man/2/openat) Linux syscall to open a file. The syscall expects the pathname to be a NULL-terminated string.

#### Character

Currently a character is a single byte sandwiched between two `'`. Escaping is done by [unicode_escape codec](https://docs.python.org/3/library/codecs.html#text-encodings) of Python. No way to escape `'` themselves for now. No special support for Unicode is provided right now too.

When compiler encounters a character it pushes its value as an integer onto the stack.

Example:

```
'E' print
```

This program pushes integer `69` onto the stack (since the ASCII code of letter `E` is `69`) and prints it with the `print` operation.

### Intrinsics (Built-in Words)

* signature is constructed as such ``<inputs> -- <outputs>`` where inputs refer to the values on the stack before intrinsic execution and outputs the values after execution

#### Stack Manipulation

| Name    | Signature        | Description                                                                                  |
| ---     | ---              | ---                                                                                          |
| `dup`   | `a -- a a`       | duplicate the element on top of the stack                                                    |
| `swap`  | `a b -- b a`     | swap 2 elements on the top of the stack                                                      |
| `drop`  | `a b -- a`       | removes the top element of the stack                                                         |
| `print` | `a b -- a`       | print the element on top of the stack in a free form to stdout and remove it from the stack  |
| `over`  | `a b -- a b a`   | copy the element below the top of the stack                                                  |
| `rot`   | `a b c -- b c a` | rotate the top three elements on the stack                                                   |

#### Comparison

| Name | Signature                              | Description                                                  |
| ---  | ---                                    | ---                                                          |
| `= ` | `[a: int] [b: int] -- [a == b : bool]` | checks if two elements on top of the stack are equal         |
| `!=` | `[a: int] [b: int] -- [a != b : bool]` | checks if two elements on top of the stack are not equal     |
| `> ` | `[a: int] [b: int] -- [a > b  : bool]` | applies the greater comparison on top two elements           |
| `< ` | `[a: int] [b: int] -- [a < b  : bool]` | applies the less comparison on top two elements              |
| `>=` | `[a: int] [b: int] -- [a >= b : bool]` | applies the greater or equal comparison on top two elements  |
| `<=` | `[a: int] [b: int] -- [a <= b : bool]` | applies the greater or equal comparison on top two elements  |

#### Arithmetic

| Name     | Signature                                        | Description                                                                                                              |
| ---      | ---                                              | ---                                                                                                                      |
| `+`      | `[a: int] [b: int] -- [a + b: int]`              | sums up two elements on the top of the stack                                                                             |
| `-`      | `[a: int] [b: int] -- [a - b: int]`              | subtracts two elements on the top of the stack                                                                           |
| `*`      | `[a: int] [b: int] -- [a * b: int]`              | multiples two elements on top of the stack                                                                               |
| `divmod` | `[a: int] [b: int] -- [a / b: int] [a % b: int]` | perform [Euclidean division](https://en.wikipedia.org/wiki/Euclidean_division) between two elements on top of the stack  |

#### Bitwise

| Name  | Signature                            | Description                   |
| ---   | ---                                  | ---                           |
| `shr` | `[a: int] [b: int] -- [a >> b: int]` | right **unsigned** bit shift  |
| `shl` | `[a: int] [b: int] -- [a << b: int]` | light bit shift               |
| `or`  | `[a: int] [b: int] -- [a \| b: int]` | bit `or`                      |
| `and` | `[a: int] [b: int] -- [a & b: int]`  | bit `and`                     |
| `not` | `[a: int] -- [~a: int]`              | bit `not`                     |

#### Memory

| Name         | Signature                      | Description                                                                                     |
| ---          | ---                            | ---                                                                                             |
| `mem`        | `-- [mem: ptr]`                | pushes the address of the beginning of the memory where you can read and write onto the stack   |
| `!8`         | `[byte: int] [place: ptr] -- ` | store a given byte at the address on the stack                                                  |
| `@8`         | `[place: ptr] -- [byte: int]`  | load a byte from the address on the stack                                                       |
| `!16`        | `[place: int] [byte: ptr] --`  | store a 2-byte word at the address on the stack.                                               |
| `@16`        | `[place: ptr] [byte: int] --`  | load a 2-byte word from the address on the stack.                                               |
| `!32`        | `[place: int] [byte: ptr] --`  | store a 4-byte word at the address on the stack.                                               |
| `@32`        | `[place: ptr] [byte: int] --`  | load an 4-byte word from the address on the stack.                                               |
| `!64`        | `[place: int] [byte: ptr] --`  | store an 8-byte word at the address on the stack                                                |
| `@64`        | `[place: ptr] -- [byte: int]`  | load an 8-byte word from the address on the stack                                               |
| `cast(int)`  | `[a: any] -- [a: int]`         | cast the element on top of the stack to `int`                                                   |
| `cast(bool)` | `[a: any] -- [a: bool]`        | cast the element on top of the stack to `bool`                                                  |
| `cast(ptr)`  | `[a: any] -- [a: ptr]`         | cast the element on top of the stack to `ptr`                                                   |

#### System

- `syscall<n>` - perform a syscall with n arguments where n is in range `[0..6]`. (`syscall1`, `syscall2`, etc)
```
syscall_number = pop()
<move syscall_number to the corresponding register>
for i in range(n):
    arg = pop()
    <move arg to i-th register according to the call convention>
<perform the syscall>
```

#### Misc

- `here (-- [len: int] [str: ptr])` - pushes a string `"<file-path>:<row>:<col>"` where `<file-path>` is the path to the file where `here` is located, `<row>` is the row on which `here` is located and `<col>` is the column from which `here` starts. It is useful for reporting developer errors:

```pascal
include "std.porth"

here puts ": TODO: not implemented\n" puts 1 exit
```
- `argc (-- [argc: int])`
- `argv (-- [argv: ptr])`

### Control Flow

- `if <condition> do <then-branch> else <else-branch> end` - pops the element on top of the stack and if the element is not `0` executes the `<then-branch>`, otherwise `<else-branch>`.
- `while <condition> do <body> end` - keeps executing both `<condition>` and `<body>` until `<condition>` produces `0` at the top of the stack. Checking the result of the `<condition>` removes it from the stack.

### Macros

Define a new word `write` that expands into a sequence of tokens `stdout SYS_write syscall3` during the compilation.

```
macro write
    stdout SYS_write syscall3
end
```

### Include

Include tokens of file `file.porth`

```
include "file.porth"
```

### Type Checking

TBD

<!-- TODO: Document Type Checking process -->

---

## References
* TSoding's Porth: [GitLab](https://gitlab.com/tsoding/porth) 
* Graphviz: http://graphviz.org/
* TSoidin's SV.c library: https://github.com/tsoding/sv
