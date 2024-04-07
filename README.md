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
* `<integer>` - push integer onto the stack. Here the integer is anything that is parsable by [int](https://docs.python.org/3/library/functions.html#int) function
```
push(<integer>)
```
* `<string>` - push size and address of the string literal onto the stack. A string literal is a sequence of characters enclosed with `"`
```
size = len(<string>)
push(n)
ptr = static_memory_alloc(n)
copy(ptr, <string>)
push(ptr)
```
* `<character>` - push a character as an integer onto the stack. For instance `'*'` would push `42` onto the stack since that is the character ascii code
```
value = ord(<character>)
push(value)
```

### Built-in Words

#### Stack Manipulation

* `dup` - duplicate an element on top of the stack
```
a = pop()
push(a)
push(a)
```
* `swap` - swaps top 2 elements on the stack
```
a = pop();
b = pop();
push(a);
push(b);
```
* `over` - copy the below element over the top element
```
a = pop()
b = pop()
push(b)
push(a)
push(b)
```
* `drop` - remove the top element on the stack
```
pop()
```
* `print` - print the element on top of the stack to *stdout* and remove it form the stack
```
a = pop()
print(a)
```

* `rot` - rotate top 3 elements on the stack
```
a = pop()
b = pop()
c = pop()
push(b)
push(a)
push(c)
```

#### Comparison
* `=` - checks if the two elements on top of the stack are equal. Removes the elements from the stack and pushes `1` if they are equal or `0` if they are not
```
a = pop()
b = pop()
push(int(a == b))
```
* `>` - checks if the element below the top is greater than the top
```
a = pop()
b = pop()
push(int(a > b));
```
* `<` - checks if the element below the top is smaller than the top
```
a = pop()
b = pop()
push(int(a < b));
```

#### Arithmetics
* `+` - sums the two elements that are on the top on the stack
```
a = pop()
b = pop()
push(a + b)
```
* `-` - subtracts the top element on the stack from the element below the top
```
a = pop()
b = pop()
push(b - a)
```
* `*` - multiplies the top element on the stack with the one below the top
```
a = pop()
b = pop()
push(a * b)
```
* `divmod`
```
a = pop()
b = pop()
push(b // a)
push(b % a)
```

#### Bitwise operations
* `shr` - 
```
a = pop()
b = pop()
push(b >> a)
```
* `shl` -
```
a = pop()
b = pop()
push(b << a)
```
* `or` -
```
a = pop()
b = pop()
push(b | a)
```
* `and` -
```
a = pop()
b = pop()
push(b & a)
```
* `not` -
```
a = pop()
push(~a)
```

#### Control Flow
* `if <then-branch> else <else-branch> end` - pops the element on top of the stack and if the element is not `0` the `<then-branch>` is executed, otherwise the `<else-branch>` executes
* `while <condition> do <body> end` - keeps executing both `<condition>` and `body` until `<condition>` results in `0` on top of the stack. Checking the result of the `<condition>` removes it from the stack

#### Memory
* `mem` - pushes the address of the beggining of the memory where you can read and write onto the stack
* `.` - store the given byte at the given address on the stack
```
byte = pop()
addr = pop()
store(addr, byte)
```
* `,` - load a byte from the given address on the stack
```
addr = pop()
byte = load(addr)
push(byte)
```
* `.64` - store an 8-byte word at the given address on the stack
```
word = pop()
addr = pop()
store(addr, byte)
```
* `,64` - load an 8-byte word from the given address on the stack
```
word = pop()
byte = load(word)
push(byte)
```

#### System
* `syscall1` - perform a syscall with 1 argument
```
syscall_number = pop()
for i in range(1):
    arg = pop()
    <move arg to i-th register according to the call convention>
<perform the syscall>
```
* `syscall3` - perform a syscall with 3 arguments
```
syscall_number = pop()
for i in range(3):
    arg = pop()
    <move arg to i-th register according to the call convention>
<perform the syscall>
```

### Macros

* Define a new word `write` that expands into a sequence of tokens `1 1 syscall3` during the compilation
```
macro write 
    1 1 syscall3
end
```

### Include
* Include tokes form anothe `.porth` file by using the `include <file_path>`, where `<file_path>` is a string literal of the relative path to the included file
```
include "std.porth"
```

### Misc

* `here` - a string `"<file-path>:<row>:<col>"` is pushed onto the stack. Where `<file-path>` is the path to the file where `here` is located, `<row>` is the row on which `here` is located and `col` is the colum on which `here` is starts. Useful for reporting developer errors
```pascal
include "std.porth"

here puts ": TODO: not impmeneted\n" puts 1 exit

---

## References
* TSoding's Porth: [GitLab](https://gitlab.com/tsoding/porth) 
