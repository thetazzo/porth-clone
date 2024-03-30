# PORTH-clone

* A clone of TSoding Porth programming language
* Developed for education purposes
* It is supposed to be a stack-based language which is a clone of Forth

## Quick Start

```{bash}
$ ./porth.py sim ./examples/test.porth
$ ./porth.py cmp ./examples/test.porth
$ ./output
```

---

## Documentation

### Stack Manipulation

* `<integer` - push integer onto the stack. Here the integer is anything that is parsable by [int](https://docs.python.org/3/library/functions.html#int) function
```
push(<integer>)
```
* `dup` - duplicate an element on top of the stack
```
a = pop()
push(a)
push(a)
```
* `2dup` - duplicate top two elements of the stack 
```
a = pop()
b = pop()
push(a)
push(a)
push(b)
push(b)
```
* `dump` - print the element on top of the stack to *stdout* and remove it form the stack
```
a = pop()
print(a)
```

### Comparison
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

### Arithmetics
* `+` - sums the two elements that are on the top of the stack
```
a = pop()
b = pop()
push(a + b)
```
* `-` - subtracts the top element of the stack from the element below
```
a = pop()
b = pop()
push(b - a)
```

### Control Flow
* `if <then-branch> else <else-branch> end` - pops the element on top of the stack and if the element is not `0` the `<then-branch>` is executed, otherwise the `<else-branch>` executes
* `while <condition> do <body> end` - keeps executing both `<condition>` and `body` until `<condition>` results in `0` on top of the stack. Checking the result of the `<condition>` removes it from the stack

### Memory
* `mem` - pushes the address of the beggining of the memory where you can read and write onto the stack
* `.` - store the given byte at the given address 
```
byte = pop()
addr = pop()
store(addr, byte)
```
* `,` - load a byte from the given address 
```
addr = pop()
byte = load(addr)
push(byte)
```

### System
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

---

## References
* TSoding's Porth: [GitLab](https://gitlab.com/tsoding/porth) 
