# Hello world

Note: All source code will be available in the same folder that the md file is in.

## The code

```pascal
include "std.mcl"

"Henlo, world!\n" puts
```

## Explanation

### The stack

The stack is a simple array, Thats it.

Example program:

```pascal
//stack = []

10    // stack.push(10)

5     // stack.push(5)

+     // a = stack.pop()
      // b = stack.pop()
      // stack.push(a + b)

print // a = stack.pop()
      // println(a)

```

Its that simple, for a better explanation of the stack and the various operations on it look at [The stack](TBD)

### Include

Including files is simple with `include`
It works like a macro evaluating in compile time like the imported file was in the main file the whole time.

### String literals

There are 2 types of strings: CStrings and PStrings

PStrings look like this:

```pascal
"Hello there\n"
```

They push 2 things on the stack The string length and string pointer.

CStrings Look like this:

```pascal
"Hello there\n"c
//             ^
//             | Notice the 'c'
```

It only pushes 1 thing on the stack, the pointer

CStrings are NULL/0 terminated which means they have a `0` byte at the end of the string.

### Printing strings

The `puts` macro (put-string) prints PStrings into stdout.  
The `eputs` macro (error-put-string) prints PStrings into stderr.  
The `putd` macro (put-decimal) prints Numbers into stdout.

You can convert a CString to a PString with `cstr-to-str`
