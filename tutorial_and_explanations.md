# Docs (I guess)

## Usefull things i forget a lot (lol)

store => . !
load => , @

## How it works

The stack is one big array
When you want to add 2 numbers and print it you do `5 2 + print`

Explanation in python:

```python
stack = []

stack.append(5) # push 5 on stack
stack.append(2) # push 5 on stack

# plus
a = stack.pop()
b = stack.pop()
stack.append(a + b)

# print
a = stack.pop()
print(a)

```

## Memory

Note: `loadN` is not compatible with `@N` since the `PTR` and `INT` arguments are swapped.

The `N` represents the memory size, 8 bit, 16 bit(TBD), 32 bit(TBD), 64 bit.

`!N` or `storeN`(defaults to 8 eg. `store`) Stores data to memory, needs

`@N` or `loadN` Loads data from memory, needs a `PTR` of the data you want to access

```forth
mem    //gives initial memory pointer
0 +    // increment the memory pointer (I add 0 which does nothing but its good practice)
59     // push the data you want to store to the stack
store

mem    // initial mem pointer
0 +    // increment mem pointer
load   // dereference pointer. pushes data to stack
print  // prints 59
```

or

```forth
59 // push the data you want to store to the stack
mem //gives initial memory pointer
0 + // increment the memory pointer (I add 0 which does nothing but its good practice)
!8

mem 0 + @8 print
```
