# MClang

## Examples

### [Hello world](./examples/hello-world.mcl)

```forth
include "std.mcl"

"Henlo, World!" puts
```

### Rule 110

A simplified version of game of life that proves that a language is turing complete  

Its too big to fit in the readme but you can check it out [here](./examples/rule-110.mcl)

## if else

In MClang:

```forth
include "std.mcl"

12 10 > if
    "True\n" puts
else 
    "False\n" puts
end
```

In C:

```c
if (12 > 10){
    printf("True\n");
} else {
    printf("False\n");
}
```  
  
## while loops

In MClang:

```forth
10 
while dup 0 > do
    dup print // print only prints the last thing on the stack so you cant print whole strings
    1 -
end
```

in c:

```c
int i = 10
while (i > 0) {
    printf(i)
    i--
}
```

output:

```bash
10
9
8
7
6
5
4
3
2
1
```

Explanation:

```forth
10            // push 10 on stack
while dup     // duplicate it with dup so it doesnt dissapear from stack 
0 > do        // check if its bigger than 0
    dup print  // duplicate it and print it with dump
    1 -       // decrement it with -
end
```

## Memory

Push to memory with address 0 the number 97 (`a` in ascii)

```forth
mem 0 + 97 store
```

`mem`   load the whole memory   
`0 +`   select the memory address  
`97`    push `97` to stack  
`store` store the value on the top of the stack to the selected memory address  
  
Read memory with address 3 and print it:

```forth
mem 3 + load dump
```

`mem`   load the whole memory  
`3 +`   select the memory address  
`load`  push the value to the stack from memmory on address 3  
`dump`  print the the value on the top of the stack
