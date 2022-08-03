# MClang


## if else

In MClang:

```forth
12 10 > if
    1 dump
else
    0 dump
end
```

In C:

```c
if (12 > 10){
    printf(1);
} else {
    printf(0);
}
```  
  
## while loops

In MClang:

```forth
10 
while dup 0 > do
    dup dump
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
    dup dump  // duplicate it and print it with dump
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
