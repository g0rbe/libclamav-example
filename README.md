# libclamav-example

## Compile

```
gcc main.c -lclamav -ggdb
```

## Valgrind

```
valgrind --leak-check=full --track-origins=yes --show-leak-kinds=all -s ./a.out
```