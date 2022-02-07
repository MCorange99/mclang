CC = gcc
CFLAGS = -c -std=c99
LDFLAGS = -g
SRC = ${wildcard src/*.c}
HDR = ${wildcard include/*.h}
OBJ = ${SRC:.c=.o}
EXEC = mclang

all: $(SRC) $(OBJ) $(EXEC)

$(EXEC): $(OBJ)
	$(CC) $(LDFLAGS) $^ -o $@
	chmod +x $(EXEC)

%.o: %.c $(HDR)
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f src/*.o $(EXEC)