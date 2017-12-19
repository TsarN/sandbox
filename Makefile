libsandbox.a: sandbox.o
	$(AR) rcs $@ $^

sandbox.o: sandbox_linux.c
	$(CC) -c $< -o $@

clean:
	rm -f sandbox.o libsandbox.a
