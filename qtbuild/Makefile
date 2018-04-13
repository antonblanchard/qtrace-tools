%.qt: %.S
	$(CC) -c $<
	./qtbuild $(patsubst %.qt,%.o,$@) $@

