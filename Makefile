.PHONY: all build clean reproduce test

all: build

build:
	mkdir -p build
	cd build && cmake ..
	$(MAKE) -C build

clean:
	rm -rf build

test: build
	./build/parity_test -runs=10000
	./build/micro_bench

reproduce:
	chmod +x ./run_all_benchmarks.sh
	./run_all_benchmarks.sh
