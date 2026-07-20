.PHONY: all materialize build clean reproduce test

all: build

materialize:
	git submodule update --init tests/eval_suite/coreruleset
	./bench/benchmark_harness/materialize_runtime.sh

build: materialize
	cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
	cmake --build build --parallel

clean:
	rm -rf build

test: build
	python3 -m unittest discover -s tests/unit -p 'test_*.py'
	tools/verify_lumina_markers.py --source-root . --binary build/libluminawaf.so
	python3 tools/verify_release_tree.py --root .

reproduce:
	./bench/benchmark_harness/run.sh smoke
