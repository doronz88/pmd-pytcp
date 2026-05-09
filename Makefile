VENV := venv
ROOT_PATH:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
PYTCP_PATH := pytcp
NET_ADDR_PATH := net_addr
NET_PROTO_PATH := net_proto
EXAMPLES_PATH := examples
PYTCP_FILES := $(shell find ${PYTCP_PATH} -name '*.py')
NET_ADDR_FILES := $(shell find ${NET_ADDR_PATH} -name '*.py')
NET_PROTO_FILES := $(shell find ${NET_PROTO_PATH} -name '*.py')
EXAMPLES_FILES := $(shell find ${EXAMPLES_PATH} -name '*.py')
ROOT_FILES := tests_runner.py

$(VENV)/bin/activate: requirements.txt requirements_dev.txt
	@python3.14 -m venv $(VENV)
	@echo "export PYTHONPATH=$(ROOT_PATH)" >> venv/bin/activate
	@./$(VENV)/bin/python -m pip install --upgrade pip
	@./$(VENV)/bin/pip install -r requirements.txt
	@./$(VENV)/bin/pip install -r requirements_dev.txt

venv: $(VENV)/bin/activate

run: venv
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python3 examples/stack.py

run_tun: venv
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python3 examples/stack.py --interface tun7 --ip4-address 10.0.0.2/24

clean:
	@rm -rf $(VENV)
	@rm -rf dist tcp_ip_stack.egg-info PyTCP.egg-info
	@rm -rf .mypy_cache .pytest_cache .pyre
	@find . -type d -name '__pycache__' -exec rm -rf {} +

lint: venv
	@echo '<<< CODESPELL'
	@./$(VENV)/bin/codespell --write-changes ${PYTCP_FILES}
	@./$(VENV)/bin/codespell --write-changes ${NET_ADDR_FILES}
	@./$(VENV)/bin/codespell --write-changes ${NET_PROTO_FILES}
	@./$(VENV)/bin/codespell --write-changes ${EXAMPLES_FILES}
	@./$(VENV)/bin/codespell --write-changes ${ROOT_FILES}
	@echo '<<< ISORT'
	@./$(VENV)/bin/isort ${PYTCP_FILES}
	@./$(VENV)/bin/isort ${NET_ADDR_FILES}
	@./$(VENV)/bin/isort ${NET_PROTO_FILES}
	@./$(VENV)/bin/isort ${EXAMPLES_FILES}
	@./$(VENV)/bin/isort ${ROOT_FILES}
	@echo '<<< BLACK'
	@./$(VENV)/bin/black ${PYTCP_FILES}
	@./$(VENV)/bin/black ${NET_ADDR_FILES}
	@./$(VENV)/bin/black ${NET_PROTO_FILES}
	@./$(VENV)/bin/black ${EXAMPLES_FILES}
	@./$(VENV)/bin/black ${ROOT_FILES}
	@echo '<<< FLAKE8'
	@./$(VENV)/bin/flake8 ${PYTCP_FILES}
	@./$(VENV)/bin/flake8 ${NET_ADDR_FILES}
	@./$(VENV)/bin/flake8 ${NET_PROTO_FILES}
	@./$(VENV)/bin/flake8 ${EXAMPLES_FILES}
	@./$(VENV)/bin/flake8 ${ROOT_FILES}
	@echo '<<< MYPY'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/mypy -p ${PYTCP_PATH}
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/mypy -p ${NET_ADDR_PATH}
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/mypy -p ${NET_PROTO_PATH}
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/mypy -p ${EXAMPLES_PATH}
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/mypy ${ROOT_FILES}

test__pytcp__integration: venv
	@echo '<<< UNITTEST PYTCP INTEGRATION'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python tests_runner.py $(shell find 'pytcp/tests/integration' -name 'test__*.py')

test__net_addr__unit: venv
	@echo '<<< UNITTEST NET_ADDR UNIT'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python tests_runner.py $(shell find 'net_addr/tests/unit' -name 'test__*.py')

test__net_proto__unit: venv
	@echo '<<< UNITTEST NET_PROTO UNIT'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python tests_runner.py $(shell find 'net_proto/tests/unit' -name 'test__*.py')

test: venv
	@echo '<<< UNITTEST ALL'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python tests_runner.py $(shell find 'net_addr/tests' 'net_proto/tests' 'pytcp/tests' -name 'test__*.py')

validate: lint test

# RX-ring micro-benchmark — measures per-frame overhead of the
# 'select() + os.read() + queue.put()' loop. Run twice (once with
# '-O' to strip __debug__/asserts, once without) and compare.
bench__rx_ring: venv
	@echo '<<< RX-RING BENCH (default)'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python tools/bench_rx_ring.py
	@echo
	@echo '<<< RX-RING BENCH (-O, __debug__ + asserts stripped)'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python -O tools/bench_rx_ring.py

# Profile RX-ring under cProfile, dump top-25 cumulative-time
# entries. Use to find the actual hot spot before deciding whether
# item 5 (RX inner-drain loop) is worth implementing.
profile__rx_ring: venv
	@echo '<<< RX-RING PROFILE (-O)'
	@PYTHONPATH=$(ROOT_PATH) ./$(VENV)/bin/python -O -m cProfile \
		-o /tmp/pytcp_rx_ring.prof tools/bench_rx_ring.py \
		--frames 50000 --runs 1
	@./$(VENV)/bin/python -c "import pstats; \
		pstats.Stats('/tmp/pytcp_rx_ring.prof').strip_dirs(\
		).sort_stats('cumulative').print_stats(25)"

# Run the stack in benchmark mode: PYTHONOPTIMIZE=1 strips
# '__debug__'-gated logs / asserts on the hot path, and
# PYTCP_STATS_INTERVAL=5 prints ring + per-protocol counters
# every 5 seconds for live observability under load.
#
# Drive the stack from a SEPARATE terminal with one of the load
# generators below; this target is the receiver side.
benchmark: venv
	@echo 'PyTCP benchmark mode. Drive from another terminal:'
	@echo
	@echo '  sudo hping3 --flood --icmp -d 1472 <stack-ip>'
	@echo
	@PYTCP_STATS_INTERVAL=5 PYTHONOPTIMIZE=1 PYTHONPATH=$(ROOT_PATH) \
		./$(VENV)/bin/python3 examples/stack.py

bridge:
	@brctl addbr br0

install: venv
	@./$(VENV)/bin/pip install -e .

package: venv
	@./$(VENV)/bin/python -m build

dist: package

pypi: dist
	@./$(VENV)/bin/twine check dist/*
	@./$(VENV)/bin/twine upload dist/*

tun3:
	@ip tuntap add name tun3 mode tun
	@ip addr add 172.16.1.1/24 dev tun3
	@ip -6 addr add 2001:db8:1::1/64 dev tun3
	@ip link set dev tun3 up
	@echo 'Interface tun3 created and assigned 2001:db8:1::1/64 and 172.16.1.1/24 addresses.'

tun5:
	@ip tuntap add name tun5 mode tun
	@ip addr add 172.16.2.1/24 dev tun5
	@ip -6 addr add 2001:db8:2::1/64 dev tun5
	@ip link set dev tun5 up
	@echo 'Interface tun5 created and assigned 2001:db8:2::1/64 and 172.16.2.1/24 addresses.'

tap7:
	@ip tuntap add name tap7 mode tap
	@ip link set dev tap7 up
	@brctl addif br0 tap7
	@echo 'Interface tap7 created and added to bridge br0.'

tap9:
	@ip tuntap add name tap9 mode tap
	@ip link set dev tap9 up
	@brctl addif br0 tap9
	@echo 'Interface tap9 created and added to bridge br0.'

add_interfaces: tun3 tun5 tap7 tap9

remove_interfaces:
	@ip tuntap del name tun3 mode tun
	@ip tuntap del name tun5 mode tun
	@ip tuntap del name tap7 mode tap
	@ip tuntap del name tap9 mode tap

.PHONY: all venv run clean lint bridge tun3 tun5 tap7 tap9
