all: user_programs analysis_engine

user_programs:
	@echo "==== 编译 C 端底层探针 ===="
	$(MAKE) -C src/user

analysis_engine:
	@echo "==== 编译 C++ 分析引擎 ===="
	$(MAKE) -C src/analysis

clean:
	@echo "==== 清理所有编译产物 ===="
	$(MAKE) -C src/user clean
	$(MAKE) -C src/analysis clean
	rm -rf build/*

.PHONY: all user_programs analysis_engine clean