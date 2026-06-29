all: user_programs

user_programs:
	@echo "==== 编译 C 端底层探针 ===="
	$(MAKE) -C src/user

clean:
	@echo "==== 清理所有编译产物 ===="
	$(MAKE) -C src/user clean

.PHONY: all user_programs clean