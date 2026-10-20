CXX = g++
CXXFLAGS = -O2 -std=c++17 -Wall -Wextra
LDFLAGS = -lhiredis -lz

TARGET = trace_engine
SRCS = trace.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	@echo "[MAKE] 正在编译 C++ 分析引擎..."
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)
	@echo "[MAKE] 编译成功！请使用 ./$(TARGET) 运行。"

clean:
	@echo "[MAKE] 清理构建文件..."
	rm -f $(TARGET)

.PHONY: all clean