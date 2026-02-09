CXX      = g++
WINDRES  = windres
CXXFLAGS = -std=c++20 -O2 -Wall
LDFLAGS  = -static -mwindows -ld3d11 -ldxgi -ld3dcompiler -ldwmapi -lgdi32 -ladvapi32 -lole32 -loleaut32 -lwbemuuid -lpsapi -lversion

# Build output directory
BUILD_DIR = build
TARGET    = $(BUILD_DIR)/overlay.exe

# Include paths
IMGUI_DIR = libs/imgui
INCLUDES  = -I$(IMGUI_DIR) -I$(IMGUI_DIR)/backends

# Source files
SRC = src/main.cpp

IMGUI_SRC = $(IMGUI_DIR)/imgui.cpp \
            $(IMGUI_DIR)/imgui_draw.cpp \
            $(IMGUI_DIR)/imgui_tables.cpp \
            $(IMGUI_DIR)/imgui_widgets.cpp \
            $(IMGUI_DIR)/backends/imgui_impl_dx11.cpp \
            $(IMGUI_DIR)/backends/imgui_impl_win32.cpp

# Resource file (icon)
RES_SRC = src/resource.rc
RES_OBJ = $(BUILD_DIR)/resource.o

ALL_SRC = $(SRC) $(IMGUI_SRC)

all: $(BUILD_DIR) $(TARGET)

$(BUILD_DIR):
	@if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)

$(RES_OBJ): $(RES_SRC) | $(BUILD_DIR)
	$(WINDRES) $(RES_SRC) -O coff -o $(RES_OBJ)

$(TARGET): $(ALL_SRC) $(RES_OBJ)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(ALL_SRC) $(RES_OBJ) -o $(TARGET) $(LDFLAGS)

clean:
	@if exist $(BUILD_DIR) rmdir /S /Q $(BUILD_DIR)

.PHONY: all clean
