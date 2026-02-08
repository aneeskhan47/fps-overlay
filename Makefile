CXX      = g++
WINDRES  = windres
CXXFLAGS = -std=c++20 -O2 -Wall
LDFLAGS  = -static -mwindows -ld3d11 -ldxgi -ld3dcompiler -ldwmapi -lgdi32 -ladvapi32 -lole32 -loleaut32 -lwbemuuid -lpsapi -lversion

TARGET   = overlay.exe

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
RES_OBJ = src/resource.o

ALL_SRC = $(SRC) $(IMGUI_SRC)

all: $(TARGET)

$(RES_OBJ): $(RES_SRC)
	$(WINDRES) $(RES_SRC) -O coff -o $(RES_OBJ)

$(TARGET): $(ALL_SRC) $(RES_OBJ)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(ALL_SRC) $(RES_OBJ) -o $(TARGET) $(LDFLAGS)

clean:
	del /Q $(TARGET) src\resource.o 2>nul

.PHONY: all clean
