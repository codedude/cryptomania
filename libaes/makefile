!INCLUDE top.mh

L_BIN_DIR=$(BIN_DIR)\$(TARGET)

#Target
TARGET=libaes
TARGET_EXT=lib
TARGET_BIN=$(L_BIN_DIR)\$(TARGET).$(TARGET_EXT)

SRC_DIR=$(LIBAES_DIR)\libaes
GEN_DIR=$(GEN_DIR)\$(TARGET)

BIN_INCLUDE=$(L_BIN_DIR)\include\libaes

OBJ=\
    $(GEN_DIR)\types_helper.obj\
    $(GEN_DIR)\aes_core.obj\
    $(GEN_DIR)\aes_mode.obj\
    $(GEN_DIR)\aes_lookups.obj\
    $(GEN_DIR)\aes_cipher.obj

DEP_H=\
    $(SRC_DIR)\types.hpp\
    $(SRC_DIR)\types_helper.hpp\
    $(SRC_DIR)\libaes.hpp\
    $(SRC_DIR)\aes_cipher.hpp

INCLUDE_PATH=\
    $(INCLUDE_PATH)\
    /I"$(UTILITY_DIR)"\
    /I"$(LIBAES_DIR)"

LIBS=

#Targets
all: check_dirs $(TARGET_BIN)

$(OBJ): $(DEP_H) makefile

$(TARGET_BIN): $(OBJ)
    @echo $(TARGET) - Creating static library...
    @set PATH=$(MSVC_BIN);$(WSDK_BIN);$(PATH)
    $(AR) $(AROPT) /OUT:$(TARGET_BIN) $(OBJ)
    @if not exist $(BIN_INCLUDE) mkdir $(BIN_INCLUDE)
    @copy /v /y $(SRC_DIR)\libaes.hpp $(BIN_INCLUDE)\libaes.hpp
    @copy /v /y $(SRC_DIR)\types.hpp $(BIN_INCLUDE)\types.hpp
    @echo $(TARGET) - Done!

{$(SRC_DIR)}.cpp{$(GEN_DIR)}.obj::
    @echo $(TARGET) - Compiling...
    @set PATH=$(MSVC_BIN);$(WSDK_BIN);$(PATH)
    $(CXX) $(CLOPT) /Fo$(GEN_DIR)\ $(INCLUDE_PATH) $(CLDEF) $<

clean:
    @echo $(TARGET) - Cleaning...
    @if exist $(GEN_DIR) rmdir /S /Q $(GEN_DIR)
    @if exist $(L_BIN_DIR) rmdir /S /Q $(L_BIN_DIR)

re: clean all

check_dirs:
    @if not exist $(GEN_DIR) mkdir $(GEN_DIR)
    @if not exist $(L_BIN_DIR) mkdir $(L_BIN_DIR)

test: ;

#============================< END OF FILE >===================================
