!INCLUDE top.mh

#Target
TARGET=crypto
TARGET_EXT=exe
TARGET_BIN=$(BUILD_DIR)\$(TARGET).$(TARGET_EXT)

OBJ=\
    $(GEN_DIR)\main.obj

DEP_H=

LIBS=

#Targets
all: check_dirs $(TARGET_BIN)

$(OBJ): $(DEP_H) makefile

$(TARGET_BIN): $(OBJ)
    @echo Linking...
    @set PATH=$(MSVC_BIN);$(WSDK_BIN);$(PATH)
    $(LD) $(LDOPT) /OUT:$(TARGET_BIN) $(LIB_PATH)\
        $(OBJ) $(LIBS)
    @echo Done!

{$(CODE_DIR)}.cpp{$(GEN_DIR)}.obj::
    @echo Compiling...
    @set PATH=$(MSVC_BIN);$(WSDK_BIN);$(PATH)
    $(CXX) $(CLOPT) /Fo$(GEN_DIR)\ $(INCLUDE_PATH) $(CLDEF) $<

clean:
    @echo Cleaning...
    @if exist $(GEN_DIR) rmdir /S /Q $(GEN_DIR)
    @if exist $(TARGET_BIN) del /F /Q $(TARGET_BIN)

re: clean all

check_dirs:
    @if not exist $(GEN_DIR) mkdir $(GEN_DIR)
    @if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)

#============================< END OF FILE >===================================
