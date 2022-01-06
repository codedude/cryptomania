!INCLUDE top.mh

#Target
TARGET=crypto
TARGET_EXT=exe
TARGET_BIN=$(BUILD_DIR)\$(TARGET).$(TARGET_EXT)

SRC_DIR=src
INC_DIR=include

OBJ=\
    $(GEN_DIR)\main.obj\
    $(GEN_DIR)\types.obj\
    $(GEN_DIR)\loadData.obj\
    $(GEN_DIR)\aes_core.obj\
    $(GEN_DIR)\aes_mode.obj\
    $(GEN_DIR)\aes_lookups.obj\
    $(GEN_DIR)\aes_cipher.obj

DEP_H=\
    $(INC_DIR)\logs.hpp\
    $(INC_DIR)\types.hpp\
    $(INC_DIR)\loadData.hpp\
    $(INC_DIR)\random_generator.hpp\
    $(INC_DIR)\aes_core.hpp\
    $(INC_DIR)\aes_cipher.hpp


#Boost
BOOST_DIR=C:\Program^ Files\boost\boost_1_78_0

INCLUDE_PATH=\
    $(INCLUDE_PATH)\
    /I$(INC_DIR)\
    /I"$(BOOST_DIR)"

LIBS=\
    /libpath:"$(BOOST_DIR)"\stage\lib

#Targets
all: check_dirs $(TARGET_BIN)

$(OBJ): $(DEP_H) makefile

$(TARGET_BIN): $(OBJ)
    @echo Linking...
    @set PATH=$(MSVC_BIN);$(WSDK_BIN);$(PATH)
    $(LD) $(LDOPT) /OUT:$(TARGET_BIN) $(LIB_PATH)\
        $(OBJ) $(LIBS)
    @echo Done!

{$(SRC_DIR)}.cpp{$(GEN_DIR)}.obj::
    @echo Compiling...
    @set PATH=$(MSVC_BIN);$(WSDK_BIN);$(PATH)
    $(CXX) $(CLOPT) /Fo$(GEN_DIR)\ $(INCLUDE_PATH) $(CLDEF) $<

clean:
    @echo Cleaning...
    @if exist $(GEN_DIR) rmdir /S /Q $(GEN_DIR)
    @if exist $(TARGET_BIN) del /F /Q $(TARGET_BIN)
    @if exist $(BUILD_DIR)\$(TARGET).pdb del /F /Q $(BUILD_DIR)\$(TARGET).pdb

re: clean all

check_dirs:
    @if not exist $(GEN_DIR) mkdir $(GEN_DIR)
    @if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)

#============================< END OF FILE >===================================
