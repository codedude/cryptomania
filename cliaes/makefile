!INCLUDE top.mh

L_BIN_DIR=$(BIN_DIR)\$(TARGET)

#Target
TARGET=cliaes
TARGET_EXT=exe
TARGET_BIN=$(L_BIN_DIR)\$(TARGET).$(TARGET_EXT)

SRC_DIR=$(CLIAES_DIR)\cliaes
GEN_DIR=$(GEN_DIR)\$(TARGET)


OBJ=\
    $(GEN_DIR)\main.obj\
    $(GEN_DIR)\loadData.obj\

DEP_H=\
    $(SRC_DIR)\loadData.hpp\
    $(SRC_DIR)\random_generator.hpp


#Include deps
BOOST_DIR=C:\Program^ Files\boost\boost_1_78_0
LIBAES_INC=$(BIN_DIR)\$(LIBAES_DIR)\include

INCLUDE_PATH=\
    $(INCLUDE_PATH)\
    /I"$(UTILITY_DIR)"\
    /I"$(CLIAES_DIR)"\
    /I"$(BOOST_DIR)"\
    /I"$(LIBAES_INC)"

LIBAES_PATH=$(BIN_DIR)\$(LIBAES_DIR)\libaes.lib

LIBS=\
    /libpath:"$(BOOST_DIR)"\stage\lib\
    $(LIBAES_PATH)

#Targets
all: check_dirs libaes_dep $(TARGET_BIN)

libaes_dep: $(LIBAES_PATH)

$(OBJ): $(DEP_H) makefile

$(TARGET_BIN): $(OBJ)
    @echo $(TARGET) - Linking...
    @set PATH=$(MSVC_BIN);$(WSDK_BIN);$(PATH)
    $(LD) $(LDOPT) /OUT:$(TARGET_BIN) $(LIB_PATH)\
        $(OBJ) $(LIBS)
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
