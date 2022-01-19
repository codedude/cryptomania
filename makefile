!INCLUDE top.mh

#Targets

# .PHONY: test clean re

all: check_dirs libaes cliaes

libaes: check_dirs
    @echo Calling libaes...
    @$(NMAKE) /nologo /F $(LIBAES_DIR)\makefile
    @echo Libaes has been built!

libaes_clean:
    @$(NMAKE) /nologo /F $(LIBAES_DIR)\makefile clean

cliaes_clean:
    @$(NMAKE) /nologo /F $(CLIAES_DIR)\makefile clean

cliaes: check_dirs libaes
    @echo Calling cliaes...
    @$(NMAKE) /nologo /F $(CLIAES_DIR)\makefile
    @echo Cliaes has been built!

clean:
    @echo Cleaning...
    @$(NMAKE) /nologo /F $(LIBAES_DIR)\makefile clean
    @$(NMAKE) /nologo /F $(CLIAES_DIR)\makefile clean

re: clean all

check_dirs:
    @if not exist $(GEN_DIR) mkdir $(GEN_DIR)
    @if not exist $(BIN_DIR) mkdir $(BIN_DIR)

do_test:
    @cd test
    @Powershell.exe -File testSuite.ps1
    @Powershell.exe -File testNist.ps1
    @Powershell.exe -File testNistGcm.ps1

#============================< END OF FILE >===================================
