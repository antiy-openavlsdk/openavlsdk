TARGET_NAME = AVLScanner
#OUTPUT_PATH = ./bin/
OUTPUT_PATH =./
export CC = gcc
export CXX = g++
export LINKER = gcc
export CFLAGS = -c -Wall

LFLAGS = 
STRIP = strip
APPEND = 

T_WINDIR = $(shell echo $(WINDIR) | tr a-z A-Z)

ifneq ($(T_WINDIR), C:WINDOWS)
	PAGE_ALIGN = $(shell getconf PAGE_SIZE)
else
	PAGE_ALIGN = 0x1000
endif

ifeq ($(platform), cavium)
	CC = mips64-octeon-linux-gnu-gcc
	CXX = mips64-octeon-linux-gnu-g++
	LINKER = mips64-octeon-linux-gnu-gcc
	STRIP = mips64-octeon-linux-gnu-strip
endif

ifneq ($(T_WINDIR), C:WINDOWS)
	LFLAGS += -Xlinker -zmax-page-size=$(PAGE_ALIGN)
    #APPEND += -ldl -lm
    APPEND += -ldl -lpthread
	CFLAGS += -fPIC
else
    APPEND += -lshlwapi
    CFLAGS += -DWin32
endif

ifeq ($(debug), yes)
	CFLAGS += -g3
else
	CFLAGS += -O2
endif

OBJS = $(patsubst %.c, %.o, $(shell find . -name "*.c"))

all : obj

obj : $(OBJS)
	$(LINKER) $(LFLAGS) -o $(OUTPUT_PATH)$(TARGET_NAME) $(OBJS) $(APPEND)

strip:
	$(STRIP) -s $(OUTPUT_PATH)$(TARGET_NAME)

%.o : %.c %.cpp
	$(CC) $(CFLAGS) $(<) -o $(@)
    
clean:
	rm -rf $(OBJS)
	rm -rf $(OUTPUT_PATH)$(TARGET_NAME)

