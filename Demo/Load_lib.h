#ifndef __LOAD_LIB_H__
#define __LOAD_LIB_H__

#ifdef __cplusplus
extern "C"{
#endif

#ifdef Win32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#define ERR_LOAD_LIBRARY        -1
#define ERR_GET_PROCADDRESS     -2

long func_long_loadLibrary(char *pch_library_path, void **pp_handle);

long func_long_getProcAddress(void *p_handle, char *pch_func_name, void **pp_func_add);

void func_void_freeLibrary(void *p_handle);

#ifdef __cplusplus
}
#endif

#endif // __LOAD_LIB_FOR_ALL_PLATFORM_H__


