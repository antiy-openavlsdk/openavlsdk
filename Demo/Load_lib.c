#include <stdio.h>
#include "Load_lib.h"


#ifdef Win32
    long func_long_loadLibrary(char *pch_library_path, void **pp_handle)
    {
        long long_ret = 0;
        HMODULE p_handle = NULL;

        if( pch_library_path == NULL || pp_handle == NULL )
        {
            long_ret = -1;
            goto finish;
        }
        p_handle = LoadLibrary(pch_library_path);
        if( p_handle == NULL )
        {
            long_ret = ERR_LOAD_LIBRARY;
            goto finish;
        }

        *pp_handle = p_handle;

    finish:
        return long_ret;
    }
    long func_long_getProcAddress(void *p_handle, char *pch_func_name, void **pp_func_add)
    {
        long long_ret = 0;
        void *p_func_add = NULL;

        if( p_handle == NULL || pch_func_name == NULL || pp_func_add == NULL )
        {
            long_ret = -1;
            goto finish;
        }

        p_func_add	=	GetProcAddress( (HMODULE)p_handle, pch_func_name );
        if( p_func_add == NULL )
        {
            long_ret = ERR_GET_PROCADDRESS;
            goto finish;
        }

        *pp_func_add = p_func_add;

    finish:
        if( long_ret < 0 )
        {
            printf("==>%s\n", pch_func_name);
        }
        return long_ret;
    }
    void func_void_freeLibrary(void *p_handle)
    {
        if( p_handle != NULL )
        {
            FreeLibrary( (HMODULE)p_handle );
            p_handle = NULL;
        }
    }
#else
    long func_long_loadLibrary(char *pch_library_path, void **pp_handle)
    {
        long long_ret = 0;
        void *p_handle = NULL;

        if( pch_library_path == NULL || pp_handle == NULL )
        {
            long_ret = -1;
            goto finish;
        }
        p_handle = dlopen(pch_library_path, RTLD_LAZY);
        if( p_handle == NULL )
        {
            long_ret = ERR_LOAD_LIBRARY;
            goto finish;
        }

        *pp_handle = p_handle;

    finish:
        return long_ret;
    }
    long func_long_getProcAddress(void *p_handle, char *pch_func_name, void **pp_func_add)
    {
        long long_ret = 0;
        void *p_func_add = NULL;

        if( p_handle == NULL || pch_func_name == NULL || pp_func_add == NULL )
        {
            long_ret = -1;
            goto finish;
        }

        p_func_add	=	dlsym(p_handle, pch_func_name);
        if( p_func_add == NULL )
        {
            long_ret = ERR_GET_PROCADDRESS;
            goto finish;
        }

        *pp_func_add = p_func_add;

    finish:
        return long_ret;
    }
    void func_void_freeLibrary(void *p_handle)
    {
        if( p_handle != NULL )
        {
            dlclose( p_handle );
            p_handle = NULL;
        }
    }
#endif // Win32


