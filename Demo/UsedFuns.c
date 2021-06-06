#include <stdio.h>
#include <stdlib.h>
#include "./UsedFuns.h"


/*
����������ȡ�ļ����ݺʹ�С
���ܣ������ļ�·������ȡ�ļ������ݺʹ�С
������
    ���룺
        pch_file_path  �ļ�·��
        ulong_max_file_size ���ܴ򿪵�����ļ���С����λ(MByte)
    �����
        ppch_buff      �ļ�����buf
        pulong_size       �ļ�����buf��С
����ֵ��0:����  <0:error
*/
long  func_long_get_file_buf_and_size(const char *pch_file_path, char **ppch_buff, unsigned long *pulong_size)
{
    long long_ret = 0;
    unsigned long ulong_file_size = 0;
    char *pch_buff = NULL;
    FILE *fp = NULL;

    if(pch_file_path == NULL || ppch_buff == NULL || pulong_size == NULL)
    {
        long_ret = -1;
        goto finish;
    }
    //open file
    fp = fopen((char *)pch_file_path, "rb");
    if(fp == NULL)
    {
        long_ret = -2;
        goto finish;
    }
    //get file content and size
    fseek(fp , 0 , SEEK_END);
    ulong_file_size = (unsigned long)ftell(fp);
    if(ulong_file_size == 0)
    {
        long_ret = -3;
        goto finish;
    }
    else
    {
        rewind(fp);
        pch_buff = (char*) malloc (sizeof(char) * ulong_file_size);
        if (pch_buff == NULL)
        {
            long_ret = -5;
            goto finish;
        }
        else if(fread(pch_buff, 1, ulong_file_size, fp) != ulong_file_size)
        {
            long_ret = -6;
            goto finish;
        }
    }

    *ppch_buff = pch_buff;
    *pulong_size  = ulong_file_size;

finish:
    if(fp != NULL)
    {
        fclose(fp);
        fp = NULL;
    }
    if( long_ret != 0 )
    {
        if( pch_buff != NULL )
        {
            free(pch_buff);
            pch_buff = NULL;
        }
    }
    return long_ret;
}
