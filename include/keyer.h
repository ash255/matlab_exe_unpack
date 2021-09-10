#pragma once
#include "def.h"
#include <string.h>
#include <windows.h>

using namespace std;

typedef char*(__fastcall* get_matlab_key_func)();

class matlab_key
{
public:
    /* matlab key stored in mclmcr.dll 
       I am lazy, so I call one function to get matlab key
    */
    matlab_key(string file);
    ~matlab_key() { if (m_handle) { FreeLibrary(m_handle); } };
    string get_matlab_key() { return m_matlab_key; }
    string get_toolbox_key() { return m_toolbox_key; }

private:
    HMODULE m_handle;
    string m_matlab_key;
    string m_toolbox_key;
    static const string m_magic_word_1;  //mov     ecx, 4F3h
    static const string m_magic_word_2;  //ret
    static const string m_magic_word_3;  //mov     r8d, 100h, call

    get_matlab_key_func m_get_matlab_key_func;
};


