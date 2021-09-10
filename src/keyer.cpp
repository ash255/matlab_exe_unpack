#include "files.h"
#include "hex.h"
#include "keyer.h"

#pragma comment(lib, "cryptlib.lib")
using namespace std;
using namespace CryptoPP;

const string matlab_key::m_magic_word_1 = string("\xB9\xF3\x04\x00\x00", 5);
const string matlab_key::m_magic_word_2 = string("\xC3", 1);
const string matlab_key::m_magic_word_3 = string("\x41\xB8\x00\x01\x00\x00\xFF", 7);


matlab_key::matlab_key(string file)
{
    m_handle = LoadLibrary(file.c_str());
    if (m_handle != 0)
    {
        string dll_data, dll_data2;
        FileSource(file.c_str(), true, new StringSink(dll_data));
        dll_data2 = string((char*)m_handle, dll_data.length());
        size_t pos = dll_data2.find(m_magic_word_1);
        if (pos != string::npos)
        {
            pos = dll_data2.rfind(m_magic_word_2, pos);
            if (pos != string::npos)
            {
                m_get_matlab_key_func = (get_matlab_key_func)((char*)m_handle + pos + 1);
                char *matlab_key_str = m_get_matlab_key_func();
                m_matlab_key = string(matlab_key_str);
            }
        }
       
        HMODULE dll = GetModuleHandle("ctfrtcrypto.dll");
        //search ctfrtcrypto.dll in 1.5MB size
        dll_data2 = string((char*)dll, 1572864);
        pos = dll_data2.find(m_magic_word_3);
        if (pos != string::npos)
        {
            pos -= 11;
            int offset = (dll_data2[pos] & 0xFF) | ((dll_data2[pos + 1]&0xFF) << 8) | ((dll_data2[pos + 2]&0xFF) << 16) | ((dll_data2[pos + 3]&0xFF) << 24);
            char *toolbox_key_str = (char*)dll + pos + offset + 4;
            m_toolbox_key = string(toolbox_key_str, 256);
        }

        CloseHandle(m_handle);
        m_handle = 0;
    }else
    {
        cout << "error code: " << GetLastError() << endl;
    }
}

#if 0
int main()
{
    SetCurrentDirectory("H:\\software\\matlab\\bin\\win64\\");
    matlab_key mk("H:\\software\\matlab\\bin\\win64\\mclmcr.dll");
    cout << "matlab key: " << mk.get_matlab_key() << endl << endl;
    cout << "toolbox key: " << mk.get_toolbox_key() << endl << endl;

    return 1;
}

#endif
