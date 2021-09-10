#pragma once
#include <string>
#include "def.h"

using namespace std;

class zip
{
public:
    zip(ArrayByte zip_data, size_t zip_data_len) { m_valid = zip_uncompress(zip_data, zip_data_len); }
    zip(string zip_file_path);
    string get_full_name() { return m_full_name; }
    string get_path() { return m_path; }
    string get_name() { return m_name; }
    string get_suffix() { return m_suffix; }
    bool is_valid() { return m_valid; }
    ArrayByte get_uncompress_data() { return m_valid ? m_data_before_compress : ""; }

private:
    void split_file_name(string file_name);
    bool zip_uncompress(ArrayByte zip_data, size_t zip_data_len);
    bool zip_decode_header(ArrayByte zip_dat, size_t zip_data_len);


    /*
    00: 50 4B 03 04 - �ļ�ͷ��ʶ
    04: 14 00       - ��ѹ�ļ���Ͱ汾
    06: 00 00       - ͨ�ñ���λ
    08: 08 00       - ѹ����ʽ
    10: 8A 51       - �ļ�����޸�ʱ��
    12: 1D 53       - �ļ�����޸�����
    14: 41 56 8C 6E - CRC32У��
    18: B6 02 00 00 - ѹ��ǰ��С
    22: B1 02 00 00 - ѹ�����С
    26: 1C 00       - �ļ�������
    28: 00 00       - ��չ������
    30: 66 73 72 6F 6F 74 2F 72 65 61 64 54 72 61 63 65 2F 72 65 61 64 54 72 61 63 65 2E 6D - �ļ���
    xx: 01 B1 02 4E FD - ѹ��ͷ
    xx: 56 31 4D 43 43 34 30 30 30 4D 45 43 31 30 30 30 4D 43 52 31 30 30 30 .. .. - ����
    */
    class zip_header
    {
    public:
#pragma pack(2)
        struct header
        {
            uint32_t  signature;
            uint16_t  version;
            uint16_t  flag;
            uint16_t  compress_method;
            uint16_t  last_mod_time;
            uint16_t  last_mod_date;
            uint32_t  crc32;
            uint32_t  compressed_size;
            uint32_t  uncompressed_size;
            uint16_t  file_name_len;
            uint16_t  extra_field_len;
        }m_header;
#pragma pack()
        string    m_file_name;
        ArrayByte m_extra_field;
        ArrayByte m_compress_data;

    }m_zip_header;
    ArrayByte m_data_before_compress;
    ArrayByte m_data_after_compress;
    string m_full_name;
    string m_path;
    string m_name;
    string m_suffix;
    bool m_valid;
    enum
    {
        ZIP_MAGIC_WORD = 0x04034B50
    };
};
