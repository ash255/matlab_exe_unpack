#include "zip.h"
#include "zinflate.h"
#include "files.h"
#include "filter.h"

#pragma comment(lib, "cryptlib.lib")

using namespace CryptoPP;
using namespace std;


zip::zip(string zip_file_path) :m_full_name(zip_file_path)
{
    ArrayByte file_data;
    FileSource(zip_file_path.c_str(), true, new StringSink(file_data));
    m_valid = zip_uncompress(file_data, file_data.length());
}

bool zip::zip_uncompress(ArrayByte zip_data, size_t zip_data_len)
{
    if (zip_decode_header(zip_data, zip_data_len) == false)
    {
        cout << "zip_uncompress: zip_decode_header failed\n" << endl;
        return false;
    }

    m_data_after_compress = m_zip_header.m_compress_data;
    try
    {
        StringSource(m_data_after_compress, true, new Inflator(new StringSink(m_data_before_compress)));
    }
    catch(...)
    {
        cout << "zip_uncompress: uncompress failed\n" << endl;
        return false;
    }
    
    return true;
}

bool zip::zip_decode_header(ArrayByte zip_data, size_t zip_data_len)
{
    zip_header header;

    if (zip_data_len < sizeof(zip_header::header))
    {
        return false;
    }
    memcpy(&header.m_header, zip_data.c_str(), sizeof(zip_header::header));
    if (header.m_header.signature != ZIP_MAGIC_WORD)
    {
        return false;
    }
    //skip much check
    if (zip_data_len < (sizeof(zip_header::header) + header.m_header.compressed_size + header.m_header.extra_field_len + header.m_header.file_name_len))
    {
        return false;
    }

    if (header.m_header.file_name_len > 0)
    {
        header.m_file_name = zip_data.substr(sizeof(zip_header::header), header.m_header.file_name_len);
    }
    if (header.m_header.extra_field_len > 0)
    {
        header.m_extra_field = zip_data.substr(sizeof(zip_header::header) + header.m_header.file_name_len, header.m_header.extra_field_len);
    }
    if (header.m_header.compressed_size > 0)
    {
        header.m_compress_data = zip_data.substr(
            sizeof(zip_header::header) + header.m_header.file_name_len + header.m_header.extra_field_len,
            header.m_header.compressed_size);
    }

    split_file_name(header.m_file_name);
    m_zip_header = header;
    return true;
}

void zip::split_file_name(string file_name)
{
    size_t pos_1, pos_2;

    pos_1 = file_name.find_last_of('/');
    pos_2 = file_name.find_last_of('.');

    m_path = file_name.substr(0, pos_1 + 1);
    m_name = file_name.substr(pos_1 + 1, pos_2 - pos_1 - 1);
    m_suffix = file_name.substr(pos_2 + 1);
}
