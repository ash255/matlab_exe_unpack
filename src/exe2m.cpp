#include "rsa.h"
#include "oaep.h"
#include "sha.h"
#include "files.h"
#include "hex.h"
#include "modes.h"
#include "aes.h"
#include "filters.h"
#include "osrng.h"
#include "zlib.h"
#include "zip.h"
#include "def.h"

#pragma comment(lib, "cryptlib.lib")

using namespace std;
using namespace CryptoPP;

static const string ZIP_MAGIC_WORD = "\x50\x4B\x03\x04";
static string solution_key = "";
static string compiler_key = "";
static string matlab_key = "30820275020100300D06092A864886F70D01010105000482025F3082025B02010002818100C49CAC34ED13A520658F6F8E0138C4315B4315277ED3F7DAE53099DB08EE589F804D4B981326A52CCE4382E9F2B4D085EB950C7AB12EDE2D41297820E6377A5FEB5689D4E6032F60C43074A04C26AB72F54B51BB460578785B199014314A65F090B61FC20169453B58FC8BA43E6776EB7ECD3178B56AB0FA06DD64967CB149E502011102818002E42FB57BF4FEA9E3603A1C70F58A6A2339750458740EF06540B6F7ED4ECC98EF10320D87CFA08BF3F976A18EDD0311073AA998647CECADD78BE769E544949F809D1802102584E73824ED0BDDF2615E92EFBE59AF0BBF51312368CAE0C4335954C4F04EDE2B2BD74502F1C493BBB1F07278CC15CBD6DB477CF30855D548D0F9024100D280261FE351800E3AFE76E6DF30FF56640BC338B8B5608B9446CD0C68BD71609C491B3EB741F16606A0D26527954B57DEFA3AD30CAA6E6BEC05092B3CD1B72D024100EF1C0328B8BA61E79F6306927893CEFD8990FEB00E31465BB96AED24146F50D5701D2F9046AFAEA6FD938107D8F6E7B537BCC0DB83AE0390EA4A249E98881099024100B9BC5DDFE6B152DF613AE1624C7686F1DFCE24B993EB552FDD2F69A1899818BEA804453756675C8733065F4A31FC336BA6A08E41BFE1ACB99404718080F54745024100D2FA99602A865662F60C14DB97917A673D25956E2AA3F2C9675E58C57B714752EA741AE8B6D73FC085640870560708AEF4F1D7584702F416745F89B91D2CC35902401FC8C791E3EFEA82763D38163EDFC4A1C5BF762D39F4CF077EC5785A80960A27EA8658EBE049421B741612324A57CFE880EE5AC92B11080623D4DDE1F6FD3CC7";
static string toolbox_key = "35668C564C9BD12CA842B902206828699C7B48E51E9F695DABBC6CCE614DBF159F724C683A28B80C365EBEB7FFD0E5BE0A144C12EA43CAED9FC1977014FE7A558A31710EB36A8ED5259B07247BC1032D94F5BC921F72DD3057146F88AFF69A7D4700F08F4CB559F00F13E62432F1EBC5CA5B745D88E871F6695CD31BCFFD5053";

const int GLOBAL_SEED_LENGTH = 32;
static string s_globalSeed;
static OFB_Mode<AES>::Encryption s_globalRNG;
RandomNumberGenerator & GlobalRNG()
{
    return dynamic_cast<RandomNumberGenerator&>(s_globalRNG);
}

string sym_key_dec(string matlab_key, string solution_key)
{
    StringSource privFile(matlab_key, true, new HexDecoder);
    RSAES_OAEP_SHA_Decryptor priv(privFile);

    std::string result;
    StringSource(solution_key, true, new HexDecoder(new PK_DecryptorFilter(GlobalRNG(), priv, new StringSink(result))));

    return result;
}

string aes_key_dec(string sym_key)
{
    SHA256 sha256;
    string result;

    StringSource(sym_key, true, new HashFilter(sha256, new HexEncoder(new StringSink(result))));

    return result;
}

bool hmac_check(string data, string aes_key)
{
    string aes_key_hex, data_without_hmac, hmac_v1, hmac_v2;

    if (data.length() < 20)
    {
        throw exception("[CALC_IV]: data length < 8\n");
    }
    StringSource(aes_key, true, new HexDecoder(new StringSink(aes_key_hex)));
    data_without_hmac = data.substr(0, data.length() - 20);
    StringSource(data.substr(data.length() - 20, 20), true, new HexEncoder(new StringSink(hmac_v1)));
    
    HMAC<SHA1> hmac_sha1((const byte *)aes_key_hex.c_str(), aes_key_hex.length());
    
    StringSource(data_without_hmac, true, new HashFilter(hmac_sha1, new HexEncoder(new StringSink(hmac_v2))));

    //cout << "hmac_v1: " << hmac_v1 << endl;
    //cout << "hmac_v2: " << hmac_v2 << endl;
    if (hmac_v1.compare(hmac_v2) == 0)
    {
        return true;
    }
    else
    {
        return false;
    }
}

string calc_iv(string data)
{
    int i;
    SHA256 sha256;
    string iv_data, iv;
    ArrayByte sha256_result;

    if (data.length() < 8)
    {
        throw exception("[CALC_IV]: data length < 8\n");
    }
    iv_data = data.substr(data.length() - 8 - 20, 8);

    StringSource(iv_data, true, new HashFilter(sha256, new StringSink(sha256_result)));

    if (sha256_result.length() != 32)
    {
        throw exception("[CALC_IV]: sha256_result length != 32\n");
    }

    for (i = 0; i < 16; i++)
    {
        sha256_result[i] ^= sha256_result[i + 16];
    }
    StringSource((const byte*)sha256_result.c_str(), 16, true, new HexEncoder(new StringSink(iv)));
    return iv;
}

ArrayByte aes_dec(string key, string iv, string data)
{
    string result, aes_data, hex_key, hex_iv;
    aes_data = data.substr(0, data.length()-28);

    StringSource(key, true, new HexDecoder(new StringSink(hex_key)));
    StringSource(iv, true, new HexDecoder(new StringSink(hex_iv)));
    CFB_Mode<AES>::Decryption aes((const byte*)hex_key.c_str(), hex_key.length(), (const byte*)hex_iv.c_str());
    StringSource(aes_data, true, new StreamTransformationFilter(aes, new StringSink(result)));

    //int i;
    //for (i = 0; i < result.length(); i++)
    //{
    //    printf("%02X ", (unsigned char)result[i]);
    //    if (i % 16 == 15)
    //    {
    //        printf("\n");
    //    }
    //}
    //cout << "len: " << result.length() << endl;
    
    return result;
}

ArrayByte data_dec(string aes_key, string data)
{
    string iv;
    iv = calc_iv(data);
    //cout << "aes key: " << aes_key << endl;
    //cout << "iv: " << iv << endl;
    return aes_dec(aes_key, iv, data);
}

int exe2m_main(ArrayByte mfile_data, string output_file)
{
    /********** init **********/
    s_globalSeed = IntToString(time(NULL));
    s_globalSeed.resize(GLOBAL_SEED_LENGTH, ' ');
    SymmetricCipher& cipher = dynamic_cast<SymmetricCipher&>(GlobalRNG());
    cipher.SetKeyWithIV((byte *)s_globalSeed.data(), s_globalSeed.size(), (byte *)s_globalSeed.data());
    /********** init end **********/

    string sym_key_from_solution, sym_key_from_toolbox;
    sym_key_from_solution = sym_key_dec(matlab_key, solution_key);
    sym_key_from_toolbox = sym_key_dec(matlab_key, toolbox_key);
    //cout << "sym_key_from_solution: " << sym_key_from_solution << endl;
    //cout << "sym_key_from_toolbox:  " << sym_key_from_toolbox << endl;

    string aes_key_from_solution, aes_key_from_toolbox;
    aes_key_from_solution = aes_key_dec(sym_key_from_solution);
    aes_key_from_toolbox = aes_key_dec(sym_key_from_toolbox);
    //cout << "aes_key_from_solution: " << aes_key_from_solution << endl;
    //cout << "aes_key_from_toolbox:  " << aes_key_from_toolbox << endl;

    string file = mfile_data;
    //FileSource("C:\\Users\\NT035\\Desktop\\readTrace.m", true, new StringSink(file));
    //cout << "file size: " << file.length() << endl;

    string file_header, file_body_1, file_body_2;
    file_header = file.substr(0, 23);
    if (file_header.compare("V1MCC4000MEC1000MCR1000") != 0)
    {
        cout << "file header invailed" << endl;
        return 0;
    }
    int file_body_1_size = *(int*)file.substr(23, 4).c_str();
    //cout << "file_body_1_size: " << file_body_1_size << endl;
    file_body_1 = file.substr(27, file_body_1_size);
    file_body_2 = file.substr(27 + file_body_1_size);

    ArrayByte file_body_dec_1, file_body_dec_2;
    /* body1 used to check file expired
    body2 used to get plain text */
    if (hmac_check(file_body_1, aes_key_from_solution))
    {
        //cout << "file_body_1: use solution key" << endl;
        file_body_dec_1 = data_dec(aes_key_from_solution, file_body_1);
    }
    else if (hmac_check(file_body_1, aes_key_from_toolbox))
    {
        //cout << "file_body_1: use toolbox key" << endl;
        file_body_dec_1 = data_dec(aes_key_from_toolbox, file_body_1);
    }
    else
    {
        throw exception("no match key for file_body_1\n");
    }
    //StringSource(file_body_dec_1, true, new HexEncoder(new FileSink(cout)));
    //cout << endl;

    if (hmac_check(file_body_2, aes_key_from_solution))
    {
        //cout << "file_body_2: use solution key" << endl;
        file_body_dec_2 = data_dec(aes_key_from_solution, file_body_2);
    }
    else if (hmac_check(file_body_2, aes_key_from_toolbox))
    {
        //cout << "file_body_2: use toolbox key" << endl;
        file_body_dec_2 = data_dec(aes_key_from_toolbox, file_body_2);
    }
    else
    {
        throw exception("no match key for file_body_2\n");
    }
    //StringSource(file_body_dec_2, true, new HexEncoder(new FileSink(cout)));
    //cout << endl;

    string file_body_compress_data, file_body_uncompress_data;
    file_body_compress_data = file_body_dec_2.substr((file_body_dec_2[0] & 0xF) + 3 + 128);

    //StringSource(file_body_compress_data, true, new HexEncoder(new FileSink(cout)));
    //cout << endl;

    try
    {
        StringSource(file_body_compress_data, true, new ZlibDecompressor(new StringSink(file_body_uncompress_data)));
    }
    catch (...)
    {
        cout << "zlib decompress failed" << endl;
        return 0;
    }
    
    //cout << file_body_uncompress_data << endl;
    StringSource(file_body_uncompress_data, true, new FileSink(output_file.c_str()));
    return 1;
}

#if 1
int main(int argc, char **argv)
{
    vector<zip*> zip_file;
    size_t offset, pos;
    ArrayByte exe_data;
    string file_name, full_name;
    zip *file_to_decrypt = NULL;
    bool select_mode = true;

    if (argc < 2)
    {
        printf("usage: %s [file]\n", argv[0]);
		printf("file: exe file path\n", argv[0]);
        system("pause");
        return 0;
    }

    try
    {
        FileSource(argv[1], true, new StringSink(exe_data));
    }
    catch (...)
    {
        cout << "file open failed" << endl;
        system("pause");
        return 0;
    }
    
    offset = 0;
    while ((pos = exe_data.find(ZIP_MAGIC_WORD, offset)) != string::npos)
    {
        ArrayByte temp = exe_data.substr(pos);
        zip *zip_ptr = new zip(temp, temp.length());
        if (zip_ptr->is_valid())
        {
            zip_file.push_back(zip_ptr);
        }       
        offset = pos + 4;
    }

    full_name = string(argv[1]);
    size_t pos1 = full_name.find_last_of('/');
    if (pos1 == string::npos)
    {
        pos1 = full_name.find_last_of('\\');
    }
    size_t pos2 = full_name.find_last_of('.');
    if (pos2 == string::npos)
    {
        pos2 = full_name.length();
    }
    file_name = full_name.substr(pos1 + 1, pos2 - pos1 - 1);
    for (zip *zip_file_ptr : zip_file)
    {
        if (zip_file_ptr->get_suffix().compare("xml") == 0 && zip_file_ptr->get_name().compare("manifest") == 0)
        {
            //get key from manifest.xml
            string xml_data = zip_file_ptr->get_uncompress_data();
            size_t start, end;

            start = xml_data.find("<session-key>");
            end = xml_data.find("</session-key>", start);
            if (start == string::npos || end == string::npos)
            {
                cout << "can not find solution key" << endl;
                return 0;
            }
            solution_key = xml_data.substr(start + strlen("<session-key>"), end - start - strlen("<session-key>"));
            //cout << "solution key: " << solution_key << endl;

            start = xml_data.find("<public-key>");
            end = xml_data.find("</public-key>", start);
            if (start == string::npos || end == string::npos)
            {
                cout << "can not find compiler key" << endl;
                return 0;
            }
            compiler_key = xml_data.substr(start + strlen("<public-key>"), end - start - strlen("<public-key>"));
            // cout << "compiler key: " << compiler_key << endl;
            break;
        }
        else if (zip_file_ptr->get_suffix().compare("m") == 0 && zip_file_ptr->get_name().compare(file_name) == 0)
        {
            cout << "*********************************************************************" << endl;
            cout << "I guess < " << file_name << ".m > is the file you want to decrypt!!!" << endl;
            cout << "So, I do it!!!" << endl;
            cout << "*********************************************************************" << endl <<endl;
            select_mode = false;
            file_to_decrypt = zip_file_ptr;
        }
    }

    //select_mode = true;
    if (select_mode == true)
    {
        int count = 0;
        vector<zip*> m_file;
        cout << "selcet file you want to decrypt" << endl;
        cout << "please input number" << endl;
        for (zip *zip_file_ptr : zip_file)
        {
            if (zip_file_ptr->get_suffix().compare("m") == 0)
            {
                m_file.push_back(zip_file_ptr);
                cout << count << ": " << zip_file_ptr->get_name() << "." << zip_file_ptr->get_suffix() << endl;
                count++;
            }
        }
        string select_str;
        int select_num;
        while (true)
        {
            cout << "-----------------------" << endl;
            cin >> select_str;
            select_num = strtol(select_str.c_str(), NULL, 10);
            if (select_num < 0 || select_num >(m_file.size() - 1))
            {
                cout << "input invalid, you input number is " << select_num << endl;
                continue;
            }
            else
            {
                file_to_decrypt = m_file[select_num];
                break;
            }
        }
    }

    if (exe2m_main(file_to_decrypt->get_uncompress_data(), file_to_decrypt->get_name() + ".m") == 0)
    {
        cout << "failed" << endl;
    }
    else
    {
        cout << "done" << endl;
    }

    system("pause");
    return 1;
}
#endif
