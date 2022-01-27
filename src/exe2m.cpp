#include <iostream>
#include <io.h>
#include <windows.h>
#include "rsa.h"
#include "oaep.h"
#include "sha.h"
#include "files.h"
#include "hex.h"
#include "modes.h"
#include "aes.h"
#include "filters.h"
#include "osrng.h"
#include "base64.h"
#include "pssr.h"
#include "zlib.h"
#include "zip.h"
#include "def.h"
#include "logger.h"

#pragma comment(lib, "cryptlib.lib")

using namespace CryptoPP;
using std::string;
using std::cin;
using std::cout;
using std::endl;
using std::exception;
using std::vector;

#define MATLAB_FILE_INTEGRITY 0

static string g_matlab_magic_file_v1 = "V1MCC4000MEC1000MCR1000";
static string g_matlab_magic_file_v2 = "V2MCC8000MEC2000MCR2000";

static string g_solution_key = "";
static string g_compiler_key = "";
static string g_matlab_key_v1 = "30820275020100300D06092A864886F70D01010105000482025F3082025B02010002818100C49CAC34ED13A520658F6F8E0138C4315B4315277ED3F7DAE53099DB08EE589F804D4B981326A52CCE4382E9F2B4D085EB950C7AB12EDE2D41297820E6377A5FEB5689D4E6032F60C43074A04C26AB72F54B51BB460578785B199014314A65F090B61FC20169453B58FC8BA43E6776EB7ECD3178B56AB0FA06DD64967CB149E502011102818002E42FB57BF4FEA9E3603A1C70F58A6A2339750458740EF06540B6F7ED4ECC98EF10320D87CFA08BF3F976A18EDD0311073AA998647CECADD78BE769E544949F809D1802102584E73824ED0BDDF2615E92EFBE59AF0BBF51312368CAE0C4335954C4F04EDE2B2BD74502F1C493BBB1F07278CC15CBD6DB477CF30855D548D0F9024100D280261FE351800E3AFE76E6DF30FF56640BC338B8B5608B9446CD0C68BD71609C491B3EB741F16606A0D26527954B57DEFA3AD30CAA6E6BEC05092B3CD1B72D024100EF1C0328B8BA61E79F6306927893CEFD8990FEB00E31465BB96AED24146F50D5701D2F9046AFAEA6FD938107D8F6E7B537BCC0DB83AE0390EA4A249E98881099024100B9BC5DDFE6B152DF613AE1624C7686F1DFCE24B993EB552FDD2F69A1899818BEA804453756675C8733065F4A31FC336BA6A08E41BFE1ACB99404718080F54745024100D2FA99602A865662F60C14DB97917A673D25956E2AA3F2C9675E58C57B714752EA741AE8B6D73FC085640870560708AEF4F1D7584702F416745F89B91D2CC35902401FC8C791E3EFEA82763D38163EDFC4A1C5BF762D39F4CF077EC5785A80960A27EA8658EBE049421B741612324A57CFE880EE5AC92B11080623D4DDE1F6FD3CC7";
static string g_toolbox_key_v1 = "35668C564C9BD12CA842B902206828699C7B48E51E9F695DABBC6CCE614DBF159F724C683A28B80C365EBEB7FFD0E5BE0A144C12EA43CAED9FC1977014FE7A558A31710EB36A8ED5259B07247BC1032D94F5BC921F72DD3057146F88AFF69A7D4700F08F4CB559F00F13E62432F1EBC5CA5B745D88E871F6695CD31BCFFD5053";
static string g_matlab_key_v2 = "308204BC020100300D06092A864886F70D0101010500048204A6308204A20201000282010100A9B2CB90DEAE533973DA6283BCCE2C2B86B910177E0ECA4AFD5C938D6E2BCA7C1EBBF1F6C5D41EB6B29C108AEC8EF1EE53BEB42CB6B791E756ABF4FF762A4A320D2D7A44F14330808CC43A47C73CEF9187C634ABFD6C10E0E11696148BFD64845EB4078F9611AD8A9E719C478B969279543AFE990F79B9CE2D29C572D5BCEF802AFC2DB2D62583A8DFE228D3D5C270939BBDD15BC5AA5505356E0DC006EAB8D14D967438CAB92F60486C2DCB6916464109B800E54AC535DF4E25C1367709DC101359EE538246372BFEF251570454A6A9EB71912B7D4A82DE61E278F8B79E7638DCA11075620FB8026A181CAAF1BC8007FE7558857E62F9BF6F2E8E50BF4B0743020111028201002CEB903CEFA69D8F354156500C54B156D0D6A260924F358C522008F0BB47D3B7718C1A66F8218FA8D4ED1370117121EC435820A26C9A00F978D32A439F476DFE30AA27E512AFE7311633F14F3C44D600E02CEFD32C7E7CF03B95099C06F0404128209896F304ADEFFCC3B86D4A98CC6B691EACCE29BE56D4B19A1DAD74D0214724023F26FA35BDA218F9E2801732CDFDC034160607178AF2EA95BA47534DE177C8C13A789AFFAFF648728EACDC9372B3931B8002EA08BD340FE24208811F3857DDCFDB8D4C6303E9DBEE6A6E4B5A91D1569846A4AA76267D3FF67426497880267A5164C1A3BA5046E3F99024FF47DDCCE0C43C170CCA22527D203CFC2569B98502818100BC8FF12CFC2D217E91DBF91B9604F712173F4C4B5F4954D6EA20A2F8A4A37B7A1AA58514F4D8DD3BE82FD86DD9F287062E637094B9D33DC333CE27A55DB583235EC20067CC02048263CC6BF1DF9164FA0AD94C57A0397B7C02E3FC853E8E26382F3EA295048C880D74A6AB32B97BF6D7A7B1F98D7EC429498B35E178C6C4B16F02818100E663BFB9B6F47954288F10F0CBA8366D91F2A3A44B9648989C3439482792CD20E73367951A8C2B2CA3E0E5096A4C0DE9CC091E7E722649C933AB83A9DC33BCF6194DCCF25CCE23E0CE12FDFD5D6D1AD1EECAC82CE752AEDE89CD37710E2CA4C4A667D4CBF2FC3993D117FB971E865FB893DE0A2F24A3325AB5F0AA02F968B56D02818100A660E3DC6609B4246294EADC1AF552795FCE707EBD7CF081652BDB17A0540389DB46C0B82355F062091B2860ED7BA450BF84EADD94E790D969F222FB52AF37798FD85AB5F03E03FA944AF5D56AE9B37336BFBBD4D8AB30B8B741A293AFAA9A319319260B0403871AEE74F168FE03F7EB75D9459AF761CA13B7116C97BE71514302818100CB48F476B07D5BFEF69C5A3DE0DFB78DDB2163369D0C21F0115B419A04CCD31D083C6A7480D607FA363EE8357BE8C0FB77CBCF9CBF12B99369D3924A951E97ABF83596B7BB4C7A0297B667A3526F53E669498372EA39E5972E4BA963C13673441A5B9DA4E57523BEA96F83A375496384BEB4DBCF3E71E122DCC54AB754899105028180456F40CDC405EA6FC25165BE84ECCBFA7D936C9B80063423F1AEE558D1FA21E95390B6D0F686F9F3BB2BB80BCD0EE9BDE7C2608E9AB023E1136B6FAF9DED4EE6C9A84C0F5E60403185D7CC311450C66733D83C3B5D28CEA850D57BB0352787032D65AEE82CB3E103F924EF9C57E576BB875A28254B4D22B5632AE8BCF966E55A";
static string g_toolbox_key_v2 = "681870f2fdd1573dcf77aa0bd0cd308c5131e137d38744a5aaf53930b130b8118d8b5d9dbed7cce8ae8f62f60b6865b0fa1bdf330de0452860baf42b682c86646f14aa3a59a7f970346e564b3bf5d3a8d334f033754861299757af47e6c8c66df445158913e7861afeae8ff83803399c182987b4cd0c1c463fbfca7f6713b7b5adfd68fc0d63aa020d979deb157f129414031163b438605a656f7005b9b6dc01f12d68c6bdbcc733d0af578a35cac6ebb667718f060eec93aff1499acfe9f068729b22e5f12af8091be5164865852699ebb6aab45eeb83bddf59f720061874803e16eb5af3dbcd87399aacd35104a6346f83461b02a7a173496617ac7aabdb54";

enum
{
    MATLAB_FILE_V1 = 1,
    MATLAB_FILE_V2 = 2,
};

static string sym_key_dec(string matlab_key, string solution_key, int version)
{
    DOCUMENTED_TYPEDEF(RSAES<OAEP<SHA512>>::Decryptor, RSAES_OAEP_SHA512_Decryptor);

    StringSource privFile(matlab_key, true, new HexDecoder);
    AutoSeededRandomPool rng;
    string result;

    if (version == MATLAB_FILE_V1)
    {
        RSAES_OAEP_SHA_Decryptor priv(privFile);
        StringSource(solution_key, true, new HexDecoder(new PK_DecryptorFilter(rng, priv, new StringSink(result))));
    }
    else if(version == MATLAB_FILE_V2)
    {
        RSAES_OAEP_SHA512_Decryptor priv(privFile);
        StringSource(solution_key, true, new HexDecoder(new PK_DecryptorFilter(rng, priv, new HexEncoder(new StringSink(result)))));
    }

    return result;
}

static string aes_key_dec(string sym_key)
{
    SHA256 sha256;
    string result;

    StringSource(sym_key, true, new HashFilter(sha256, new HexEncoder(new StringSink(result))));

    return result;
}

static bool hmac_check(ArrayByte data, string aes_key, ArrayByte xhmac, int version)
{
    string aes_key_hex, hmac;

    StringSource(aes_key, true, new HexDecoder(new StringSink(aes_key_hex)));
    
    if (version == MATLAB_FILE_V1)
    {
        HMAC<SHA1> hmac_sha1((const byte*)aes_key_hex.data(), aes_key_hex.length());
        StringSource(data, true, new HashFilter(hmac_sha1, new StringSink(hmac)));
        return xhmac.compare(hmac) == 0;
    }
    else if(version == MATLAB_FILE_V2)
    {
        HMAC<SHA256> hmac_sha256((const byte*)aes_key_hex.data(), aes_key_hex.length());
        StringSource(data, true, new HashFilter(hmac_sha256, new StringSink(hmac)));
        return xhmac.compare(hmac) == 0;
    }
    return false;
}

static string calc_iv(ArrayByte data)
{
    if (data.length() < 8)
    {
        __LOG_ERROR__("CALC_IV", "data length < 8\n");
        throw CryptoPP::Exception(CryptoPP::Exception::OTHER_ERROR,"data length < 8\n");
        return "";
    }
    string iv_data = data.substr(data.length() - 8, 8);

    ArrayByte sha256_result;
    SHA256 sha256;
    StringSource(iv_data, true, new HashFilter(sha256, new StringSink(sha256_result)));

    int i;
    for (i = 0; i < 16; i++)
    {
        sha256_result[i] ^= sha256_result[i + 16];
    }

    string iv;
    StringSource((const byte*)sha256_result.data(), 16, true, new StringSink(iv));
    return iv;
}

static ArrayByte aes_dec(string key, ArrayByte iv, ArrayByte data)
{
    string result, hex_key;
    string aes_data = data;

    StringSource(key, true, new HexDecoder(new StringSink(hex_key)));
    CFB_Mode<AES>::Decryption aes((const byte*)hex_key.data(), hex_key.length(), (const byte*)iv.data());
    StringSource(aes_data, true, new StreamTransformationFilter(aes, new StringSink(result)));

    return result;
}

static ArrayByte data_dec(string aes_key, ArrayByte data)
{
    string iv;
    iv = calc_iv(data);
    ArrayByte data_without_iv = data.substr(0, data.length() - 8);
    return aes_dec(aes_key, iv, data_without_iv);
}

static bool check_integrity(ArrayByte message, ArrayByte signature, string key, int version)
{
    StringSource public_key(key, true, new HexDecoder);
    bool check = false;

    if (version == MATLAB_FILE_V1)
    {
        //todo: check v1 signature
        RSASS<PSS, SHA256>::Verifier verifier(public_key);
        check = verifier.VerifyMessage((byte*)message.data(), message.length(), (byte*)signature.data(), signature.length());
    }
    else if (version == MATLAB_FILE_V2)
    {
        RSASS<PSS, SHA512>::Verifier verifier(public_key);
        check = verifier.VerifyMessage((byte*)message.data(), message.length(), (byte*)signature.data(), signature.length());
    }

    return check;
}

static int dec_matlab_file_v1(ArrayByte mfile_data, string output_file, int version)
{
    string sym_key_from_solution = sym_key_dec(g_matlab_key_v1, g_solution_key, version);
    string sym_key_from_toolbox = sym_key_dec(g_matlab_key_v1, g_toolbox_key_v1, version);
    __LOG_DEBUG__("dec_matlab_file_v1", "sym_key_from_solution: %s\n", sym_key_from_solution.data());
    __LOG_DEBUG__("dec_matlab_file_v1", "sym_key_from_toolbox: %s\n", sym_key_from_toolbox.data());

    string aes_key_from_solution = aes_key_dec(sym_key_from_solution);
    string aes_key_from_toolbox = aes_key_dec(sym_key_from_toolbox);
    __LOG_DEBUG__("dec_matlab_file_v1", "aes_key_from_solution: %s\n", aes_key_from_solution.data());
    __LOG_DEBUG__("dec_matlab_file_v1", "aes_key_from_toolbox: %s\n", aes_key_from_toolbox.data());

    int file_body_1_size = *(int*)mfile_data.substr(23, 4).data();
    ArrayByte file_body_1 = mfile_data.substr(27, file_body_1_size);
    ArrayByte file_body_2 = mfile_data.substr(27 + (size_t)file_body_1_size);
    ArrayByte file_body_1_without_hmac = file_body_1.substr(0, file_body_1.length() - 20);
    ArrayByte file_body_2_without_hmac = file_body_2.substr(0, file_body_2.length() - 20);
    ArrayByte file_body_1_hmac = file_body_1.substr(file_body_1.length() - 20);
    ArrayByte file_body_2_hmac = file_body_2.substr(file_body_2.length() - 20);
    __LOG_DEBUG__("dec_matlab_file_v1", "file_body_1_size: %d\n", file_body_1.length());
    __LOG_DEBUG__("dec_matlab_file_v1", "file_body_2_size: %d\n", file_body_2.length());

    // body1 used to check file expired
    // body2 used to get plain text
    ArrayByte file_body_dec_1, file_body_dec_2;
    string used_key_1, used_key_2;
    if (hmac_check(file_body_1_without_hmac, aes_key_from_solution, file_body_1_hmac, version))
    {
        __LOG_DEBUG__("dec_matlab_file_v1", "body_1 use solution key\n");
        used_key_1 = aes_key_from_solution;
    }
    else if (hmac_check(file_body_1_without_hmac, aes_key_from_toolbox, file_body_1_hmac, version))
    {
        __LOG_DEBUG__("dec_matlab_file_v1", "body_1 use toolbox key\n");
        used_key_1 = aes_key_from_toolbox;
    }
    else
    {
        __LOG_ERROR__("dec_matlab_file_v1", "no key match for file_body_1\n");
        throw CryptoPP::Exception(CryptoPP::Exception::OTHER_ERROR, "no key match for file_body_1\n");
        return 0;
    }
    file_body_dec_1 = data_dec(used_key_1, file_body_1_without_hmac);
    __LOG_DEBUG__("dec_matlab_file_v1", "body_dec_1 length: %d\n", file_body_dec_1.length());

    if (hmac_check(file_body_2_without_hmac, aes_key_from_solution, file_body_2_hmac, version))
    {
        __LOG_DEBUG__("dec_matlab_file_v1", "body_2 use solution key\n");
        used_key_2 = aes_key_from_solution;
    }
    else if (hmac_check(file_body_2_without_hmac, aes_key_from_toolbox, file_body_2_hmac, version))
    {
        __LOG_DEBUG__("dec_matlab_file_v1", "body_2 use toolbox key\n");
        used_key_2 = aes_key_from_solution;
    }
    else
    {
        __LOG_ERROR__("dec_matlab_file_v1", "no key match for file_body_2\n");
        throw CryptoPP::Exception(CryptoPP::Exception::OTHER_ERROR, "no key match for file_body_2\n");
        return 0;
    }
    file_body_dec_2 = data_dec(used_key_2, file_body_2_without_hmac);
    __LOG_DEBUG__("dec_matlab_file_v1", "body_dec_2 length: %d\n", file_body_dec_2.length());

    ArrayByte file_body_compress_data, file_body_uncompress_data;
    file_body_compress_data = file_body_dec_2.substr((file_body_dec_2[0] & 0xF) + 3 + 128);

    try
    {
        StringSource(file_body_compress_data, true, new ZlibDecompressor(new StringSink(file_body_uncompress_data)));
    }
    catch (CryptoPP::Exception e)
    {
        __LOG_ERROR__("dec_matlab_file_v1", "zlib decompress failed\n");
        throw CryptoPP::Exception(CryptoPP::Exception::OTHER_ERROR, "zlib decompress failed\n");
        return 0;
    }

#if MATLAB_FILE_INTEGRITY
    //做数据的完整性保护测试，默认不做测试
    
    ArrayByte signature = file_body_dec_1.substr(7, 128);
    ArrayByte message = file_body_dec_1.substr(7+128);
    if (check_integrity(message, signature, g_compiler_key, version) == false)
    {
        __LOG_MESSAGE__("dec_matlab_file_v1", "body_1 signature failed\n");
    }
    
#endif

    StringSource(file_body_uncompress_data, true, new FileSink(output_file.data()));
    return 1;
}

static int dec_matlab_file_v2(ArrayByte mfile_data, string output_file, int version)
{
    string sym_key_from_solution = sym_key_dec(g_matlab_key_v2, g_solution_key, version);
    string sym_key_from_toolbox = sym_key_dec(g_matlab_key_v2, g_toolbox_key_v2, version);
    __LOG_DEBUG__("dec_matlab_file_v2", "sym_key_from_solution: %s\n", sym_key_from_solution.data());
    __LOG_DEBUG__("dec_matlab_file_v2", "sym_key_from_toolbox: %s\n", sym_key_from_toolbox.data());

    string aes_key_from_solution = sym_key_from_solution;
    string aes_key_from_toolbox = sym_key_from_toolbox;

    int file_body_1_size = *(int*)mfile_data.substr(23, 4).data();
    int64_t file_body_2_uncompress_size = *(int64_t*)mfile_data.substr(27 + file_body_1_size, 8).data();
    ArrayByte file_body_1 = mfile_data.substr(27, file_body_1_size);
    ArrayByte file_body_2 = mfile_data.substr(27 + file_body_1_size + 8, mfile_data.length() - 8 - 32 - 16 - 27 - file_body_1_size);
    ArrayByte data_without_hmac = mfile_data.substr(0, mfile_data.length() - 32);
    ArrayByte hmac = mfile_data.substr(mfile_data.length() - 32, 32);
    ArrayByte aes_iv = mfile_data.substr(mfile_data.length() - 32 - 16, 16);
    __LOG_DEBUG__("dec_matlab_file_v2", "file_body_1_size: %d\n", file_body_1.length());
    __LOG_DEBUG__("dec_matlab_file_v2", "file_body_2_size: %d\n", file_body_2.length());

    // body1 used to check file expired
    // body2 used to get plain text
    ArrayByte file_body_dec_1, file_body_dec_2;
    string used_key;
    if (hmac_check(data_without_hmac, aes_key_from_solution, hmac, version))
    {
        __LOG_DEBUG__("dec_matlab_file_v2", "use solution key\n");
        used_key = aes_key_from_solution;
    }
    else if (hmac_check(data_without_hmac, aes_key_from_toolbox, hmac, version))
    {
        __LOG_DEBUG__("dec_matlab_file_v2", "use toolbox key\n");
        used_key = aes_key_from_toolbox;
    }
    else
    {
        __LOG_ERROR__("dec_matlab_file_v2", "no key match\n");
        throw CryptoPP::Exception(CryptoPP::Exception::OTHER_ERROR, "no key match\n");
        return 0;
    }
    file_body_dec_1 = aes_dec(used_key, aes_iv, file_body_1);
    file_body_dec_2 = aes_dec(used_key, aes_iv, file_body_2);

    ArrayByte file_body_compress_data, file_body_uncompress_data;
    file_body_compress_data = file_body_dec_2;
    try
    {
        StringSource(file_body_compress_data, true, new ZlibDecompressor(new StringSink(file_body_uncompress_data)));
    }
    catch (CryptoPP::Exception e)
    {
        __LOG_ERROR__("dec_matlab_file_v2", "zlib decompress failed\n");
        throw CryptoPP::Exception(CryptoPP::Exception::OTHER_ERROR, "zlib decompress failed\n");
        return 0;
    }

#if MATLAB_FILE_INTEGRITY
    //做数据的完整性保护测试，默认不做测试
    ArrayByte signature = file_body_dec_1.substr(0, 256);
    ArrayByte message = file_body_dec_1.substr(256);
    if (check_integrity(message, signature, g_compiler_key, version) == false)
    {
        __LOG_MESSAGE__("dec_matlab_file_v2", "body_1 signature failed\n");
    }
    else
    {
        __LOG_MESSAGE__("dec_matlab_file_v2", "body_1 signature good\n");
    }

    signature = file_body_uncompress_data.substr(0, 256);
    message = file_body_uncompress_data.substr(256);
    if (check_integrity(message, signature, g_compiler_key, version) == false)
    {
        __LOG_MESSAGE__("dec_matlab_file_v2", "body_2 signature failed\n");
    }
    else
    {
        __LOG_MESSAGE__("dec_matlab_file_v2", "body_2 signature good\n");
    }
#endif

    ArrayByte plain = file_body_uncompress_data.substr(256);
    StringSource(plain, true, new FileSink(output_file.data()));
    return 1;
}

static int exe2m_main(ArrayByte mfile_data, string output_file)
{
    int version = 0;

    if (mfile_data.compare(0, g_matlab_magic_file_v1.length(), g_matlab_magic_file_v1) == 0)
    {
        version = MATLAB_FILE_V1;
        __LOG_DEBUG__("exe2m_main", "current version: %d\n", version);
        dec_matlab_file_v1(mfile_data, output_file, version);
    }
    else if (mfile_data.compare(0, g_matlab_magic_file_v2.length(), g_matlab_magic_file_v2) == 0)
    {
        version = MATLAB_FILE_V2;
        __LOG_DEBUG__("exe2m_main", "current version: %d\n", version);
        dec_matlab_file_v2(mfile_data, output_file, version);
    }
    else
    {
        __LOG_ERROR__("exe2m_main", "unknown version\n");
        return 0;
    }
    return 1;
}

static size_t zip_traverse(vector<zip*> &zip_file, ArrayByte input_data)
{
    size_t offset = 0, pos = 0;
    while ((pos = input_data.find(zip::ZIP_MAGIC_WORD, offset)) != string::npos)
    {
        ArrayByte temp = input_data.substr(pos);
        zip* zip_ptr = new zip(temp, temp.length());
        if (zip_ptr->is_valid())
        {
            zip_file.push_back(zip_ptr);
        }
        else
        {
            delete zip_ptr;
        }
        offset = pos + zip::ZIP_MAGIC_WORD.length();
    }
    return zip_file.size();
}

#if 1
int main(int argc, char **argv)
{
    enum 
    {
        RUN_MODE_NORMAL,
        RUN_MODE_DEC_ALL,
        RUN_MODE_LIST
    };

    if (argc < 5)
    {
        printf("usage: %s [-i input] [-o output] [-a/-l] [-d] \n", argv[0]);
		printf("-i: 输入文件的路径\n");
        printf("-o: 输出文件的路径或者输出的目录\n");
        printf("-a: 全部解密，此时-o指定输出的目录\n");
        printf("-l: 列出所有可以被解密的文件\n");
        printf("-d: 显示调试日志\n");
        system("pause");
        return 0;
    }
    
    log_with_fd(stdout);
    //log_set_level(__LEVEL_DEBUG__);
    log_set_level(__LEVEL_MESSAGE__);
    log_set_level(__LEVEL_ERROR__);

    int i, run_mode = RUN_MODE_NORMAL;
    string input_file, output_file;
    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-i") == 0)
        {
            input_file = string(argv[i+1]);
            i++;
            continue;
        }
        else if (strcmp(argv[i], "-o") == 0)
        {
            output_file = string(argv[i + 1]);
            i++;
            continue;
        }
        else if (strcmp(argv[i], "-a") == 0)
        {
            run_mode = RUN_MODE_DEC_ALL;
            continue;
        }
        else if (strcmp(argv[i], "-l") == 0)
        {
            run_mode = RUN_MODE_LIST;
            continue;
        }
        else if (strcmp(argv[i], "-d") == 0)
        {
            log_set_level(__LEVEL_DEBUG__);
            continue;
        }
    }

    __LOG_MESSAGE__("exe2m", "input file: %s\n", input_file.data());
    __LOG_MESSAGE__("exe2m", "output file: %s\n", output_file.data());

    ArrayByte input_data;
    try
    {
        FileSource(input_file.data(), true, new StringSink(input_data));
    }
    catch (CryptoPP::Exception e)
    {
        cout << e.GetWhat() << endl;
        system("pause");
        return 0;
    }
    
    /* 遍历exe文件的zip文件 */
    vector<zip*> zip_file;
    if (zip_traverse(zip_file, input_data) <= 0)
    {
        __LOG_ERROR__("exe2m", "no zip file in %s\n", input_file);
        return 0;
    }

    vector<zip*> enc_file;
    for (zip* zip_file_ptr : zip_file)
    {
        /* get key from manifest.xml */
        if (zip_file_ptr->get_suffix().compare("xml") == 0 && zip_file_ptr->get_name().compare("manifest") == 0)
        {
            string xml_data = zip_file_ptr->get_uncompress_data();
            size_t start, end;

            start = xml_data.find("<session-key>");
            end = xml_data.find("</session-key>", start);
            if (start == string::npos || end == string::npos)
            {
                __LOG_ERROR__("exe2m", "can not find solution key\n");
                return 0;
            }
            g_solution_key = xml_data.substr(start + strlen("<session-key>"), end - start - strlen("<session-key>"));
            __LOG_DEBUG__("exe2m", "solution key: %s\n", g_solution_key.data());

            start = xml_data.find("<public-key>");
            end = xml_data.find("</public-key>", start);
            if (start == string::npos || end == string::npos)
            {
                __LOG_ERROR__("exe2m", "can not find compiler key\n");
                return 0;
            }
            g_compiler_key = xml_data.substr(start + strlen("<public-key>"), end - start - strlen("<public-key>"));
            __LOG_DEBUG__("exe2m", "compiler key: %s\n", g_compiler_key.data());
            continue;
        }

        /* 遍历所有能解密的文件 */
        ArrayByte uncompress_data = zip_file_ptr->get_uncompress_data();
        if(uncompress_data.compare(0, g_matlab_magic_file_v1.length(), g_matlab_magic_file_v1) == 0)
        {
            //cout << "v1:  " << zip_file_ptr->get_full_name() << endl;
            enc_file.push_back(zip_file_ptr);
        }
        else if (uncompress_data.compare(0, g_matlab_magic_file_v2.length(), g_matlab_magic_file_v2) == 0)
        {
            //cout << "v2:  " << zip_file_ptr->get_full_name() << endl;
            enc_file.push_back(zip_file_ptr);
        }
        else if(uncompress_data.compare(0, zip::ZIP_MAGIC_WORD.length(), zip::ZIP_MAGIC_WORD) == 0)   //处理嵌套的zip文件
        {
            //cout << "zip: " << zip_file_ptr->get_full_name() << endl;
            vector<zip*> nested_zip_file;
            if (zip_traverse(nested_zip_file, uncompress_data) > 0)
            {
                for (zip* nested_zip_file_ptr : nested_zip_file)
                {
                    ArrayByte nested_uncompress_data = nested_zip_file_ptr->get_uncompress_data();
                    if (nested_uncompress_data.compare(0, g_matlab_magic_file_v1.length(), g_matlab_magic_file_v1) == 0)
                    {
                        nested_zip_file_ptr->set_full_name(zip_file_ptr->get_full_name() + "#" + nested_zip_file_ptr->get_full_name());
                        enc_file.push_back(nested_zip_file_ptr);
                    }
                    else if (nested_uncompress_data.compare(0, g_matlab_magic_file_v2.length(), g_matlab_magic_file_v2) == 0)
                    {
                        nested_zip_file_ptr->set_full_name(zip_file_ptr->get_full_name() + "#" + nested_zip_file_ptr->get_full_name());
                        enc_file.push_back(nested_zip_file_ptr);
                    }
                }
            }
        }
    }
    
    if (run_mode == RUN_MODE_DEC_ALL)
    {
        if (output_file[output_file.length() - 1] != '\\')
        {
            output_file += '\\';
        }
        if (_access(output_file.data(), 0) != 0)
        {
            if (CreateDirectory(output_file.data(), NULL) == false)
            {
                __LOG_ERROR__("main", "create dir %s failed\n", output_file.data());
                return 0;
            }
        }
        for (zip* zip_file_ptr : enc_file)
        {
            try
            {
                if (exe2m_main(zip_file_ptr->get_uncompress_data(), output_file + zip_file_ptr->get_name() + ".m") == 0)
                {
                    __LOG_ERROR__("main", "dec %s failed\n", zip_file_ptr->get_full_name().data());
                }
                else
                {
                    __LOG_MESSAGE__("main", "dec %s done\n", zip_file_ptr->get_full_name().data());
                }
            }
            catch (CryptoPP::Exception e)
            {
                __LOG_ERROR__("main", "%s\n", e.GetWhat().data());
            }
        }
    }
    else if(run_mode == RUN_MODE_NORMAL || run_mode == RUN_MODE_LIST)
    {
        //通常模式下只会寻找fsroot目录下除.matlab，.META，toolbox之外的文件夹
        if (run_mode == RUN_MODE_NORMAL)
        {
            vector<zip*>::iterator it = enc_file.begin();
            while (it != enc_file.end())
            {
                if ((*it)->get_path().find(".matlab") != string::npos ||
                    (*it)->get_path().find(".META") != string::npos ||
                    (*it)->get_path().find("toolbox") != string::npos)
                {
                    it = enc_file.erase(it);
                }
                else
                {
                    it++;
                }
            }
        }

        int count = 0;
        cout << "选择你想要解密的文件，并输入对应的号码" << endl;
        printf("%-6s | %-8s | %-64s \n", "序号", "大小", "文件名");
        cout << "--------------------------------------------------------------------------------------------" << endl;
        for (zip* zip_file_ptr : enc_file)
        {
            printf("%-6d | %-8d | %-64s\n", count, zip_file_ptr->get_uncompressed_size(), zip_file_ptr->get_full_name().data());
            count++;
        }

        string select_str;
        int select_num;
        zip* to_dec_file = NULL;
        while (true)
        {
            cout << "--------------------------------------------------------------------------------------------" << endl;
            cin >> select_str;
            select_num = strtol(select_str.data(), NULL, 10);
            if (select_num < 0 || select_num >(count - 1))
            {
                cout << "input invalid, you input number is " << select_num << endl;
                continue;
            }
            else
            {
                to_dec_file = enc_file[select_num];
                break;
            }
        }

        try
        {
            if (exe2m_main(to_dec_file->get_uncompress_data(), output_file) == 0)
            {
                __LOG_ERROR__("main", "dec %s failed\n", to_dec_file->get_full_name().data());
            }
            else
            {
                __LOG_MESSAGE__("main", "dec %s done\n", to_dec_file->get_full_name().data());
            }
        }
        catch (CryptoPP::Exception e)
        {
            __LOG_ERROR__("main","%s\n", e.GetWhat().data());
        }
    }

    system("pause");
    return 1;
}
#endif
