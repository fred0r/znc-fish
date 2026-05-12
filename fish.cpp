#include <arpa/inet.h>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <memory>
#include <vector>

#include <znc/Chan.h>
#include <znc/IRCNetwork.h>
#include <znc/Message.h>
#include <znc/Modules.h>
#include <znc/SHA256.h>
#include <znc/User.h>

#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x1010100fL
#error "OpenSSL 1.1.1 or later is required"
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
#define SSL_get1_peer_certificate SSL_get_peer_certificate
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <openssl/blowfish.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

using std::map;
using std::make_pair;
using std::vector;

#define DEBUG_FISH(fmt, ...) DEBUG("FiSH: " << fmt, ##__VA_ARGS__)
#define MODVERSION "1.2.0"
#define KEY_PREFIX "key "
#define MODURL "https://github.com/ZarTek-Creole/znc-fish"
#define MODAUTHOR "ZarTek-Creole"
#define MODDESC "FiSH module with ECB/CBC, DH1080, topic encryption, marking"
#define NICK_PREFIX_KEY "[nick-prefix]"

/* FiSH base64 alphabet (ECB legacy) */
unsigned char B64[] = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

static inline bool IsFishB64Char(unsigned char c) {
    for (int i = 0; i < 64; ++i)
        if (B64[i] == c) return true;
    return false;
}

static int base64dec_fish(char c) {
    for (int i = 0; i < 64; ++i)
        if (B64[i] == (unsigned char)c) return i;
    return 0;
}

/* ECB encrypt -> FiSH custom base64 */
static char* encrypts_fish(const char* key, const char* str) {
    if (key == nullptr || str == nullptr) {
        DEBUG_FISH("encrypts_fish: NULL input");
        return nullptr;
    }

    size_t in_len = strlen(str);
    size_t total = ((in_len + 7) / 8) * 8;
    if (total == 0) total = 8;
    DEBUG_FISH("encrypts_fish: plain=\"" << CString(str).Left(40) << "\" in_len=" << in_len << " padded=" << total << " key_len=" << strlen(key));

    unsigned char* inbuf = (unsigned char*)malloc(total);
    if (!inbuf) return nullptr;
    memcpy(inbuf, str, in_len);
    memset(inbuf + in_len, 0, total - in_len);

    size_t blocks = total / 8;
    size_t out_len = blocks * 12 + 1;
    char* out = (char*)malloc(out_len);
    if (!out) { memset(inbuf, 0, total); free(inbuf); return nullptr; }

    BF_KEY bfkey;
    BF_set_key(&bfkey, strlen(key), (const unsigned char*)key);

    char* d = out;
    for (size_t b = 0; b < blocks; ++b) {
        unsigned char cipher[8];
        BF_ecb_encrypt(inbuf + (b * 8), cipher, &bfkey, BF_ENCRYPT);

        uint32_t l = ((uint32_t)cipher[0] << 24) | ((uint32_t)cipher[1] << 16) |
                     ((uint32_t)cipher[2] << 8)  |  (uint32_t)cipher[3];
        uint32_t r = ((uint32_t)cipher[4] << 24) | ((uint32_t)cipher[5] << 16) |
                     ((uint32_t)cipher[6] << 8)  |  (uint32_t)cipher[7];

        for (int i = 0; i < 6; ++i) { *d++ = B64[r & 0x3F]; r >>= 6; }
        for (int i = 0; i < 6; ++i) { *d++ = B64[l & 0x3F]; l >>= 6; }
    }
    *d = '\0';

    memset(inbuf, 0, total);
    free(inbuf);
    DEBUG_FISH("encrypts_fish: result=\"" << CString(out).Left(30) << "\" len=" << strlen(out));
    return out;
}

/* ECB decrypt from FiSH custom base64 */
static char* decrypts_fish(const char* key, const char* str) {
    if (key == nullptr || str == nullptr) {
        DEBUG_FISH("decrypts_fish: NULL input");
        return nullptr;
    }

    size_t in_len = strlen(str);
    DEBUG_FISH("decrypts_fish: input=" << CString(str).Left(20) << "... len=" << in_len << " key_len=" << strlen(key));
    if (in_len % 12 != 0) {
        DEBUG_FISH("decrypts_fish: invalid length " << in_len << " (not multiple of 12), truncating to " << (in_len / 12 * 12));
        return nullptr;
    }

    size_t blocks = in_len / 12;
    size_t out_bin_len = blocks * 8;
    DEBUG_FISH("decrypts_fish: blocks=" << blocks << " out_bin_len=" << out_bin_len);
    unsigned char* bin = (unsigned char*)malloc(out_bin_len);
    if (!bin) return nullptr;

    BF_KEY bfkey;
    BF_set_key(&bfkey, strlen(key), (const unsigned char*)key);

    const char* p = str;
    unsigned char* w = bin;
    for (size_t b = 0; b < blocks; ++b) {
        uint32_t r = 0, l = 0;
        for (int i = 0; i < 6; ++i) { r |= (uint32_t)base64dec_fish(*p++) << (i * 6); }
        for (int i = 0; i < 6; ++i) { l |= (uint32_t)base64dec_fish(*p++) << (i * 6); }

        r = htonl(r);
        l = htonl(l);
        unsigned char block[8];
        memcpy(block, &l, 4);
        memcpy(block + 4, &r, 4);

        BF_ecb_encrypt(block, block, &bfkey, BF_DECRYPT);
        memcpy(w, block, 8);
        w += 8;
    }

    size_t plain_len = out_bin_len;
    DEBUG_FISH("decrypts_fish: pre-strip plain_len=" << plain_len);
    while (plain_len > 0 && bin[plain_len - 1] == '\0') plain_len--;
    DEBUG_FISH("decrypts_fish: after trailing-NUL strip plain_len=" << plain_len);

    size_t write_pos = 0;
    for (size_t i = 0; i < plain_len; i++) {
        if (bin[i] != '\x00' && bin[i] != '\x0d' && bin[i] != '\x0a')
            bin[write_pos++] = bin[i];
    }
    DEBUG_FISH("decrypts_fish: after remove_bad_chars write_pos=" << write_pos);

    char* out = (char*)malloc(write_pos + 1);
    if (!out) { memset(bin, 0, out_bin_len); free(bin); return nullptr; }
    memcpy(out, bin, write_pos);
    out[write_pos] = '\0';

    memset(bin, 0, out_bin_len);
    free(bin);
    DEBUG_FISH("decrypts_fish: result=\"" << CString(out) << "\" len=" << write_pos);
    return out;
}



/* Standard base64 for CBC mode */
static const char b64_std[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_std_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static char* base64_encode(const unsigned char* input, size_t len) {
    size_t out_len = ((len + 2) / 3) * 4 + 1;
    char* out = (char*)malloc(out_len);
    if (!out) return nullptr;

    size_t i = 0, o = 0;
    while (i < len) {
        uint32_t n = (i < len ? input[i] : 0) << 16;
        n |= (i + 1 < len ? input[i + 1] : 0) << 8;
        n |= (i + 2 < len ? input[i + 2] : 0);
        out[o++] = b64_std[(n >> 18) & 0x3F];
        out[o++] = b64_std[(n >> 12) & 0x3F];
        out[o++] = (i + 1 < len) ? b64_std[(n >> 6) & 0x3F] : '=';
        out[o++] = (i + 2 < len) ? b64_std[n & 0x3F] : '=';
        i += 3;
    }
    out[o] = '\0';
    return out;
}

static unsigned char* base64_decode(const char* input, size_t* out_len) {
    size_t in_len = strlen(input);
    if (in_len % 4 != 0) return nullptr;

    size_t pad = 0;
    if (in_len > 0 && input[in_len - 1] == '=') pad++;
    if (in_len > 1 && input[in_len - 2] == '=') pad++;

    size_t len = (in_len / 4) * 3 - pad;
    unsigned char* out = (unsigned char*)malloc(len + 1);
    if (!out) return nullptr;

    size_t i = 0, o = 0;
    while (i < in_len) {
        int a = b64_std_char(input[i]);
        int b = b64_std_char(input[i + 1]);
        int c = (i + 2 < in_len && input[i + 2] != '=') ? b64_std_char(input[i + 2]) : -1;
        int d = (i + 3 < in_len && input[i + 3] != '=') ? b64_std_char(input[i + 3]) : -1;
        if (a < 0 || b < 0) { free(out); return nullptr; }

        uint32_t n = (a << 18) | (b << 12);
        if (c >= 0) n |= (c << 6);
        if (d >= 0) n |= d;

        out[o++] = (n >> 16) & 0xFF;
        if (c >= 0) out[o++] = (n >> 8) & 0xFF;
        if (d >= 0) out[o++] = n & 0xFF;
        i += 4;
    }
    out[o] = '\0';
    *out_len = o;
    return out;
}

/* Normalize base64 padding for lenient decode */
static char* b64_normalize(const char* str) {
    size_t len = strlen(str);
    if (len == 0) return nullptr;
    size_t rem = len % 4;
    if (rem == 1) {
        /* Invalid padding, drop last char */
        char* copy = strdup(str);
        if (copy) copy[len - 1] = '\0';
        return copy;
    }
    if (rem == 0) return nullptr;
    size_t new_len = len + (4 - rem) + 1;
    char* copy = (char*)malloc(new_len);
    if (!copy) return nullptr;
    memcpy(copy, str, len);
    memset(copy + len, '=', 4 - rem);
    copy[new_len - 1] = '\0';
    return copy;
}

/* CBC encrypt -> +OK *<standard-base64> */
static char* encrypts_cbc(const char* key, const char* str) {
    if (key == nullptr || str == nullptr) {
        DEBUG_FISH("encrypts_cbc: NULL input");
        return nullptr;
    }

    size_t in_len = strlen(str);
    size_t total = ((in_len + 7) / 8) * 8;
    if (total == 0) total = 8;
    DEBUG_FISH("encrypts_cbc: plain=\"" << CString(str).Left(40) << "\" in_len=" << in_len << " padded=" << total << " key_len=" << strlen(key));

    unsigned char* inbuf = (unsigned char*)malloc(total);
    if (!inbuf) return nullptr;
    memcpy(inbuf, str, in_len);
    memset(inbuf + in_len, 0, total - in_len);

    unsigned char iv[8];
    if (RAND_bytes(iv, 8) != 1) {
        DEBUG_FISH("encrypts_cbc: RAND_bytes failed");
        memset(inbuf, 0, total);
        free(inbuf);
        return nullptr;
    }
    DEBUG_FISH("encrypts_cbc: IV=" << CString((const char*)iv, 8).Base64Encode());

    BF_KEY bfkey;
    BF_set_key(&bfkey, strlen(key), (const unsigned char*)key);

    unsigned char* cipher = (unsigned char*)malloc(total);
    if (!cipher) { memset(inbuf, 0, total); free(inbuf); return nullptr; }

    unsigned char ivec[8];
    memcpy(ivec, iv, 8);
    BF_cbc_encrypt(inbuf, cipher, total, &bfkey, ivec, BF_ENCRYPT);

    size_t buf_len = 8 + total;
    unsigned char* combined = (unsigned char*)malloc(buf_len);
    if (!combined) {
        memset(inbuf, 0, total); free(inbuf);
        memset(cipher, 0, total); free(cipher);
        return nullptr;
    }
    memcpy(combined, iv, 8);
    memcpy(combined + 8, cipher, total);

    char* b64 = base64_encode(combined, buf_len);
    DEBUG_FISH("encrypts_cbc: b64=\"" << CString(b64).Left(40) << "\" len=" << strlen(b64));

    memset(inbuf, 0, total);
    memset(cipher, 0, total);
    memset(combined, 0, buf_len);
    free(inbuf);
    free(cipher);
    free(combined);

    return b64;
}

/* CBC decrypt from standard base64 */
static char* decrypts_cbc(const char* key, const char* str) {
    if (key == nullptr || str == nullptr) {
        DEBUG_FISH("decrypts_cbc: NULL input");
        return nullptr;
    }
    DEBUG_FISH("decrypts_cbc: input=\"" << CString(str).Left(30) << "\" len=" << strlen(str) << " key_len=" << strlen(key));

    const char* to_decode = str;
    char* free_me = nullptr;
    if (strlen(str) % 4 != 0) {
        DEBUG_FISH("decrypts_cbc: non-standard base64 padding (len%4=" << strlen(str) % 4 << ")");
        free_me = b64_normalize(str);
        if (!free_me) { DEBUG_FISH("decrypts_cbc: b64_normalize failed"); return nullptr; }
        to_decode = free_me;
        DEBUG_FISH("decrypts_cbc: normalized to \"" << CString(to_decode) << "\"");
    }

    size_t raw_len;
    unsigned char* raw = base64_decode(to_decode, &raw_len);
    if (free_me) free(free_me);
    if (!raw || raw_len < 9) {
        DEBUG_FISH("decrypts_cbc: base64_decode failed (raw=" << (void*)raw << " raw_len=" << raw_len << ")");
        free(raw);
        return nullptr;
    }
    DEBUG_FISH("decrypts_cbc: decoded raw_len=" << raw_len);

    size_t total = raw_len - 8;
    DEBUG_FISH("decrypts_cbc: IV=" << CString((const char*)raw, 8).Base64Encode() << " cipher_len=" << total);

    BF_KEY bfkey;
    BF_set_key(&bfkey, strlen(key), (const unsigned char*)key);

    unsigned char* plain = (unsigned char*)malloc(total);
    if (!plain) { memset(raw, 0, raw_len); free(raw); return nullptr; }

    unsigned char ivec[8];
    memcpy(ivec, raw, 8);
    BF_cbc_encrypt(raw + 8, plain, total, &bfkey, ivec, BF_DECRYPT);

    size_t plain_len = total;
    DEBUG_FISH("decrypts_cbc: pre-strip plain_len=" << plain_len);
    while (plain_len > 0 && plain[plain_len - 1] == '\0') plain_len--;
    DEBUG_FISH("decrypts_cbc: after trailing-NUL strip plain_len=" << plain_len);

    size_t write_pos = 0;
    for (size_t i = 0; i < plain_len; i++) {
        if (plain[i] != '\x00' && plain[i] != '\x0d' && plain[i] != '\x0a')
            plain[write_pos++] = plain[i];
    }
    DEBUG_FISH("decrypts_cbc: after remove_bad_chars write_pos=" << write_pos);

    char* out = (char*)malloc(write_pos + 1);
    if (!out) { memset(raw, 0, raw_len); memset(plain, 0, total); free(raw); free(plain); return nullptr; }
    memcpy(out, plain, write_pos);
    out[write_pos] = '\0';

    memset(raw, 0, raw_len);
    memset(plain, 0, total);
    free(raw);
    free(plain);
    DEBUG_FISH("decrypts_cbc: result=\"" << CString(out) << "\" len=" << write_pos);
    return out;
}

/* DH1080 base64 (standard) helpers */
unsigned char B64ABC[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
unsigned char b64buf[256];

void initb64() {
    for (unsigned int i = 0; i < 256; i++) b64buf[i] = 0x00;
    for (unsigned int i = 0; i < 64; i++) b64buf[(B64ABC[i])] = i;
}

int b64toh(char *b, char *d) {
    int i, k, l;
    l = strlen(b);
    if (l < 2) return 0;
    for (i = l - 1; i > -1; i--) {
        if (b64buf[(unsigned char)(b[i])] == 0 && b[i] != 'A')
            l--;
        else
            break;
    }
    if (l < 2) return 0;
    i = 0, k = 0;
    while (1) {
        i++;
        if (k + 1 < l) d[i - 1] = ((b64buf[(unsigned char)(b[k])]) << 2);
        else break;
        k++;
        if (k < l) d[i - 1] |= ((b64buf[(unsigned char)(b[k])]) >> 4);
        else break;
        i++;
        if (k + 1 < l) d[i - 1] = ((b64buf[(unsigned char)(b[k])]) << 4);
        else break;
        k++;
        if (k < l) d[i - 1] |= ((b64buf[(unsigned char)(b[k])]) >> 2);
        else break;
        i++;
        if (k + 1 < l) d[i - 1] = ((b64buf[(unsigned char)(b[k])]) << 6);
        else break;
        k++;
        if (k < l) d[i - 1] |= (b64buf[(unsigned char)(b[k])]);
        else break;
        k++;
    }
    return i - 1;
}

int htob64(char *h, char *d, unsigned int l) {
    unsigned int i, j, k;
    unsigned char m, t;
    if (!l) return 0;
    l <<= 3;
    m = 0x80;
    for (i = 0, j = 0, k = 0, t = 0; i < l; i++) {
        if (h[(i >> 3)] & m) t |= 1;
        j++;
        if (!(m >>= 1)) m = 0x80;
        if (!(j % 6)) {
            d[k] = B64ABC[t];
            t = 0;
            k++;
        }
        t <<= 1;
    }
    m = 5 - (j % 6);
    t <<= m;
    if (m) { d[k] = B64ABC[t]; k++; }
    d[k] = '\0';
    return strlen(d);
}

const char *prime1080 = "FBE1022E23D213E8ACFA9AE8B9DFADA3EA6B7AC7A7B7E95AB5EB2DF858921FEADE95E6AC7BE7DE6ADBAB8A783E7AF7A7FA6A2B7BEB1E72EAE2B72F9FA2BFB2A2EFBEFAC868BADB3E828FA8BADFADA3E4CC1BE7E8AFE85E9698A783EB68FA07A77AB6AD7BEB618ACF9CA2897EB28A6189EFA07AB99A8A7FA9AE299EFA7BA66DEAFEFBEFBF0B7D8B";

enum EFishMode { ModeECB, ModeCBC };

struct SKeyExchangeState {
    time_t timestamp;
    CString privkey;
    bool cbc_mode;
    SKeyExchangeState(time_t t, const CString& priv, bool cbc = true)
        : timestamp(t), privkey(priv), cbc_mode(cbc) {}
};

class CKeyExchangeTimer : public CTimer {
public:
    CKeyExchangeTimer(CModule *pModule)
        : CTimer(pModule, 5, 0, "KeyExchangeTimer", "Key exchange timer removes stale exchanges") {}
protected:
    virtual void RunJob();
};

class CFishMod : public CModule {
    CString NickPrefix() {
        MCString::iterator it = FindNV(NICK_PREFIX_KEY);
        CString sStatusPrefix = GetUser()->GetStatusPrefix();
        if (it != EndNV()) {
            size_t sp = sStatusPrefix.size();
            size_t np = it->second.size();
            size_t min = std::min(sp, np);
            if (min == 0 || sStatusPrefix.CaseCmp(it->second, min) != 0)
                return it->second;
        }
        return sStatusPrefix.StartsWith("*") ? "." : "*";
    }

    /* Parse mode prefix from key, default to CBC */
    bool ParseKey(const CString& raw, CString& out_key, EFishMode& out_mode) {
        if (raw.Left(4).Equals("ECB:")) {
            out_key = raw.Token(1, true, ":");
            out_mode = ModeECB;
            return true;
        } else if (raw.Left(4).Equals("CBC:")) {
            out_key = raw.Token(1, true, ":");
            out_mode = ModeCBC;
            return true;
        }
        out_key = raw;
        out_mode = ModeECB;
        return true;
    }

    /* Get stored mode for a target */
    CString GetModeNV(const CString& target) {
        CString key = "mode_" + target.AsLower();
        MCString::iterator it = FindNV(key);
        return it != EndNV() ? it->second : "";
    }

    void SetModeNV(const CString& target, const CString& mode) {
        SetNV("mode_" + target.AsLower(), mode);
    }

    bool IsDisabled(const CString& target) {
        MCString::iterator it = FindNV("disabled_" + target.AsLower());
        return it != EndNV() && it->second.Equals("on");
    }

    bool GetBoolNV(const CString& key, bool def) {
        MCString::iterator it = FindNV(key);
        if (it == EndNV()) return def;
        return it->second.Equals("on");
    }

    void SetBoolNV(const CString& key, bool val) {
        SetNV(key, val ? "on" : "off");
    }

    bool ShouldProcessIncoming() { return GetBoolNV("config process_incoming", true); }
    bool ShouldProcessOutgoing() { return GetBoolNV("config process_outgoing", true); }
    bool ShouldEncryptNotice() { return GetBoolNV("config encrypt_notice", true); }
    bool ShouldEncryptAction() { return GetBoolNV("config encrypt_action", true); }
    bool ShouldEncryptTopic(const CString& channel) {
        if (GetBoolNV("config global_topic_encrypt", false)) return true;
        MCString::iterator it = FindNV("topic_encrypt_" + channel.AsLower());
        if (it != EndNV()) return it->second.Equals("on");
        return FindNV("key " + channel.AsLower()) != EndNV();
    }
    bool IsMarkIncoming() { return GetBoolNV("config mark_incoming", false); }
    bool IsMarkIncomingTarget(const CString& target) {
        MCString::iterator it = FindNV("mark_target_" + target.AsLower());
        return it != EndNV() && it->second.Equals("on");
    }
    bool IsMarkBroken() { return GetBoolNV("config mark_broken", false); }
    CString MarkPos() {
        MCString::iterator it = FindNV("config mark_pos");
        return it != EndNV() ? it->second : "prefix";
    }
    CString MarkStr(const CString& type) {
        MCString::iterator it = FindNV("config mark_str_" + type);
        return it != EndNV() ? it->second : (type == "dec" ? "[decrypt]" : (type == "enc" ? "[encrypt]" : "[plain]"));
    }
    CString PlainPrefix() {
        MCString::iterator it = FindNV("config plain_prefix");
        return it != EndNV() ? it->second : "";
    }
    bool IsAutoKeyX() { return GetBoolNV("config autokeyx", false); }
    bool IsDebug() { return GetBoolNV("config debug", false); }
    void LogDebug(const CString& sMsg) {
        DEBUG_FISH(sMsg);
        if (IsDebug()) PutModule("[debug] " + sMsg);
    }

    CString EncryptValue(const CString& sPlain) {
        if (sPlain.empty()) return "";
        CString sPass = GetUser()->GetPass();
        if (sPass.empty()) return sPlain;
        unsigned char aes_key[32];
        sha256((const unsigned char*)sPass.c_str(), sPass.length(), aes_key);
        unsigned char iv[16];
        if (RAND_bytes(iv, 16) != 1) return sPlain;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return sPlain;
        int len, cipher_len;
        unsigned char cipher[4096];
        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_key, iv)) {
            EVP_CIPHER_CTX_free(ctx);
            return sPlain;
        }
        if (!EVP_EncryptUpdate(ctx, cipher, &len, (const unsigned char*)sPlain.c_str(), sPlain.length())) {
            EVP_CIPHER_CTX_free(ctx);
            return sPlain;
        }
        cipher_len = len;
        if (!EVP_EncryptFinal_ex(ctx, cipher + len, &len)) {
            EVP_CIPHER_CTX_free(ctx);
            return sPlain;
        }
        cipher_len += len;
        EVP_CIPHER_CTX_free(ctx);
        CString combined;
        combined.append((const char*)iv, 16);
        combined.append((const char*)cipher, cipher_len);
        combined.Base64Encode();
        return "$" + combined;
    }

    CString DecryptValue(const CString& sCipher) {
        if (!sCipher.StartsWith("$")) return "";
        CString b64 = sCipher.LeftChomp_n(1);
        CString sPass = GetUser()->GetPass();
        if (sPass.empty()) return "";
        unsigned char aes_key[32];
        sha256((const unsigned char*)sPass.c_str(), sPass.length(), aes_key);
        b64.Base64Decode();
        if (b64.length() < 16) return "";
        unsigned char iv[16];
        memcpy(iv, b64.data(), 16);
        CString enc = b64.substr(16);
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return "";
        int len, plain_len;
        unsigned char plain[4096];
        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_key, iv)) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        if (!EVP_DecryptUpdate(ctx, plain, &len, (const unsigned char*)enc.c_str(), enc.length())) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        plain_len = len;
        if (EVP_DecryptFinal_ex(ctx, plain + len, &len) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        plain_len += len;
        EVP_CIPHER_CTX_free(ctx);
        return CString((const char*)plain, plain_len);
    }

    CString GetEncryptedNV(const CString& sKey) {
        MCString::iterator it = FindNV(sKey);
        if (it == EndNV()) return "";
        CString sDec = DecryptValue(it->second);
        if (!sDec.empty()) return sDec;
        return it->second;
    }

    void SetEncryptedNV(const CString& sKey, const CString& sValue) {
        SetNV(sKey, EncryptValue(sValue));
        if (sKey.Left(4).Equals("key "))
            DelNV("mode_" + sKey.substr(4));
    }

    std::unique_ptr<DH, decltype(&DH_free)> m_pDH;

    template<typename T>
    bool CheckSkipEncryption(CString& sMessage, T& Message, const CString& sHandler) {
        if (sMessage.Left(2).Equals("-e")) {
            LogDebug(sHandler + ": -e prefix, skipping encryption");
            sMessage.LeftChomp(2);
            if (!sMessage.empty() && sMessage[0] == ' ') sMessage.LeftChomp();
            Message.SetText(sMessage);
            return true;
        }
        CString prefix = PlainPrefix();
        if (!prefix.empty() && sMessage.Left(prefix.length()).Equals(prefix)) {
            DEBUG_FISH(sHandler + ": PlainPrefix match, skipping encryption");
            return true;
        }
        return false;
    }

    bool TryDecryptClientEncrypted(const CString& sTarget, CString& sMessage,
                                    CString& out_result) {
        if (!(sMessage.Left(4) == "+OK " || sMessage.Left(5) == "mcps "))
            return false;
        if (IsDisabled(sTarget)) return false;
        CString sRawKey = GetEncryptedNV("key " + sTarget.AsLower());
        if (sRawKey.empty()) return false;
        CString sKey;
        EFishMode mode;
        ParseKey(sRawKey, sKey, mode);
        EFishMode used_mode;
        bool ok = false;
        TryDecrypt(sTarget, sKey, mode, sMessage, out_result, used_mode, ok);
        return ok;
    }

public:
    MODCONSTRUCTOR(CFishMod),
        m_pDH(DH_new(), DH_free)
    {
        AddHelpCommand();
        AddCommand("SetKey", t_d("<target> [CBC:|ECB:]<key>"), t_d("Sets encryption key"), [this](const CString& sLine) { OnSetKeyCommand(sLine); });
        AddCommand("DelKey", t_d("<target>"), t_d("Removes encryption key"), [this](const CString& sLine) { OnDelKeyCommand(sLine); });
        AddCommand("ShowKey", t_d("<target>"), t_d("Show encryption key"), [this](const CString& sLine) { OnShowKeyCommand(sLine); });
        AddCommand("ListKeys", t_d("[full]"), t_d("List all keys"), [this](const CString& sLine) { OnListKeysCommand(sLine); });
        AddCommand("SetKeyFrom", t_d("<dest> <src>"), t_d("Copy key between targets"), [this](const CString& sLine) { OnSetKeyFromCommand(sLine); });
        AddCommand("SetMode", t_d("<target> ecb|cbc"), t_d("Set encryption mode"), [this](const CString& sLine) { OnSetModeCommand(sLine); });
        AddCommand("GetMode", t_d("<target>"), t_d("Get encryption mode"), [this](const CString& sLine) { OnGetModeCommand(sLine); });
        AddCommand("KeyX", t_d("<nick> [ecb|cbc]"), t_d("Key exchange with user"), [this](const CString& sLine) { OnKeyXCommand(sLine); });
        AddCommand("KeyXChan", t_d("<#chan> <nick> [ecb|cbc]"), t_d("Key exchange for channel"), [this](const CString& sLine) { OnKeyXChanCommand(sLine); });
        AddCommand("KeyXChanAll", t_d("<#chan> [ecb|cbc]"), t_d("Key exchange with all channel users"), [this](const CString& sLine) { OnKeyXChanAllCommand(sLine); });
        AddCommand("AutoKeyX", t_d("on|off"), t_d("Auto key exchange on first PM"), [this](const CString& sLine) { OnAutoKeyXCommand(sLine); });
        AddCommand("EncryptTopic", t_d("<#chan> on|off|status"), t_d("Per-channel topic encryption"), [this](const CString& sLine) { OnEncryptTopicCommand(sLine); });
        AddCommand("EncryptGlobalTopic", t_d("on|off|status"), t_d("Global topic encryption"), [this](const CString& sLine) { OnEncryptGlobalTopicCommand(sLine); });
        AddCommand("DisableTarget", t_d("<target> on|off"), t_d("Disable encryption for target"), [this](const CString& sLine) { OnDisableTargetCommand(sLine); });
        AddCommand("ProcessIncoming", t_d("on|off"), t_d("Process incoming messages"), [this](const CString& sLine) { OnProcessIncomingCommand(sLine); });
        AddCommand("ProcessOutgoing", t_d("on|off"), t_d("Process outgoing messages"), [this](const CString& sLine) { OnProcessOutgoingCommand(sLine); });
        AddCommand("EncryptNotice", t_d("on|off"), t_d("Encrypt notices"), [this](const CString& sLine) { OnEncryptNoticeCommand(sLine); });
        AddCommand("EncryptAction", t_d("on|off"), t_d("Encrypt actions (/me)"), [this](const CString& sLine) { OnEncryptActionCommand(sLine); });
        AddCommand("MarkIncoming", t_d("on|off"), t_d("Mark decrypted messages"), [this](const CString& sLine) { OnMarkIncomingCommand(sLine); });
        AddCommand("MarkIncomingTarget", t_d("<target> on|off"), t_d("Mark per target"), [this](const CString& sLine) { OnMarkIncomingTargetCommand(sLine); });
        AddCommand("MarkPos", t_d("prefix|suffix"), t_d("Marker position"), [this](const CString& sLine) { OnMarkPosCommand(sLine); });
        AddCommand("MarkStr", t_d("dec|enc|plain <text>"), t_d("Marker text"), [this](const CString& sLine) { OnMarkStrCommand(sLine); });
        AddCommand("MarkBroken", t_d("on|off"), t_d("Mark broken blocks"), [this](const CString& sLine) { OnMarkBrokenCommand(sLine); });
        AddCommand("PlainPrefix", t_d("<prefix|off>"), t_d("Plaintext prefix to skip encryption"), [this](const CString& sLine) { OnPlainPrefixCommand(sLine); });
        AddCommand("SelfTest", t_d("ecb|cbc <key> <text>"), t_d("Roundtrip encryption test"), [this](const CString& sLine) { OnSelfTestCommand(sLine); });
        AddCommand("SetConfig", t_d("<name> [value]"), t_d("Set config option"), [this](const CString& sLine) { OnSetConfigCommand(sLine); });
        AddCommand("ListConfig", "", t_d("List config options"), [this](const CString& sLine) { OnListConfigCommand(sLine); });
        AddCommand("Version", "", t_d("Show version"), [this](const CString& sLine) { OnVersionCommand(sLine); });
        AddCommand("Debug", t_d("on|off"), t_d("Show debug output in *fish window"), [this](const CString& sLine) { OnDebugCommand(sLine); });
        AddCommand("GetNickPrefix", "", t_d("Show current nick prefix"), [this](const CString& sLine) { OnGetNickPrefixCommand(sLine); });
        AddCommand("SetNickPrefix", t_d("[prefix]"), t_d("Set nick prefix (empty to disable)"), [this](const CString& sLine) { OnSetNickPrefixCommand(sLine); });
    }

    ~CFishMod() override = default;

    bool OnLoad(const CString& sArgs, CString& sMessage) override {
        for (const CModule* pMod : GetNetwork()->GetModules()) {
            if (pMod == this) continue;
            if (pMod->GetModName().Equals("crypt")) {
                sMessage = "Cannot load fish — crypt module is already active. "
                           "Unload crypt first, then load fish.";
                return false;
            }
        }

        MCString::iterator version = FindNV("version");
        if (version == EndNV()) {
            SetNV("config postfix_encrypted", "  \00312e\003");
            SetNV("config postfix_decrypted", "  \00304d\003");
            SetNV("version", "1");
        }
        return true;
    }

    void OnClientLogin() override {
        MCString::iterator ver = FindNV("version");
        if (ver == EndNV() || ver->second < "2") {
            if (!GetUser()->GetPass().empty()) {
                for (MCString::iterator it = BeginNV(); it != EndNV(); ++it) {
                    if (it->first.Left(4) == "key " && !it->second.StartsWith("$"))
                        SetNV(it->first, EncryptValue(it->second));
                }
            } else {
                bool has_keys = false;
                for (MCString::iterator it = BeginNV(); it != EndNV(); ++it) {
                    if (it->first.Left(4) == "key ") { has_keys = true; break; }
                }
                if (has_keys)
                    PutModule("No password set — FiSH encryption keys are stored in plaintext on disk.");
            }
            SetNV("version", "2");
        }
    }

    EModRet OnPrivNoticeMessage(CNoticeMessage &Message) override {
        CString sText = Message.GetText();
        CString command = sText.Token(0);
        CString sOtherPub_Key = sText.Token(1);
        CString sRemaining = sText.Token(2, true);
        LogDebug("OnPrivNoticeMessage: from=" + Message.GetNick().GetNick() + " cmd=" + command + " pub_key=" + sOtherPub_Key.Left(20));

        bool is_cbc_init = command.Equals("DH1080_INIT_CBC");
        bool is_init = command.Equals("DH1080_INIT") || is_cbc_init;

        if (is_init && !sOtherPub_Key.empty()) {
            LogDebug("DH1080_INIT received from " + Message.GetNick().GetNick() + " cbc_init=" + CString(is_cbc_init ? "yes" : "no"));
            CString sPriv_Key, sPub_Key, sSecretKey;
            bool use_cbc = is_cbc_init || sRemaining.Contains("CBC");
            sOtherPub_Key.TrimSuffix("A"); /* FiSH10 compat */
            DH1080_gen(sPriv_Key, sPub_Key);
            if (!DH1080_comp(sPriv_Key, sOtherPub_Key, sSecretKey)) {
                PutModule("Error in DH1080 with " + Message.GetNick().GetNick() + ": " + sSecretKey);
                return CONTINUE;
            }
            PutModule("Received DH1080 public key from " + Message.GetNick().GetNick() + ", sending mine...");
            CString response = "DH1080_FINISH " + sPub_Key + "A"; /* FiSH10 compat */
            if (use_cbc) response += " CBC";
            PutIRC("NOTICE " + Message.GetNick().GetNick() + " :" + response);
            CString nvkey = (use_cbc ? "CBC:" : "ECB:") + sSecretKey;
            LogDebug("DH1080_INIT: storing key for " + Message.GetNick().GetNick() + " prefix=" + CString(use_cbc ? "CBC:" : "ECB:") + " secret=" + sSecretKey.Left(20));
            SetEncryptedNV("key " + Message.GetNick().GetNick().AsLower(), nvkey);
            PutModule("Key for " + Message.GetNick().GetNick() + " successfully set.");
            if (!use_cbc)
                PutModule("Warning: ECB mode is less secure than CBC.");
            return HALT;
        } else if (command.Equals("DH1080_FINISH") && !sOtherPub_Key.empty()) {
            LogDebug("DH1080_FINISH received from " + Message.GetNick().GetNick());
            CString sPriv_Key, sSecretKey;
            map<CString, SKeyExchangeState>::iterator it = m_msKeyExchange.find(Message.GetNick().GetNick().AsLower());
            if (it == m_msKeyExchange.end()) {
                /* Already have a key? This is a confirmation FINISH from the peer. */
                if (FindNV("key " + Message.GetNick().GetNick().AsLower()) != EndNV())
                    return HALT;
                PutModule("Received unexpected DH1080_FINISH from " + Message.GetNick().GetNick() + ".");
            } else {
                sOtherPub_Key.TrimSuffix("A"); /* FiSH10 compat */
                sPriv_Key = it->second.privkey;
                if (DH1080_comp(sPriv_Key, sOtherPub_Key, sSecretKey)) {
                    CString nvkey = (it->second.cbc_mode ? "CBC:" : "ECB:") + sSecretKey;
                    SetEncryptedNV("key " + Message.GetNick().GetNick().AsLower(), nvkey);
                    PutModule("Key for " + Message.GetNick().GetNick() + " successfully set.");
                    m_msKeyExchange.erase(Message.GetNick().GetNick().AsLower());
                }
            }
            return HALT;
        } else {
            if (ShouldProcessIncoming()) {
                FilterIncoming(Message.GetNick().GetNick(), Message.GetNick(), sText);
                Message.SetText(sText);
            }
        }
        return CONTINUE;
    }

    EModRet OnChanNoticeMessage(CNoticeMessage &Message) override {
        CString sText = Message.GetText();
        if (ShouldProcessIncoming())
            FilterIncoming(Message.GetChan()->GetName(), Message.GetNick(), sText);
        Message.SetText(sText);
        return CONTINUE;
    }

    EModRet OnUserTextMessage(CTextMessage &Message) override {
        CString sTarget = Message.GetTarget().TrimLeft_n(NickPrefix());
        CString sMessage = Message.GetText();
        LogDebug("OnUserTextMessage: target=" + sTarget + " text_start=\"" + sMessage.Left(30) + "\"");

        if (CheckSkipEncryption(sMessage, Message, "OnUserTextMessage"))
            return CONTINUE;
        if (!ShouldProcessOutgoing()) {
            LogDebug("OnUserTextMessage: ProcessOutgoing disabled");
            return CONTINUE;
        }

        CString result;
        if (TryDecryptClientEncrypted(sTarget, sMessage, result)) {
            CChan* pChan = GetNetwork()->FindChan(sTarget);
            CString sNickMask = GetNetwork()->GetIRCNick().GetNickMask();
            if (pChan && !(pChan->AutoClearChanBuffer())) {
                pChan->AddBuffer(":" + NickPrefix() + _NAMEDFMT(sNickMask) + " PRIVMSG " + _NAMEDFMT(sTarget) + " :{text}", result);
                GetUser()->PutUser(":" + NickPrefix() + sNickMask + " PRIVMSG " + sTarget + " :" + result, nullptr, GetClient());
            }
            PutIRC("PRIVMSG " + sTarget + " :" + sMessage);
            RelayToClients(sTarget, result, "PRIVMSG");
            return HALTCORE;
        }
        if (sMessage.Left(4) == "+OK " || sMessage.Left(5) == "mcps ")
            return CONTINUE;

        CChan* pChan = GetNetwork()->FindChan(sTarget);
        CString sNickMask = GetNetwork()->GetIRCNick().GetNickMask();
        if (pChan && !(pChan->AutoClearChanBuffer())) {
            pChan->AddBuffer(":" + NickPrefix() + _NAMEDFMT(sNickMask) + " PRIVMSG " + _NAMEDFMT(sTarget) + " :{text}", sMessage);
            GetUser()->PutUser(":" + NickPrefix() + sNickMask + " PRIVMSG " + sTarget + " :" + sMessage, nullptr, GetClient());
        }

        SendEncryptedChunks(sTarget, sMessage, "PRIVMSG");

        if (IsMarkIncoming() || IsMarkIncomingTarget(sTarget)) {
            CString m = MarkStr("enc");
            if (MarkPos().Equals("suffix"))
                sMessage = sMessage + " " + m;
            else
                sMessage = m + " " + sMessage;
        }

        RelayToClients(sTarget, sMessage, "PRIVMSG");
        return HALTCORE;
    }

    EModRet OnUserActionMessage(CActionMessage &Message) override {
        if (!ShouldEncryptAction()) {
            LogDebug("OnUserActionMessage: EncryptAction disabled");
            return CONTINUE;
        }
        CString sTarget = Message.GetTarget().TrimLeft_n(NickPrefix());
        CString sMessage = Message.GetText();
        LogDebug("OnUserActionMessage: target=" + sTarget + " text=\"" + sMessage.Left(30) + "\"");

        if (CheckSkipEncryption(sMessage, Message, "OnUserActionMessage"))
            return CONTINUE;

        CString result;
        if (TryDecryptClientEncrypted(sTarget, sMessage, result)) {
            PutIRC("PRIVMSG " + sTarget + " :\001ACTION " + sMessage + "\001");
            RelayToClients(sTarget, result, "PRIVMSG", "\001ACTION ", "\001");
            return HALTCORE;
        }
        if (sMessage.Left(4) == "+OK " || sMessage.Left(5) == "mcps ")
            return CONTINUE;

        SendEncryptedChunks(sTarget, sMessage, "PRIVMSG", "\001ACTION ", "\001");
        RelayToClients(sTarget, sMessage, "PRIVMSG", "\001ACTION ", "\001");
        return HALTCORE;
    }

    EModRet OnUserNoticeMessage(CNoticeMessage &Message) override {
        if (!ShouldEncryptNotice()) {
            DEBUG_FISH("OnUserNoticeMessage: EncryptNotice disabled");
            return CONTINUE;
        }
        CString sTarget = Message.GetTarget().TrimLeft_n(NickPrefix());
        CString sMessage = Message.GetText();
        DEBUG_FISH("OnUserNoticeMessage: target=" << sTarget << " text_start=\"" << sMessage.Left(30) << "\"");

        if (CheckSkipEncryption(sMessage, Message, "OnUserNoticeMessage"))
            return CONTINUE;

        CString result;
        if (TryDecryptClientEncrypted(sTarget, sMessage, result)) {
            PutIRC("NOTICE " + sTarget + " :" + sMessage);
            RelayToClients(sTarget, result, "NOTICE");
            return HALTCORE;
        }
        if (sMessage.Left(4) == "+OK " || sMessage.Left(5) == "mcps ")
            return CONTINUE;

        CChan *pChan = GetNetwork()->FindChan(sTarget);
        if (pChan && !(pChan->AutoClearChanBuffer())) {
            pChan->AddBuffer(":" + GetNetwork()->GetIRCNick().GetNickMask() + " NOTICE " + sTarget + " :" + sMessage);
        }

        SendEncryptedChunks(sTarget, sMessage, "NOTICE");
        RelayToClients(sTarget, sMessage, "NOTICE");
        return HALTCORE;
    }

    EModRet OnUserTopicMessage(CTopicMessage &Message) override {
        CString sChannel = Message.GetTarget().TrimLeft_n(NickPrefix());
        CString sTopic = Message.GetTopic();

        if (sTopic.Left(4) == "+OK " || sTopic.Left(5) == "mcps ")
            return CONTINUE;

        if (!sTopic.empty() && ShouldEncryptTopic(sChannel)) {
            CString sEncrypted = EncryptForTarget(sChannel, sTopic);
            if (!sEncrypted.empty()) sTopic = sEncrypted;
        }
        Message.SetTopic(sTopic);
        return CONTINUE;
    }

    EModRet OnPrivTextMessage(CTextMessage &Message) override {
        LogDebug("OnPrivTextMessage: from=" + Message.GetNick().GetNick() + " text=\"" + Message.GetText().Left(20) + "\"");
        CString sMsg = Message.GetText();
        if (ShouldProcessIncoming()) FilterIncoming(Message.GetNick().GetNick(), Message.GetNick(), sMsg);
        Message.SetText(sMsg);
        return CONTINUE;
    }

    EModRet OnChanTextMessage(CTextMessage &Message) override {
        LogDebug("OnChanTextMessage: from=" + Message.GetNick().GetNick() + " chan=" + Message.GetChan()->GetName() + " text=\"" + Message.GetText().Left(20) + "\"");
        CString sMsg = Message.GetText();
        if (ShouldProcessIncoming()) FilterIncoming(Message.GetChan()->GetName(), Message.GetNick(), sMsg);
        Message.SetText(sMsg);
        return CONTINUE;
    }

    EModRet OnPrivActionMessage(CActionMessage &Message) override {
        LogDebug("OnPrivActionMessage: from=" + Message.GetNick().GetNick() + " text=\"" + Message.GetText().Left(20) + "\"");
        CString sMsg = Message.GetText();
        if (ShouldProcessIncoming()) FilterIncoming(Message.GetNick().GetNick(), Message.GetNick(), sMsg);
        Message.SetText(sMsg);
        return CONTINUE;
    }

    EModRet OnChanActionMessage(CActionMessage &Message) override {
        LogDebug("OnChanActionMessage: from=" + Message.GetNick().GetNick() + " chan=" + Message.GetChan()->GetName() + " text=\"" + Message.GetText().Left(20) + "\"");
        CString sMsg = Message.GetText();
        if (ShouldProcessIncoming()) FilterIncoming(Message.GetChan()->GetName(), Message.GetNick(), sMsg);
        Message.SetText(sMsg);
        return CONTINUE;
    }

    EModRet OnTopicMessage(CTopicMessage &Message) override {
        LogDebug("OnTopicMessage: from=" + Message.GetNick().GetNick() + " chan=" + Message.GetChan()->GetName() + " topic=\"" + Message.GetTopic().Left(20) + "\"");
        CString sTopic = Message.GetTopic();
        if (ShouldProcessIncoming()) FilterIncoming(Message.GetChan()->GetName(), Message.GetNick(), sTopic);
        Message.SetTopic(sTopic);
        return CONTINUE;
    }

    EModRet OnNumericMessage(CNumericMessage& Message) override {
        if (Message.GetCode() == 332) {
            CChan* pChan = GetNetwork()->FindChan(Message.GetParam(1));
            if (pChan) {
                CNick Nick(Message.GetParam(0));
                CString sTopic = Message.GetParam(2);
                if (ShouldProcessIncoming()) FilterIncoming(pChan->GetName(), Nick, sTopic);
                Message.SetParam(1, pChan->GetName());
                VCString vsParams;
                vsParams.push_back(pChan->GetName());
                vsParams.push_back(sTopic);
                Message.SetParams(vsParams);
            }
        }
        return CONTINUE;
    }

private:
    friend class CKeyExchangeTimer;
    void TryDecrypt(const CString& sTarget, const CString& sKey, EFishMode mode, const CString& raw_msg, CString& out_result, EFishMode& out_mode, bool& out_ok) {
        out_ok = false;
        LogDebug("TryDecrypt: target=" + sTarget + " mode=" + CString(mode == ModeCBC ? "CBC" : "ECB") + " raw=" + raw_msg.Left(30));

        /* Try CBC first (starts with +OK *...) */
        if (raw_msg.Left(5) == "+OK *" || mode == ModeCBC) {
            CString to_decode = raw_msg;
            if (to_decode.Left(5) == "+OK *") to_decode.LeftChomp(5);
            LogDebug("TryDecrypt: trying CBC with \"" + to_decode.Left(30) + "\"");
            char* dec = decrypts_cbc(sKey.c_str(), to_decode.c_str());
            if (dec) {
                out_result = CString(dec);
                free(dec);
                out_mode = ModeCBC;
                out_ok = true;
                LogDebug("TryDecrypt: CBC success result=\"" + out_result + "\"");
                return;
            }
            LogDebug("TryDecrypt: CBC failed");
        }

        /* Try ECB */
        if (raw_msg.Left(4) == "+OK " || raw_msg.Left(5) == "mcps ") {
            CString to_decode = raw_msg;
            if (to_decode.Left(5) == "mcps ") to_decode.LeftChomp(5);
            else if (to_decode.Left(4) == "+OK ") to_decode.LeftChomp(4);
            LogDebug("TryDecrypt: trying ECB with \"" + to_decode.Left(30) + "\"");

            size_t msg_len = strlen(to_decode.c_str());
            if ((strspn(to_decode.c_str(), (const char *)B64) == msg_len) && msg_len >= 12) {
                if (msg_len % 12 != 0)
                    to_decode.RightChomp(msg_len % 12);

                char* dec = decrypts_fish(sKey.c_str(), to_decode.c_str());
                if (dec) {
                    out_result = CString(dec);
                    free(dec);
                    out_mode = ModeECB;
                    out_ok = true;
                    LogDebug("TryDecrypt: ECB success result=\"" + out_result + "\"");
                    return;
                }
            } else {
                LogDebug("TryDecrypt: ECB base64 validation failed msg_len=" + CString(msg_len));
            }
            LogDebug("TryDecrypt: ECB failed");
        }
    }

    void FilterIncoming(const CString &sTarget, CNick &Nick, CString &sMessage) {
        LogDebug("FilterIncoming: target=" + sTarget + " nick=" + Nick.GetNick() + " msg_start=\"" + sMessage.Left(30) + "\"");
        CString sRawKey = GetEncryptedNV("key " + sTarget.AsLower());
        if (sRawKey.empty()) {
            LogDebug("FilterIncoming: no key for " + sTarget);
            return;
        }
        if (IsDisabled(sTarget)) {
            LogDebug("FilterIncoming: " + sTarget + " is disabled");
            return;
        }

        bool is_encrypted = sMessage.Left(4) == "+OK " || sMessage.Left(5) == "mcps ";
        LogDebug("FilterIncoming: is_encrypted=" + CString(is_encrypted ? "yes" : "no"));
        if (!is_encrypted) {
            LogDebug("FilterIncoming: message not encrypted");
            if (IsMarkIncoming() || IsMarkIncomingTarget(sTarget)) {
                CString m = MarkStr("plain");
                if (MarkPos().Equals("suffix"))
                    sMessage = sMessage + " " + m;
                else
                    sMessage = m + " " + sMessage;
            }
            return;
        }

        CString sKey;
        EFishMode stored_mode;
        ParseKey(sRawKey, sKey, stored_mode);
        LogDebug("FilterIncoming: parsed_key_len=" + CString(sKey.length()) + " mode=" + CString(stored_mode == ModeCBC ? "CBC" : "ECB"));

        CString stored_mode_str = GetModeNV(sTarget);
        if (stored_mode_str.Equals("ecb")) stored_mode = ModeECB;
        else if (stored_mode_str.Equals("cbc")) stored_mode = ModeCBC;
        LogDebug("FilterIncoming: stored_mode=\"" + stored_mode_str + "\" effective=" + CString(stored_mode == ModeCBC ? "CBC" : "ECB"));

        CString result;
        EFishMode used_mode;
        bool ok = false;

        /* Try configured mode first */
        if (stored_mode == ModeCBC && sMessage.Left(5) == "+OK *") {
            TryDecrypt(sTarget, sKey, ModeCBC, sMessage, result, used_mode, ok);
            if (!ok)
                TryDecrypt(sTarget, sKey, ModeECB, sMessage, result, used_mode, ok);
        } else {
            TryDecrypt(sTarget, sKey, ModeECB, sMessage, result, used_mode, ok);
            if (!ok)
                TryDecrypt(sTarget, sKey, ModeCBC, sMessage, result, used_mode, ok);
        }
        LogDebug("FilterIncoming: decrypt ok=" + CString(ok ? "yes" : "no") + " used_mode=" + CString(used_mode == ModeCBC ? "CBC" : "ECB") + " result=\"" + result.Left(40) + "\"");

        if (ok) {
            CString mode_str = (used_mode == ModeCBC) ? "cbc" : "ecb";
            if (!stored_mode_str.Equals(mode_str)) {
                LogDebug("FilterIncoming: updating stored mode from " + stored_mode_str + " to " + mode_str);
                SetModeNV(sTarget, mode_str);
            }

            if (IsMarkIncoming() || IsMarkIncomingTarget(sTarget)) {
                CString m = MarkStr("dec");
                if (MarkPos().Equals("suffix"))
                    result = result + " " + m;
                else
                    result = m + " " + result;
            }

            sMessage = result + GetNV("config postfix_encrypted");
            LogDebug("FilterIncoming: final_msg=\"" + sMessage.Left(60) + "\"");
        } else {
            LogDebug("FilterIncoming: all decrypt attempts failed");
            if (IsMarkIncoming() || IsMarkIncomingTarget(sTarget)) {
                CString m = MarkStr("plain");
                if (MarkPos().Equals("suffix"))
                    sMessage = sMessage + " " + m;
                else
                    sMessage = m + " " + sMessage;
            }
        }
    }

    CString DoEncrypt(const CString& sKey, EFishMode mode, const CString& sPlain) {
        LogDebug("DoEncrypt: mode=" + CString(mode == ModeCBC ? "CBC" : "ECB") + " plain=\"" + sPlain.Left(40) + "\"");
        if (mode == ModeCBC) {
            char* cbc = encrypts_cbc(sKey.c_str(), sPlain.c_str());
            if (!cbc) { LogDebug("DoEncrypt: encrypts_cbc failed"); return ""; }
            CString r = "+OK *" + CString(cbc);
            free(cbc);
            LogDebug("DoEncrypt: CBC result=\"" + r.Left(40) + "\"");
            return r;
        }
        char* cMsg = encrypts_fish(sKey.c_str(), sPlain.c_str());
        if (!cMsg) { LogDebug("DoEncrypt: encrypts_fish failed"); return ""; }
        CString r = "+OK " + CString(cMsg);
        free(cMsg);
        LogDebug("DoEncrypt: ECB result=\"" + r.Left(40) + "\"");
        return r;
    }

    CString EncryptForTarget(const CString& sTarget, const CString& sMessage) {
        CString sRawKey = GetEncryptedNV("key " + sTarget.AsLower());
        if (sRawKey.empty() || IsDisabled(sTarget)) {
            LogDebug("EncryptForTarget: no key or disabled for " + sTarget);
            return "";
        }

        CString sKey;
        EFishMode mode;
        ParseKey(sRawKey, sKey, mode);
        LogDebug("EncryptForTarget: target=" + sTarget + " key_len=" + CString(sKey.length()) + " mode=" + CString(mode == ModeCBC ? "CBC" : "ECB"));

        CString stored_mode = GetModeNV(sTarget);
        if (stored_mode.Equals("ecb")) mode = ModeECB;
        else if (stored_mode.Equals("cbc")) mode = ModeCBC;
        LogDebug("EncryptForTarget: stored_mode=\"" + stored_mode + "\" final_mode=" + CString(mode == ModeCBC ? "CBC" : "ECB"));

        return DoEncrypt(sKey, mode, sMessage);
    }

    void SendEncryptedChunks(const CString& sTarget, const CString& sMessage,
                              const CString& sIrcCmd,
                              const CString& sActPrefix = "",
                              const CString& sActSuffix = "") {
        size_t max = 300;
        size_t len = sMessage.length();
        if (len <= max) {
            CString enc = EncryptForTarget(sTarget, sMessage);
            if (!enc.empty())
                PutIRC(sIrcCmd + " " + sTarget + " :" + sActPrefix + enc + sActSuffix);
            else
                PutIRC(sIrcCmd + " " + sTarget + " :" + sActPrefix + sMessage + sActSuffix);
            return;
        }
        size_t pos = 0;
        while (pos < len) {
            size_t chunk_len = std::min(max, len - pos);
            CString chunk(sMessage.c_str() + pos, chunk_len);
            CString enc = EncryptForTarget(sTarget, chunk);
            if (!enc.empty())
                PutIRC(sIrcCmd + " " + sTarget + " :" + sActPrefix + enc + sActSuffix);
            else
                PutIRC(sIrcCmd + " " + sTarget + " :" + sActPrefix + chunk + sActSuffix);
            pos += chunk_len;
        }
    }

    void RelayToClients(const CString& sTarget, const CString& sMessage,
                         const CString& sIrcCmd,
                         const CString& sActPrefix = "",
                         const CString& sActSuffix = "") {
        CString sFull = ":" + GetNetwork()->GetIRCNick().GetNickMask() + " " +
                        sIrcCmd + " " + sTarget + " :" +
                        sActPrefix + sMessage + sActSuffix;
        GetNetwork()->PutUser(sFull, nullptr, m_pClient);
        for (const auto& pClient : GetNetwork()->GetClients()) {
            if (pClient != GetClient())
                pClient->PutClient(sFull);
        }
    }

    /* Manual KV storage for compat */
    void SetNVKey(const CString& key, const CString& val) { SetNV(key, val); }
    CString GetNVKey(const CString& key) {
        MCString::iterator it = FindNV(key);
        return it != EndNV() ? it->second : "";
    }
    bool DelNVKey(const CString& key) { return DelNV(key); }

    void OnSetKeyCommand(const CString& sCommand) {
        CString sTarget = sCommand.Token(1);
        CString sKey = sCommand.Token(2, true);
        if (sTarget.empty() || sKey.empty()) {
            PutModule("Usage: SetKey <#chan|Nick> [CBC:|ECB:]<Key>");
            return;
        }
        SetEncryptedNV("key " + sTarget.AsLower(), sKey);
        PutModule("Set encryption key for [" + sTarget + "] to [" + sKey + "]");
    }

    void OnDelKeyCommand(const CString& sCommand) {
        CString sTarget = sCommand.Token(1);
        if (sTarget.empty()) {
            PutModule("Usage: DelKey <#chan|Nick>");
            return;
        }
        if (DelNV("key " + sTarget.AsLower())) {
            DelNV("mode_" + sTarget.AsLower());
            DelNV("disabled_" + sTarget.AsLower());
            PutModule("Target [" + sTarget + "] deleted");
        } else
            PutModule("Target [" + sTarget + "] not found");
    }

    void OnShowKeyCommand(const CString& sCommand) {
        CString sTarget = sCommand.Token(1);
        if (sTarget.empty()) {
            PutModule("Usage: ShowKey <#chan|Nick>");
            return;
        }
        {
            CString sShowKey = GetEncryptedNV("key " + sTarget.AsLower());
            if (!sShowKey.empty())
                PutModule("Target key is " + sShowKey);
            else
                PutModule("Target not found.");
        }
    }

    void OnListKeysCommand(const CString& sCommand) {
        if (BeginNV() == EndNV()) {
            PutModule("You have no encryption keys set.");
            return;
        }
        CTable Table;
        Table.AddColumn("Target");
        Table.AddColumn("Key");
        for (MCString::iterator it = BeginNV(); it != EndNV(); ++it) {
            if (it->first.Left(4) == "key ") {
                Table.AddRow();
                Table.SetCell("Target", it->first.LeftChomp_n(4));
                CString val = GetEncryptedNV(it->first);
                CString full = sCommand.Token(1).AsLower() == "full" ? val : val.Left(8) + "...";
                Table.SetCell("Key", full);
            }
        }
        PutModule(Table);
    }

    void OnSetKeyFromCommand(const CString& sCommand) {
        CString sDst = sCommand.Token(1);
        CString sSrc = sCommand.Token(2);
        if (sDst.empty() || sSrc.empty()) {
            PutModule("Usage: SetKeyFrom <destination> <source>");
            return;
        }
        CString sSrcKey = GetEncryptedNV("key " + sSrc.AsLower());
        if (sSrcKey.empty()) {
            PutModule("Source [" + sSrc + "] not found.");
            return;
        }
        SetEncryptedNV("key " + sDst.AsLower(), sSrcKey);
        PutModule("Copied key from [" + sSrc + "] to [" + sDst + "]");
    }

    void OnSetModeCommand(const CString& sCommand) {
        CString sTarget = sCommand.Token(1);
        CString sMode = sCommand.Token(2).AsLower();
        if (sTarget.empty() || (sMode != "ecb" && sMode != "cbc")) {
            PutModule("Usage: SetMode <target> ecb|cbc");
            return;
        }
        SetModeNV(sTarget, sMode);
        PutModule("Set mode for [" + sTarget + "] to " + sMode);
    }

    void OnGetModeCommand(const CString& sCommand) {
        CString sTarget = sCommand.Token(1);
        if (sTarget.empty()) {
            PutModule("Usage: GetMode <target>");
            return;
        }
        CString sRawKey = GetEncryptedNV("key " + sTarget.AsLower());
        if (sRawKey.empty()) {
            PutModule("No key for target [" + sTarget + "]");
            return;
        }
        CString stored_mode = GetModeNV(sTarget);
        if (stored_mode.empty()) {
            EFishMode m;
            CString k;
            ParseKey(sRawKey, k, m);
            stored_mode = (m == ModeCBC) ? "cbc" : "ecb";
        }
        PutModule("Mode for [" + sTarget + "] is " + stored_mode);
    }

    void OnKeyXCommand(const CString& sCommand) {
        CString sTarget = sCommand.Token(1);
        if (sTarget.empty()) {
            PutModule("Usage: KeyX <Nick> [ecb|cbc]");
            return;
        }
        bool use_cbc = !sCommand.Token(2).AsLower().Equals("ecb");
        DEBUG_FISH("OnKeyXCommand: target=" << sTarget << " cbc=" << use_cbc);
        if (m_msKeyExchange.find(sTarget.AsLower()) != m_msKeyExchange.end()) {
            PutModule("Key exchange with " + sTarget + " already in progress.");
            return;
        }
        CString sPriv_Key, sPub_Key;
        DH1080_gen(sPriv_Key, sPub_Key);
        DEBUG_FISH("OnKeyXCommand: generated keys: pub_len=" << sPub_Key.length() << " priv_len=" << sPriv_Key.length());
        m_msKeyExchange.insert(make_pair(sTarget.AsLower(), SKeyExchangeState(time(NULL), sPriv_Key, use_cbc)));
        if (use_cbc) {
            PutIRC("NOTICE " + sTarget + " :DH1080_INIT " + sPub_Key + "A CBC");
            PutModule("Sent my DH1080 public key to " + sTarget + " (CBC mode), waiting for reply ...");
        } else {
            PutIRC("NOTICE " + sTarget + " :DH1080_INIT " + sPub_Key + "A");
            PutModule("Sent my DH1080 public key to " + sTarget + " (ECB mode), waiting for reply ...");
            PutModule("Warning: ECB mode is less secure than CBC.");
        }
        if (FindTimer("KeyExchangeTimer") == nullptr)
            AddTimer(new CKeyExchangeTimer(this));
    }

    void OnKeyXChanCommand(const CString& sCommand) {
        CString sChan = sCommand.Token(1);
        CString sTarget = sCommand.Token(2);
        CString sMode = sCommand.Token(3).AsLower();
        if (sChan.empty() || sTarget.empty()) {
            PutModule("Usage: KeyXChan <#chan> <Nick> [ecb|cbc]");
            return;
        }
        bool use_cbc = !sMode.Equals("ecb");
        if (m_msKeyExchange.find(sTarget.AsLower()) != m_msKeyExchange.end()) {
            PutModule("Key exchange with " + sTarget + " already in progress.");
            return;
        }
        CString sPriv_Key, sPub_Key;
        DH1080_gen(sPriv_Key, sPub_Key);
        m_msKeyExchange.insert(make_pair(sTarget.AsLower(), SKeyExchangeState(time(NULL), sPriv_Key, use_cbc)));
        if (use_cbc) {
            PutIRC("NOTICE " + sTarget + " :DH1080_INIT " + sPub_Key + "A CBC");
            PutModule("Sent my DH1080 public key to " + sTarget + " (CBC mode) for channel " + sChan + ", waiting for reply ...");
        } else {
            PutIRC("NOTICE " + sTarget + " :DH1080_INIT " + sPub_Key + "A");
            PutModule("Sent my DH1080 public key to " + sTarget + " (ECB mode) for channel " + sChan + ", waiting for reply ...");
            PutModule("Warning: ECB mode is less secure than CBC.");
        }
        if (FindTimer("KeyExchangeTimer") == nullptr)
            AddTimer(new CKeyExchangeTimer(this));
    }

    void OnKeyXChanAllCommand(const CString& sCommand) {
        CString sChan = sCommand.Token(1);
        CString sMode = sCommand.Token(2).AsLower();
        if (sChan.empty()) {
            PutModule("Usage: KeyXChanAll <#chan> [ecb|cbc]");
            return;
        }
        CChan *pChan = GetNetwork()->FindChan(sChan);
        if (!pChan) {
            PutModule("Channel [" + sChan + "] not found.");
            return;
        }
        bool use_cbc = !sMode.Equals("ecb");
        const map<CString, CNick>& users = pChan->GetNicks();
        unsigned int count = 0;
        for (map<CString, CNick>::const_iterator it = users.begin(); it != users.end(); ++it) {
            CString nick = it->first;
            if (nick.Equals(GetNetwork()->GetIRCNick().GetNick())) continue;
            if (m_msKeyExchange.find(nick.AsLower()) != m_msKeyExchange.end()) continue;
            CString sPriv_Key, sPub_Key;
            DH1080_gen(sPriv_Key, sPub_Key);
            m_msKeyExchange.insert(make_pair(nick.AsLower(), SKeyExchangeState(time(NULL), sPriv_Key, use_cbc)));
            if (use_cbc)
                PutIRC("NOTICE " + nick + " :DH1080_INIT " + sPub_Key + "A CBC");
            else
                PutIRC("NOTICE " + nick + " :DH1080_INIT " + sPub_Key + "A");
            count++;
        }
        if (!use_cbc)
            PutModule("Warning: ECB mode is less secure than CBC.");
        PutModule("Sent DH1080 init to " + CString(count) + " user(s) in " + sChan);
        if (FindTimer("KeyExchangeTimer") == nullptr)
            AddTimer(new CKeyExchangeTimer(this));
    }

    void OnAutoKeyXCommand(const CString& sCommand) {
        CString sVal = sCommand.Token(1).AsLower();
        if (sVal != "on" && sVal != "off") {
            PutModule("Usage: AutoKeyX on|off");
            return;
        }
        SetBoolNV("config autokeyx", sVal == "on");
        PutModule("Auto key exchange is now " + sVal);
    }

    void OnEncryptTopicCommand(const CString& sCommand) {
        CString sTarget = sCommand.Token(1);
        CString sVal = sCommand.Token(2).AsLower();
        if (sTarget.empty()) {
            PutModule("Usage: EncryptTopic <#chan> on|off|status");
            return;
        }
        if (sVal == "status") {
            MCString::iterator it = FindNV("topic_encrypt_" + sTarget.AsLower());
            CString status = (it != EndNV() && it->second == "on") ? "on" : "off";
            PutModule("Topic encryption for [" + sTarget + "] is " + status);
        } else if (sVal == "on" || sVal == "off") {
            SetNV("topic_encrypt_" + sTarget.AsLower(), sVal);
            PutModule("Topic encryption for [" + sTarget + "] set to " + sVal);
        } else {
            PutModule("Usage: EncryptTopic <#chan> on|off|status");
        }
    }

    void OnEncryptGlobalTopicCommand(const CString& sCommand) {
        CString sVal = sCommand.Token(1).AsLower();
        if (sVal == "status") {
            CString status = GetBoolNV("config global_topic_encrypt", false) ? "on" : "off";
            PutModule("Global topic encryption is " + status);
        } else if (sVal == "on" || sVal == "off") {
            SetBoolNV("config global_topic_encrypt", sVal == "on");
            PutModule("Global topic encryption set to " + sVal);
        } else {
            PutModule("Usage: EncryptGlobalTopic on|off|status");
        }
    }

    void OnDisableTargetCommand(const CString& sCommand) {
        CString sTarget = sCommand.Token(1);
        CString sVal = sCommand.Token(2).AsLower();
        if (sTarget.empty() || (sVal != "on" && sVal != "off")) {
            PutModule("Usage: DisableTarget <#chan|Nick> on|off");
            return;
        }
        SetNV("disabled_" + sTarget.AsLower(), sVal);
        PutModule("Disabled target [" + sTarget + "] set to " + sVal);
    }

    void OnProcessIncomingCommand(const CString& sCommand) {
        CString sVal = sCommand.Token(1).AsLower();
        if (sVal != "on" && sVal != "off") {
            PutModule("Usage: ProcessIncoming on|off");
            return;
        }
        SetBoolNV("config process_incoming", sVal == "on");
        PutModule("Incoming message processing is now " + sVal);
    }

    void OnProcessOutgoingCommand(const CString& sCommand) {
        CString sVal = sCommand.Token(1).AsLower();
        if (sVal != "on" && sVal != "off") {
            PutModule("Usage: ProcessOutgoing on|off");
            return;
        }
        SetBoolNV("config process_outgoing", sVal == "on");
        PutModule("Outgoing message processing is now " + sVal);
    }

    void OnEncryptNoticeCommand(const CString& sCommand) {
        CString sVal = sCommand.Token(1).AsLower();
        if (sVal != "on" && sVal != "off") {
            PutModule("Usage: EncryptNotice on|off");
            return;
        }
        SetBoolNV("config encrypt_notice", sVal == "on");
        PutModule("Notice encryption is now " + sVal);
    }

    void OnEncryptActionCommand(const CString& sCommand) {
        CString sVal = sCommand.Token(1).AsLower();
        if (sVal != "on" && sVal != "off") {
            PutModule("Usage: EncryptAction on|off");
            return;
        }
        SetBoolNV("config encrypt_action", sVal == "on");
        PutModule("Action encryption is now " + sVal);
    }

    void OnMarkIncomingCommand(const CString& sCommand) {
        CString sVal = sCommand.Token(1).AsLower();
        if (sVal != "on" && sVal != "off") {
            PutModule("Usage: MarkIncoming on|off");
            return;
        }
        SetBoolNV("config mark_incoming", sVal == "on");
        PutModule("Incoming marking is now " + sVal);
    }

    void OnMarkIncomingTargetCommand(const CString& sCommand) {
        CString sTarget = sCommand.Token(1);
        CString sVal = sCommand.Token(2).AsLower();
        if (sTarget.empty() || (sVal != "on" && sVal != "off")) {
            PutModule("Usage: MarkIncomingTarget <target> on|off");
            return;
        }
        SetNV("mark_target_" + sTarget.AsLower(), sVal);
        PutModule("Marking for [" + sTarget + "] set to " + sVal);
    }

    void OnMarkPosCommand(const CString& sCommand) {
        CString sVal = sCommand.Token(1).AsLower();
        if (sVal != "prefix" && sVal != "suffix") {
            PutModule("Usage: MarkPos prefix|suffix");
            return;
        }
        SetNV("config mark_pos", sVal);
        PutModule("Marker position set to " + sVal);
    }

    void OnMarkStrCommand(const CString& sCommand) {
        CString sType = sCommand.Token(1).AsLower();
        CString sVal = sCommand.Token(2, true);
        if (sType != "dec" && sType != "enc" && sType != "plain") {
            PutModule("Usage: MarkStr dec|enc|plain <text>");
            return;
        }
        SetNV("config mark_str_" + sType, sVal);
        PutModule("Marker text for " + sType + " set to [" + sVal + "]");
    }

    void OnMarkBrokenCommand(const CString& sCommand) {
        CString sVal = sCommand.Token(1).AsLower();
        if (sVal != "on" && sVal != "off") {
            PutModule("Usage: MarkBroken on|off");
            return;
        }
        SetBoolNV("config mark_broken", sVal == "on");
        PutModule("Broken block marking is now " + sVal);
    }

    void OnPlainPrefixCommand(const CString& sCommand) {
        CString sVal = sCommand.Token(1, true);
        if (sVal.empty() || sVal.Equals("off")) {
            SetNV("config plain_prefix", "");
            PutModule("Plain prefix disabled");
        } else {
            SetNV("config plain_prefix", sVal);
            PutModule("Plain prefix set to [" + sVal + "]");
        }
    }

    void OnSelfTestCommand(const CString& sCommand) {
        CString sMode = sCommand.Token(1).AsLower();
        CString sKey = sCommand.Token(2);
        CString sText = sCommand.Token(3, true);
        if (sMode != "ecb" && sMode != "cbc") {
            PutModule("Usage: SelfTest <ecb|cbc> <key> <text>");
            return;
        }
        if (sKey.empty() || sText.empty()) {
            PutModule("Usage: SelfTest <ecb|cbc> <key> <text>");
            return;
        }

        bool use_cbc = (sMode == "cbc");
        char* enc = nullptr;
        char* dec = nullptr;
        CString enc_str;

        if (use_cbc) {
            enc = encrypts_cbc(sKey.c_str(), sText.c_str());
            if (!enc) { PutModule("SelfTest: encryption failed (CBC)"); return; }
            enc_str = "+OK *" + CString(enc);
            CString b64 = CString(enc);
            dec = decrypts_cbc(sKey.c_str(), b64.c_str());
        } else {
            enc = encrypts_fish(sKey.c_str(), sText.c_str());
            if (!enc) { PutModule("SelfTest: encryption failed (ECB)"); return; }
            enc_str = "+OK " + CString(enc);
            dec = decrypts_fish(sKey.c_str(), enc);
        }

        if (!dec) {
            PutModule("SelfTest: encryption OK but decryption FAILED");
            PutModule("  Encrypted: " + enc_str);
            free(enc);
            return;
        }

        CString dec_str(dec);
        if (dec_str.Equals(sText)) {
            PutModule("SelfTest: OK (" + sMode + ")");
            PutModule("  Original: " + sText);
            PutModule("  Encrypted: " + enc_str);
        } else {
            PutModule("SelfTest: MISMATCH (" + sMode + ")");
            PutModule("  Original: " + sText);
            PutModule("  Encrypted: " + enc_str);
            PutModule("  Decrypted: " + dec_str);
        }
        free(enc);
        free(dec);
    }

    void OnSetConfigCommand(const CString& sCommand) {
        CString sName = sCommand.Token(1);
        CString sValue = sCommand.Token(2, true);
        if (sName.empty()) {
            PutModule("Usage: SetConfig <Name> [Value]");
            return;
        }
        if (!sValue.empty()) {
            SetNV("config " + sName.AsLower(), sValue);
            PutModule("Set config option [" + sName + "] to [" + sValue + "]");
        } else {
            SetNV("config " + sName.AsLower(), "");
            PutModule("Set config option [" + sName + "] to nothing (disabled)");
        }
    }

    void OnListConfigCommand(const CString&) {
        for (MCString::iterator it = BeginNV(); it != EndNV(); ++it) {
            if (it->first.Left(7) == "config ")
                PutModule(it->first.LeftChomp_n(7) + " : \"" + it->second + "\"");
        }
    }

    void OnGetNickPrefixCommand(const CString&) {
        CString sPrefix = NickPrefix();
        if (sPrefix.empty())
            PutModule("Nick prefix disabled.");
        else
            PutModule("Nick prefix: \"" + sPrefix + "\"");
    }

    void OnSetNickPrefixCommand(const CString& sCommand) {
        CString sPrefix = sCommand.Token(1);
        if (sPrefix.StartsWith(":")) {
            PutModule("You cannot use : as nick prefix.");
            return;
        }
        CString sStatusPrefix = GetUser()->GetStatusPrefix();
        size_t sp = sStatusPrefix.size();
        size_t np = sPrefix.size();
        size_t min = std::min(sp, np);
        if (min > 0 && sStatusPrefix.CaseCmp(sPrefix, min) == 0) {
            PutModule("Overlap with status prefix (" + sStatusPrefix + "), this nick prefix will not be used.");
            return;
        }
        SetNV(NICK_PREFIX_KEY, sPrefix);
        if (sPrefix.empty())
            PutModule("Nick prefix disabled.");
        else
            PutModule("Nick prefix set to \"" + sPrefix + "\".");
    }

    void OnDebugCommand(const CString& sCommand) {
        CString sVal = sCommand.Token(1).AsLower();
        if (sVal != "on" && sVal != "off") {
            PutModule("Usage: Debug on|off  (current: " + CString(IsDebug() ? "on" : "off") + ")");
            return;
        }
        SetBoolNV("config debug", sVal == "on");
        PutModule("Debug output is now " + sVal + " (shown in this window)");
    }

    void OnVersionCommand(const CString&) {
        PutModule("ZNC-FiSH v" + CString(MODVERSION) + " by " + CString(MODAUTHOR));
        PutModule("Description: " + CString(MODDESC));
        PutModule(CString(SSLeay_version(SSLEAY_VERSION)));
        PutModule("URL: " + CString(MODURL));
    }

    void DelStaleKeyExchanges(time_t iTime) {
        vector<CString> to_remove;
        for (map<CString, SKeyExchangeState>::iterator it = m_msKeyExchange.begin(); it != m_msKeyExchange.end(); ++it) {
            if (iTime - 5 >= it->second.timestamp) {
                PutModule("Key exchange with " + it->first + " expired before completion.");
                to_remove.push_back(it->first);
            }
        }
        for (size_t i = 0; i < to_remove.size(); i++)
            m_msKeyExchange.erase(to_remove[i]);
        if (m_msKeyExchange.size() <= 0)
            RemTimer("KeyExchangeTimer");
    }

    void DH1080_gen(CString& sPriv_Key, CString& sPub_Key) {
        if (!m_bKeysGenerated) {
            if (!m_pDH) return;
            unsigned char raw_buf[200];
            unsigned long len;
            unsigned char *a, *b;
            BIGNUM *b_prime = NULL;
            BIGNUM *b_generator = NULL;

            initb64();
            if (!BN_hex2bn(&b_prime, prime1080)) return;
            if (!BN_dec2bn(&b_generator, "2")) { BN_clear_free(b_prime); return; }
            if (b_prime == NULL || b_generator == NULL || !DH_set0_pqg(m_pDH.get(), b_prime, nullptr, b_generator)) {
                BN_clear_free(b_prime);
                BN_clear_free(b_generator);
                return;
            }
            if (!DH_generate_key(m_pDH.get())) return;

            const BIGNUM *priv_key, *pub_key;
            DH_get0_key(m_pDH.get(), &pub_key, &priv_key);
            len = BN_num_bytes(priv_key);
            a = (unsigned char *)malloc(len);
            if (a) {
                BN_bn2bin(priv_key, a);
                memset(raw_buf, 0, 200);
                htob64((char *)a, (char *)raw_buf, len);
                m_sCachedPrivKey = CString((char *)raw_buf);
                free(a);
            }
            len = BN_num_bytes(pub_key);
            b = (unsigned char *)malloc(len);
            if (b) {
                BN_bn2bin(pub_key, b);
                memset(raw_buf, 0, 200);
                htob64((char *)b, (char *)raw_buf, len);
                m_sCachedPubKey = CString((char *)raw_buf);
                free(b);
            }
            m_bKeysGenerated = true;
        }
        sPriv_Key = m_sCachedPrivKey;
        sPub_Key = m_sCachedPubKey;
    }

    bool DH1080_comp(CString& sPriv_Key, CString& sOtherPub_Key, CString& sSecret_Key) {
        int len;
        unsigned char SHA256digest[32];
        char *key;
        BIGNUM *b_prime = NULL;
        BIGNUM *b_myPrivkey = NULL;
        BIGNUM *b_HisPubkey = NULL;
        BIGNUM *b_generator = NULL;
        unsigned char raw_buf[200];

        if (!BN_hex2bn(&b_prime, prime1080)) return false;
        if (!BN_dec2bn(&b_generator, "2")) { BN_clear_free(b_prime); return false; }

        std::unique_ptr<DH, decltype(&DH_free)> dh(DH_new(), DH_free);
        if (b_prime == NULL || b_generator == NULL || !DH_set0_pqg(dh.get(), b_prime, nullptr, b_generator)) {
            BN_clear_free(b_prime);
            BN_clear_free(b_generator);
            return false;
        }

        memset(raw_buf, 0, 200);
        len = b64toh((char *)sPriv_Key.c_str(), (char *)raw_buf);
        b_myPrivkey = BN_bin2bn(raw_buf, len, NULL);
        DH_set0_key(dh.get(), nullptr, b_myPrivkey);

        memset(raw_buf, 0, 200);
        len = b64toh((char *)sOtherPub_Key.c_str(), (char *)raw_buf);
        b_HisPubkey = BN_bin2bn(raw_buf, len, NULL);

        key = (char *)malloc(DH_size(dh.get()));
        if (!key) { BN_clear_free(b_HisPubkey); return false; }
        memset(key, 0, DH_size(dh.get()));
        if (!b_HisPubkey) { free(key); return false; }

        int dh_codes = 0;
        if (!DH_check_pub_key(dh.get(), b_HisPubkey, &dh_codes) || dh_codes != 0) {
            BN_clear_free(b_HisPubkey);
            free(key);
            return false;
        }

        len = DH_compute_key((unsigned char *)key, b_HisPubkey, dh.get());
        if (len == -1) {
            unsigned long err = ERR_get_error();
            DEBUG("** DH Error:" << ERR_error_string(err, nullptr));
            BN_clear_free(b_HisPubkey);
            free(key);
            sSecret_Key = CString(ERR_error_string(err, nullptr)).Token(4, true, ":");
            return false;
        }

        sha256_ctx c;
        sha256_init(&c);
        memset(SHA256digest, 0, 32);
        sha256_update(&c, (const unsigned char *)key, len);
        sha256_final(&c, SHA256digest);
        memset(raw_buf, 0, 200);
        len = htob64((char *)SHA256digest, (char *)raw_buf, 32);
        sSecret_Key = "";
        sSecret_Key.append((char *)raw_buf, len);
        sSecret_Key.TrimRight("="); /* FiSH10 compat */

        BN_clear_free(b_HisPubkey);
        free(key);
        return true;
    }

    map<CString, SKeyExchangeState> m_msKeyExchange;
    bool m_bKeysGenerated = false;
    CString m_sCachedPrivKey;
    CString m_sCachedPubKey;
};

void CKeyExchangeTimer::RunJob() {
    CFishMod *p = static_cast<CFishMod *>(m_pModule);
    p->DelStaleKeyExchanges(time(NULL));
}

template <>
void TModInfo<CFishMod>(CModInfo &Info) {
    Info.SetWikiPage(MODURL);
}

NETWORKMODULEDEFS(CFishMod, MODDESC)
#pragma GCC diagnostic pop
