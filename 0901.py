import copy
import hashlib

def main():
    print("main")
    
    params_n = 3
    
    seed = "cef8256742661ba3b1acb09a2fbca640abf1b072f1db84a888903ba0fff7e909"
    pub_seed = "040daf341a78f98c36a37b3571f3ab26eb80dc782a7273b270d0f8429b572c32"
    m = "b0d77406268a5aaf4535d948fd834c183d28a8f2a9ca4b41f5c2d513747a0966"
    addr = "85b5abb22a57f390302fc56c94762f852101df4c3c51b7749d49be7a414b6d9e"

    seed = bytes.fromhex(seed)
    
    pub_seed = bytes.fromhex(pub_seed)
    m = bytes.fromhex(m)
    addr = bytes.fromhex(addr)

    wots_pkgen(params_n, seed, pub_seed, addr)



def wots_pkgen(params_n, seed, pub_seed, addr):
    print("wots_pkgen")
    expand_seed(params_n, seed, pub_seed, addr)
    


def expand_seed(params_n, inseeds, pub_seed, addr):
    print("expand_seed")
    buf = bytearray(params_n + 32)
    addr = copy.copy(addr[:24] + bytearray(8))
    buf = copy.copy(pub_seed + buf[params_n:])
    #print(buf.hex())
    params_wots_len = 67

    outseeds = bytearray(0)

    for i in range(params_wots_len):
        addr = copy.copy(addr[:4*5] + i.to_bytes(4, 'little') + addr[4*6:])
        #print(addr.hex())
        buf = copy.copy(buf[:params_n] + (addr[0:4])[::-1] + (addr[4:8])[::-1]+ (addr[8:12])[::-1]+ (addr[12:16])[::-1]+ (addr[16:20])[::-1]+ (addr[20:24])[::-1]+ (addr[24:28])[::-1]+ (addr[28:32])[::-1])
        #print(buf.hex())
        outseeds = copy.copy(outseeds[:32*i] + prf_keygen(params_n, buf, inseeds))


def prf_keygen(params_n, in_data, key):
    print("prf_keygen")
    params_padding_len = 32
    XMSS_HASH_PADDING_PRF_KEYGEN = bytearray(28) + (4).to_bytes(4, 'little')
    #print(XMSS_HASH_PADDING_PRF_KEYGEN.hex())
    buf = bytearray(params_padding_len + 2 * params_n + 32)
    buf = copy.copy((XMSS_HASH_PADDING_PRF_KEYGEN[0:4])[::-1] + (XMSS_HASH_PADDING_PRF_KEYGEN[4:8])[::-1]+ (XMSS_HASH_PADDING_PRF_KEYGEN[8:12])[::-1]+ (XMSS_HASH_PADDING_PRF_KEYGEN[12:16])[::-1]+ (XMSS_HASH_PADDING_PRF_KEYGEN[16:20])[::-1]+ (XMSS_HASH_PADDING_PRF_KEYGEN[20:24])[::-1]+ (XMSS_HASH_PADDING_PRF_KEYGEN[24:28])[::-1]+ (XMSS_HASH_PADDING_PRF_KEYGEN[28:32])[::-1] + buf[params_padding_len:])
    buf = copy.copy(buf[:params_padding_len] + key[:params_n] + buf[params_padding_len + params_n:])
    buf = copy.copy(buf[:params_padding_len + params_n] + in_data[:params_n + 32])
    #print(buf.hex())

    hasher = hashlib.sha256()
    hasher.update(buf)
    hash_value = hasher.hexdigest()

    return bytes.fromhex(hash_value)

if __name__ == "__main__":
    main()
