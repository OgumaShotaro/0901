import copy
import hashlib

def main():
    print("main")
    
    params_n = 32
    
    seed = "f7ca61b63ba522827ba7a75efe1d087fca7adbd26bd4546f9203231433eae07a"
    pub_seed = "1b8b8fc1fc6a00635c6086e4657ba0fb00bb809d5a78a730d2a797606f8eeaec"
    m = "c64f8f6e08ec73d1326f1abe53ded9f5ddcfa7b9a08eeb7b875f95e6c3c55356"
    addr = "d352b6cfe459d6b1c3e17c233308eb326fdf7e88726627387a3cc524bdff8677"

    seed = bytes.fromhex(seed)
    pub_seed = bytes.fromhex(pub_seed)
    m = bytes.fromhex(m)
    addr = bytes.fromhex(addr)

    wots_pkgen(params_n, seed, pub_seed, addr)

def wots_pkgen(params_n, seed, pub_seed, addr):
    print("wots_pkgen")

    params_wots_len = 67
    params_wots_w = 16

    pk = expand_seed(params_n, seed, pub_seed, addr)
    
    for i in range(params_wots_len):
        addr = copy.copy(addr[:4*5] + i.to_bytes(4, 'little') + addr[4*6:])
        gen_chain(pk[i*params_n:i*params_n+32], pk[i*params_n:i*params_n+32], 0, params_wots_w - 1, pub_seed, addr)

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

    return outseeds


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

def gen_chain(out_data, in_data, start, steps, pub_seed, addr):
    params_n = 32
    print("gen_chain")
    #print(out_data[:32].hex())
    for i in range(steps):
        addr = copy.copy(addr[:4*6] + i.to_bytes(4, 'little') + addr[4*7:])
        thash_f(out_data, out_data, pub_seed, addr)

def thash_f(out_data, in_data, pub_seed, addr):
    print("thash_f")

if __name__ == "__main__":
    main()
