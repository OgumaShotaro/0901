import copy
import hashlib

def main():
    print("main")
    
    params_n = 32

    seed    = "0cb909e41a7727d9a5410d465d5eaf856b3b3f2fc23ae15543acedf025befa5a"
    pub_seed= "d5c506c4218fe7a05059468dbaa4a8c11be625608a371a32d9c5b2265e6d37af"
    m       = "402dbcfedfdebb10dac57df5a72823c308f6aa272e78da05b86389863f74ac33"
    addr    = "d6c7362709933355a33a7dbb5940ddb5b15a15c0afe8f71313e9596649e9b199"

    seed = bytes.fromhex(seed)
    pub_seed = bytes.fromhex(pub_seed)
    m = bytes.fromhex(m)
    addr = bytes.fromhex(addr)

    wots_pkgen(params_n, seed, pub_seed, addr)

def wots_pkgen(params_n, seed, pub_seed, addr):
    #print("wots_pkgen")

    params_wots_len = 67
    params_wots_w = 16

    pk = expand_seed(params_n, seed, pub_seed, addr)
    after_pk = bytearray(0)
    
    for i in range(params_wots_len):
        addr = copy.copy(addr[:4*5] + i.to_bytes(4, 'little') + addr[4*6:])
        after_pk = copy.copy(after_pk[:i*params_n] + gen_chain(pk[i*params_n:i*params_n+32], 0, params_wots_w - 1, pub_seed, addr))

    #ここで公開鍵が完成
    print(after_pk.hex())

def expand_seed(params_n, inseeds, pub_seed, addr):
    #print("expand_seed")
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
    #print("prf_keygen")
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

def gen_chain(out_data, start, steps, pub_seed, addr):
    params_n = 32
    #print("gen_chain")
    #print(out_data[:32].hex())
    for i in range(steps):
        addr = copy.copy(addr[:4*6] + i.to_bytes(4, 'little') + addr[4*7:])
        out_data = thash_f(out_data, pub_seed, addr)

    return out_data


def thash_f(in_data, pub_seed, addr):
    #print("thash_f")

    params_n = 32
    params_padding_len = 32

    buf = bytearray(params_padding_len + 2 * params_n)
    bitmask = bytearray(params_n)
    addr_as_bytes = bytes(32)

    #xmss_hash_padding_f
    buf = copy.copy(buf[:params_padding_len] + buf[params_padding_len:])
    addr = copy.copy(addr[:28] + bytearray(4))
    addr_as_bytes = addr[0:4][::-1] + addr[4:8][::-1]+ addr[8:12][::-1]+ addr[12:16][::-1]+ addr[16:20][::-1]+ addr[20:24][::-1]+ addr[24:28][::-1]+ addr[28:32][::-1]
    #print(addr_as_bytes.hex())
    buf = copy.copy(buf[:params_n] + prf(addr_as_bytes, pub_seed) + buf[params_n + 32:])
    addr_as_bytes = addr[0:4][::-1] + addr[4:8][::-1]+ addr[8:12][::-1]+ addr[12:16][::-1]+ addr[16:20][::-1]+ addr[20:24][::-1]+ addr[24:28][::-1]+ (1).to_bytes(4, 'big')
    
    bitmask = copy.copy(prf(addr_as_bytes, pub_seed))

    for i in range(params_n):
        buf[params_padding_len + params_n + i] = in_data[i] ^ bitmask[i]

    hasher = hashlib.sha256()
    hasher.update(buf)
    hash_value = hasher.hexdigest()

    return bytes.fromhex(hash_value)



def prf(in_data, key):
    #print("prf")
    params_n = 32
    params_padding_len = 32
    buf = bytearray(params_padding_len + params_n + 32)
    XMSS_HASH_PADDING_F = bytearray(28) + (3).to_bytes(4, 'big')
    buf = copy.copy(XMSS_HASH_PADDING_F + key[:params_n] + in_data[:params_n])
    #print(buf.hex())
    hasher = hashlib.sha256()
    hasher.update(buf)
    hash_value = hasher.hexdigest()
    return bytes.fromhex(hash_value)




if __name__ == "__main__":
    main()
