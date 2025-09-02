import copy
import hashlib

def main():
    print("main")
    
    params_n = 32
    
    seed = "ce42e5150e1fc8685cb369b53a660852f40712d4c02e534c1f2426d200f57c04"
    pub_seed = "36a36813534b5b52fe74caa3eec4af3c1ebfcc8ed220eb2d155c279bef68f43e"
    m = "7b0b91ca708938c6d39ff5047f0e5e6b36a7e127fef60b23fa461d6239836e86"
    addr = "ae5976db492411b1b8c64385f5cd65685d425ed88b1d83755d49bded892c09ad"

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
    buf = copy.copy(buf[:params_n] + prf(buf[params_padding_len:], addr_as_bytes, pub_seed) + buf[params_n + 32:])
    print(buf.hex())
    print()


def prf(out_data, in_data, key):
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
