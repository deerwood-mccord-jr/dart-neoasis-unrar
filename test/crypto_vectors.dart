/// Auto-generated reference vectors for the crypto port. Ground truth
/// comes from Python hashlib/hmac, the RARLAB-embedded PBKDF2 test vectors,
/// and real archives verified against unrar 7.23.
library;

List<int> hx(String s) => List<int>.generate(
    s.length ~/ 2, (i) => int.parse(s.substring(i * 2, i * 2 + 2), radix: 16));

final Map<String, String> sha1Vectors = {
 "empty": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
 "abc": "a9993e364706816aba3e25717850c26c9cd0d89d",
 "56": "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
 "long": "b35b87cf7ddbcf4c4d749cacd4d158093bd38db4"
};
final Map<String, String> sha256Vectors = {
 "empty": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
 "abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
 "56": "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
 "long": "eef860cfd151cf650d435896d54bd74303b34bbc4ee3135c7bd4e93821fdc6d7"
};
final Map<String, String> shaMessages = {
 "empty": "",
 "abc": "abc",
 "56": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
 "long": "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog again!The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog again!The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog again!"
};
final Map<String, String> hmacVectors = {
 "rfc1": "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
 "rfc2": "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
 "rfc3": "7d1bf2c6251b9c2263d5b86110e42a418fcfef4ca455a74a811ddb545e2fffa3",
 "k32": "1db98dd7ce99625446605eda104968c6b27c6a3753867b0cfdc633defced6919"
};
final Map<String, Map<String, String>> pbkdf2Vectors = {
 "c1": {
  "key": "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
  "v1": "ae4ee2d75b78ca4b52c833c7a2c46aa5afcda84910c816129180c7db94d12828",
  "v2": "8d0d186304625d4fdf487b4f929c0224d6e26bbd33a698e446fdb17e876f6975"
 },
 "c4096": {
  "key": "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
  "v1": "f5813aeb14cd6ad5a2714b4f82f277a5c9d3b5441199fd731cebf707eaf39f12",
  "v2": "9de7fbbc3868a043dd5a14e254be45a9afb7feaca0ce4f4a6e2713ff8e7bea7f"
 },
 "c65536": {
  "key": "080fa31d422db047839bce3a3bce4951e262b9ff762f57e9c47196ce4b6b6ebf",
  "v1": "62c33556fc0d8238ff9a11f7d1463dbf8eb384e2f5227a060224444a7647d0f7",
  "v2": "d85dd4f96fc85298a93e2af7cf0d6555b835856e11dce700604f7fad2808a119"
 }
};
final Map<String, dynamic> rar5DataVectors = {
 "salt": "5c2af988aba5e36862cd1a638c8aa3c7",
 "lg2": 15,
 "key": "c41b16251ce1f2097d128257879a59090e74d89ee35799a938bc7f6379911d6e",
 "hashKey": "ba94cad08bd0970a51bb55a1488190e377c031f110cc0fecbd03071a884a0642",
 "pswValue": "7c9c8ff84172de3f1cab626aa912fd65af9e4c8a234f25c29c102791d1a5f9bf",
 "fold": "53b986891a8aff27",
 "stored": "53b986891a8aff27"
};
final Map<String, dynamic> rar5HeadersVectors = {
 "salt": "c6c4197aeb8476e85e220dadb783bf59",
 "lg2": 15,
 "key": "543eaa01b5305e8f1d9cde83b903894e77f52c57c97fcd51df146e20d98cb276",
 "hashKey": "802645d0a67d988823a6e674d7edd56c4dcdb46a797ec594323eb53190a6ebc7",
 "pswValue": "66fb151ff5e91abe2f87a0d593ab56d746bd286ea581b7b8c0bb58db805d5183",
 "fold": "cf7ac57f439eaa52",
 "stored": "cf7ac57f439eaa52"
};
final Map<String, dynamic> rar3Fixture = {
 "password": "password",
 "salt": "b30e2f01101f65bd",
 "kdf3": [
  "a240160822889d4886f921b0416b6b41",
  "2fb796c4f0ec487f8350caf785ffe39a"
 ]
};
final Map<String, dynamic> rar4Crafted = {
 "password": "test123",
 "salt": "0102030405060708",
 "kdf3": [
  "0a04f81b56105448679a7ae9dacf9edc",
  "d873e0069c5f557ae6edeeee8d8bdb8f"
 ]
};
final Map<String, dynamic> aes128Vectors = {
 "key": "2b7e151628aed2a6abf7158809cf4f3c",
 "iv": "000102030405060708090a0b0c0d0e0f",
 "pt": "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
 "ct": "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
};
final Map<String, dynamic> aes256Vectors = {
 "key": "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
 "iv": "000102030405060708090a0b0c0d0e0f",
 "pt": "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
 "ct": "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"
};
