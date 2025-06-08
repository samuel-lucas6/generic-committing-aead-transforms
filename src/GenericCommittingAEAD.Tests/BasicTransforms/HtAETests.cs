using GenericCommittingAeadTransforms;
using System.Security.Cryptography;

namespace GenericCommittingAEAD.Tests;

[TestClass]
public class HtAETests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "19a00fe1c949fb8978ca01f491050a5929312cd84fb64ed005d33ae7fa7547769f503f1750c2b3169bf90e0d11454d9f705dea9f47f4b7e41479e469ed81522bf7705942d785074102b2de1f8630e0e3b4344d2b624aa61d94255bf07975207811d1aa9e3a841aa174297d8d74b9b872fec3680560dd9f76ff69b2052cc03dded6da578de1daf47f2a21e4e7372811739277810d468992bfa40eb713fc68d691260b",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        ];
        yield return
        [
            "50c5ae9a227a5647fa3949c858ad2d2e2bc3e94633706953d3086b5b5f95ff30b457b4f0f03295508a7aa431101bd8a30685639c5f820702e3b8e5e47be4b5ca4e02a8d94bb0af3238b892fd4a74364bed7ad41d50bf4b16d8e4e3bd44a38a2c591ec7690f8ae6bffcf8662fffc30ffe69e1e440023e0e06a950e1a43f6a1a6fb61b85d56057a1925a9eca061646f11b1dc0bff69447b0477f7d3be2f713c0de61c30f1eef15c9e1fa4ae196df0d072c19678e73761b37fcd929bfe82c44206c6ac2204187402d52efcf8d0e8513a0ece3dfe8beca90f96de5309e46206a721fe03b74b3ac832a39070fd91e4605918bcab85571fca9fcf87fff4c08245cd9aa86b257e6c635bc29ac7538c9b9063dd4ef9a7f17bab23343050c67a40e36afbc4ddb59b7a3e8eb5408c6efb51ecc9096f4d83dd771728d481a",
            "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d",
            "000000000102030405060708",
            "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
            "f33388860000000000004e91"
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [HtAE.TagSize + HtAE.CommitmentSize - 1, 0, HtAE.NonceSize, HtAE.KeySize, HtAE.TagSize];
        yield return [HtAE.TagSize + HtAE.CommitmentSize, 1, HtAE.NonceSize, HtAE.KeySize, HtAE.TagSize];
        yield return [HtAE.TagSize + HtAE.CommitmentSize, 0, HtAE.NonceSize + 1, HtAE.KeySize, HtAE.TagSize];
        yield return [HtAE.TagSize + HtAE.CommitmentSize, 0, HtAE.NonceSize - 1, HtAE.KeySize, HtAE.TagSize];
        yield return [HtAE.TagSize + HtAE.CommitmentSize, 0, HtAE.NonceSize, HtAE.KeySize + 1, HtAE.TagSize];
        yield return [HtAE.TagSize + HtAE.CommitmentSize, 0, HtAE.NonceSize, HtAE.KeySize - 1, HtAE.TagSize];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, HtAE.KeySize);
        Assert.AreEqual(12, HtAE.NonceSize);
        Assert.AreEqual(16, HtAE.TagSize);
        Assert.AreEqual(32, HtAE.CommitmentSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        HtAE.Encrypt(c, p, n, k, ad);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HtAE.Encrypt(c, p, n, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        HtAE.Decrypt(p, c, n, k, ad);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        var p = new byte[plaintext.Length / 2];
        var parameters = new Dictionary<string, byte[]>
        {
            { "c", Convert.FromHexString(ciphertext) },
            { "n", Convert.FromHexString(nonce) },
            { "k", Convert.FromHexString(key) },
            { "ad", Convert.FromHexString(associatedData) }
        };

        foreach (var param in parameters.Values.Where(param => param.Length > 0)) {
            param[0]++;
            Assert.ThrowsException<CryptographicException>(() => HtAE.Decrypt(p, parameters["c"], parameters["n"], parameters["k"], parameters["ad"]));
            param[0]--;
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HtAE.Decrypt(p, c, n, k, ad));
    }
}
