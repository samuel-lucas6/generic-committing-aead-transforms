using GenericCommittingAeadTransforms;
using System.Security.Cryptography;

namespace GenericCommittingAEAD.Tests;

[TestClass]
public class EtHTests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "37cd4f4c48c767ce67d25a12c18721e86f8cb31d301abfcb5efb10585db9328cd15ea3b88dfc748deb37d582e94263bbd3c2f8e86b241bed188407405dd14979f117907d6e93259a618bffdb50ee788eb5a8ed1f6f741aabafeffca726f76dd62decae5dc2ae2944cdb6d62f98be7281012a575ab7fe8964e1c3ff3b2cfbcf109f33d91865de89c59ccb78db00ab5fef1555",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        ];
        yield return
        [
            "f49e3ecc2e8abbfdb8f539d7c7fb9f8f4735ea70a4269405afe0c67145601fcf7a91c23179add6c97140ecedf374e3f73dc9dc81bbceb1f955850d3f7ba1ec9542a0861874c81eee29947dc784b252f81f8749b9315af78ba9087100d47580b4477ca3186c4e0fe8a6cde04d2f7922f4f0b4b675301a0445c9b67f633f55d9c732358446635fd6c19291e55fad4693ca1491132a088a76b022b880a4fd34d9449b92f82bbbf6a02ed6863802072f1739640a8c2f284c18b4eda2023451ce2af3b2047a247f9a0e42eb8f1316c1f8a8a6dc29def64d346d17ef8aa5a5f2774a29ab042fc6b02ebc155a1b433fe5b3532f508bceece97d4ee05d5f3f73e449680f1cb1276118bbf77ca4b258411d91bd7906f7094a40ccf824291fa38228a13c54d204dc5de9fbb03fdc",
            "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d",
            "000000000102030405060708",
            "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
            "f33388860000000000004e91"
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [EtH.TagSize - 1, 0, EtH.NonceSize, EtH.KeySize, EtH.TagSize];
        yield return [EtH.TagSize, 1, EtH.NonceSize, EtH.KeySize, EtH.TagSize];
        yield return [EtH.TagSize, 0, EtH.NonceSize + 1, EtH.KeySize, EtH.TagSize];
        yield return [EtH.TagSize, 0, EtH.NonceSize - 1, EtH.KeySize, EtH.TagSize];
        yield return [EtH.TagSize, 0, EtH.NonceSize, EtH.KeySize + 1, EtH.TagSize];
        yield return [EtH.TagSize, 0, EtH.NonceSize, EtH.KeySize - 1, EtH.TagSize];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, EtH.KeySize);
        Assert.AreEqual(12, EtH.NonceSize);
        Assert.AreEqual(32, EtH.TagSize);
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

        EtH.Encrypt(c, p, n, k, ad);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => EtH.Encrypt(c, p, n, k, ad));
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

        EtH.Decrypt(p, c, n, k, ad);

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
            Assert.ThrowsException<CryptographicException>(() => EtH.Decrypt(p, parameters["c"], parameters["n"], parameters["k"], parameters["ad"]));
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => EtH.Decrypt(p, c, n, k, ad));
    }
}
