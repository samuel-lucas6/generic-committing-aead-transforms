using GenericCommittingAeadTransforms;
using System.Security.Cryptography;

namespace GenericCommittingAEAD.Tests;

[TestClass]
public class AEtHTests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "414cb2511cefaabaa3c908935b8e5ddb067685b726343ba86a3899b42661d63e3b80b774205009414d7204ddf64ffd324c2cc974ba0128ed3ec8ea812942f5e618d17bd62406c3ee3b3bd01e2a2dd5657ebf0b04d40de7a450a9d6707ffc3c3e58726f26f1f4f33570bbed9485b762ec1b9c5799999af2436c777f63f32028b1024824414f2c8c8dcddaa9d765f9b8a0d2dacfad33c10c055727aadfb2bbe1328575e2b74919b866f29a87e9bb01490ddf0f",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "404142434445464748494a4b4c4d4e4f5051525354555658",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        ];
        yield return
        [
            "e8a3ec096329dd24916b2b699d721ac06f2c607d1c96ecdc98f20c0602fa5d85d919ff1fcd350fd7a1cfc1c0c58f1eeb6e3fad87a67a13c34099a2d8c1a884a181c5f6e14d9d10554d426676dc5acf1ca3faeb0df9dba01f4086efe8f00359c145c671b1a1a61b7268a39dcfa28dad466eeaa5728b519e63cf44ab41b4eafbd9cc67a073e388af950d9a11043ed8f6e66b66623a24ecb5bff633443e5f12a7e41613e9a402882e36ccbc98ad74be97fcf5182b725b8c11d4a506270e95294a18a50ae565abc9abc81ea47676bc1554673d469dc825fb079cc35bb8a1390ac48063a15f143cf7478a1039aff7a3325f31b58c632822ad3e5da779d29b7939fff3cf6f0e6452c0bad3895659f180337ab6efaba48873527d83893188d21912e652cf812c1c94e98246ff9364e5e000f71c751c77dc41424abf86846cc40648cbd0a59a33e54428a5a001",
            "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d",
            "404142434445464748494a4b4c4d4e4f5051525354555658",
            "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
            "f33388860000000000004e91"
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [AEtH.TagSize + AEtH.CommitmentSize - 1, 0, AEtH.NonceSize, AEtH.KeySize, AEtH.TagSize];
        yield return [AEtH.TagSize + AEtH.CommitmentSize, 1, AEtH.NonceSize, AEtH.KeySize, AEtH.TagSize];
        yield return [AEtH.TagSize + AEtH.CommitmentSize, 0, AEtH.NonceSize + 1, AEtH.KeySize, AEtH.TagSize];
        yield return [AEtH.TagSize + AEtH.CommitmentSize, 0, AEtH.NonceSize - 1, AEtH.KeySize, AEtH.TagSize];
        yield return [AEtH.TagSize + AEtH.CommitmentSize, 0, AEtH.NonceSize, AEtH.KeySize + 1, AEtH.TagSize];
        yield return [AEtH.TagSize + AEtH.CommitmentSize, 0, AEtH.NonceSize, AEtH.KeySize - 1, AEtH.TagSize];
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, AEtH.KeySize);
        Assert.AreEqual(24, AEtH.NonceSize);
        Assert.AreEqual(32, AEtH.TagSize);
        Assert.AreEqual(32, AEtH.CommitmentSize);
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

        AEtH.Encrypt(c, p, n, k, ad);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => AEtH.Encrypt(c, p, n, k, ad));
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

        AEtH.Decrypt(p, c, n, k, ad);

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
            Assert.ThrowsException<CryptographicException>(() => AEtH.Decrypt(p, parameters["c"], parameters["n"], parameters["k"], parameters["ad"]));
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => AEtH.Decrypt(p, c, n, k, ad));
    }
}
