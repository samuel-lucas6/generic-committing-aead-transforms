using System.Security.Cryptography;
using Geralt;

namespace GenericCommittingAeadTransforms;

// A worse version of cSIV from my 2023 MSc dissertation, which derives separates keys for encryption and authentication based on the nonce plus AD
// Could be further improved by allowing pre-processing of static associated data
// https://github.com/samuel-lucas6/dissertation/blob/main/src/cAEAD/Proposals/Schemes/Misuse/cSIVBLAKE2b.cs
public static class chaSIV
{
    public const int KeySize = XChaCha20.KeySize;
    public const int NonceSize = XChaCha20.NonceSize;
    public const int TagSize = 32;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkey = stackalloc byte[KeySize];
        BLAKE2b.ComputeTag(subkey, nonce, key);

        Span<byte> tag = ciphertext[^TagSize..];
        ComputeTag(tag, key, nonce, associatedData, plaintext);

        XChaCha20.Encrypt(ciphertext[..^TagSize], plaintext, tag[^NonceSize..], subkey);
        CryptographicOperations.ZeroMemory(subkey);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkey = stackalloc byte[KeySize];
        BLAKE2b.ComputeTag(subkey, nonce, key);

        ReadOnlySpan<byte> tag = ciphertext[^TagSize..];
        XChaCha20.Decrypt(plaintext, ciphertext[..^TagSize], tag[^NonceSize..], subkey);
        CryptographicOperations.ZeroMemory(subkey);

        Span<byte> computedTag = stackalloc byte[TagSize];
        ComputeTag(computedTag, key, nonce, associatedData, plaintext);

        bool valid = ConstantTime.Equals(computedTag, tag);
        CryptographicOperations.ZeroMemory(computedTag);
        if (!valid) {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException();
        }
    }

    // Note that the paper doesn't bother to specify how to make the input unambiguous
    private static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plaintext)
    {
        // Separation indicator following NIST SP 800-108 (an alternative to length encoding)
        // https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final
        Span<byte> separator = [0x00];
        using var blake2b = new IncrementalBLAKE2b(tag.Length, key);
        blake2b.Update(nonce);
        blake2b.Update(separator);
        blake2b.Update(associatedData);
        blake2b.Update(separator);
        blake2b.Update(plaintext);
        blake2b.Finalize(tag);
    }
}
