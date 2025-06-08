using System.Security.Cryptography;
using System.Buffers.Binary;
using Geralt;

namespace GenericCommittingAeadTransforms;

// A worse version of oEtM from my 2023 MSc dissertation, which allows pre-processing static associated data
// https://github.com/samuel-lucas6/dissertation/blob/main/src/cAEAD/Proposals/Schemes/Nonce/oEtMBLAKE2b.cs
public static class EtH
{
    public const int KeySize = ChaCha20.KeySize;
    public const int NonceSize = ChaCha20.NonceSize;
    public const int TagSize = 32;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> ciphertextCore = ciphertext[..^TagSize], tag = ciphertext[^TagSize..];
        ChaCha20.Encrypt(ciphertextCore, plaintext, nonce, key);
        ComputeTag(tag, key, nonce, associatedData, ciphertextCore);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        ReadOnlySpan<byte> ciphertextCore = ciphertext[..^TagSize], tag = ciphertext[^TagSize..];
        Span<byte> computedTag = stackalloc byte[TagSize];
        ComputeTag(computedTag, key, nonce, associatedData, ciphertextCore);

        try {
            if (!ConstantTime.Equals(computedTag, tag)) {
                throw new CryptographicException();
            }
            ChaCha20.Decrypt(plaintext, ciphertextCore, nonce, key);
        }
        finally {
            CryptographicOperations.ZeroMemory(computedTag);
        }
    }

    private static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertextCore)
    {
        // Note that the paper doesn't bother to specify how to make the input unambiguous
        Span<byte> lengths = tag[..16];
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[..8], (ulong)associatedData.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[8..], (ulong)ciphertextCore.Length);

        // Assumes a fixed-length nonce
        using var blake2b = new IncrementalBLAKE2b(tag.Length, key);
        blake2b.Update(nonce);
        blake2b.Update(associatedData);
        blake2b.Update(ciphertextCore);
        blake2b.Update(lengths);
        blake2b.Finalize(tag);
    }
}
