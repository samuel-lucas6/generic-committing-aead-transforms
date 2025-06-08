using System.Security.Cryptography;
using Geralt;
using ChaCha20Poly1305 = Geralt.ChaCha20Poly1305;

namespace GenericCommittingAeadTransforms;

// Equivalent to CommitAll from my 2023 MSc dissertation
// https://github.com/samuel-lucas6/dissertation/blob/main/src/cAEAD/Proposals/Patches/Nonce/CommitAll.cs
public static class HtAE
{
    public const int KeySize = ChaCha20Poly1305.KeySize;
    public const int NonceSize = ChaCha20Poly1305.NonceSize;
    public const int TagSize = ChaCha20Poly1305.TagSize;
    public const int CommitmentSize = 32;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + TagSize + CommitmentSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> tag = stackalloc byte[BLAKE2b.MaxTagSize], subkey = tag[..KeySize], commitment = tag[KeySize..];
        // Add length encoding if not using a fixed-length nonce
        using var blake2b = new IncrementalBLAKE2b(tag.Length, key);
        blake2b.Update(nonce);
        blake2b.Update(associatedData);
        blake2b.Finalize(tag);

        ChaCha20Poly1305.Encrypt(ciphertext[..^CommitmentSize], plaintext, nonce, subkey, associatedData: ReadOnlySpan<byte>.Empty);
        commitment.CopyTo(ciphertext[^CommitmentSize..]);
        CryptographicOperations.ZeroMemory(tag);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, TagSize + CommitmentSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - TagSize - CommitmentSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> tag = stackalloc byte[BLAKE2b.MaxTagSize], subkey = tag[..KeySize], commitment = tag[KeySize..];
        using var blake2b = new IncrementalBLAKE2b(tag.Length, key);
        blake2b.Update(nonce);
        blake2b.Update(associatedData);
        blake2b.Finalize(tag);

        // Timing difference between tag checks unless you implement ChaCha20-Poly1305 decryption
        try {
            if (!ConstantTime.Equals(commitment, ciphertext[^CommitmentSize..])) {
                throw new CryptographicException();
            }
            ChaCha20Poly1305.Decrypt(plaintext, ciphertext[..^CommitmentSize], nonce, subkey, associatedData: ReadOnlySpan<byte>.Empty);
        }
        finally {
            CryptographicOperations.ZeroMemory(tag);
        }
    }
}
