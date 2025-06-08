using System.Security.Cryptography;
using Geralt;
using ChaCha20Poly1305 = Geralt.ChaCha20Poly1305;

namespace GenericCommittingAeadTransforms;

// Virtually identical to Context Hashing from RWC 2023: https://iacr.org/submit/files/slides/2023/rwc/rwc2023/112/slides.pptx
// The commitment can be computed in parallel, but that will almost certainly be slower than doing it serially
public static class AEaH
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

        ChaCha20Poly1305.Encrypt(ciphertext[..^CommitmentSize], plaintext, nonce, key, associatedData: ReadOnlySpan<byte>.Empty);
        // Add length encoding if not using a fixed-length nonce
        using var blake2b = new IncrementalBLAKE2b(CommitmentSize, key);
        blake2b.Update(nonce);
        blake2b.Update(associatedData);
        blake2b.Finalize(ciphertext[^CommitmentSize..]);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, TagSize + CommitmentSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - TagSize - CommitmentSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> commitment = stackalloc byte[CommitmentSize];
        using var blake2b = new IncrementalBLAKE2b(commitment.Length, key);
        blake2b.Update(nonce);
        blake2b.Update(associatedData);
        blake2b.Finalize(commitment);

        // Timing difference between tag checks unless you implement ChaCha20-Poly1305 decryption
        try {
            if (!ConstantTime.Equals(commitment, ciphertext[^CommitmentSize..])) {
                throw new CryptographicException();
            }
            ChaCha20Poly1305.Decrypt(plaintext, ciphertext[..^CommitmentSize], nonce, key, associatedData: ReadOnlySpan<byte>.Empty);
        }
        finally {
            CryptographicOperations.ZeroMemory(commitment);
        }
    }
}
