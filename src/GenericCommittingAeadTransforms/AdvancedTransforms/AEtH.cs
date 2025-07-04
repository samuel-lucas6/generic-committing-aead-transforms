using System.Security.Cryptography;
using Geralt;

namespace GenericCommittingAeadTransforms;

// Equivalent to CTX but without replacing the tag, meaning greater storage overhead
// This is like DEH from my 2023 MSc dissertation, except DEH derives subkeys for encryption and commitment using the nonce and associated data
// https://github.com/samuel-lucas6/dissertation/blob/main/src/cAEAD/Proposals/Patches/Misuse/DEH.cs
public static class AEtH
{
    public const int KeySize = chaSIV.KeySize;
    public const int NonceSize = chaSIV.NonceSize;
    public const int TagSize = chaSIV.TagSize;
    public const int CommitmentSize = TagSize;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + TagSize + CommitmentSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        // Using chaSIV because libsodium doesn't have a misuse-resistant AEAD/to keep this project self-contained
        // However, chaSIV is already committing so doesn't need AEtH
        Span<byte> ciphertextCore = ciphertext[..^CommitmentSize];
        chaSIV.Encrypt(ciphertextCore, plaintext, nonce, key, associatedData);
        ComputeCommitment(ciphertext[^CommitmentSize..], key, nonce, associatedData, ciphertextCore[^TagSize..]);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, TagSize + CommitmentSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - TagSize - CommitmentSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        ReadOnlySpan<byte> ciphertextCore = ciphertext[..^CommitmentSize];
        Span<byte> commitment = stackalloc byte[CommitmentSize];
        ComputeCommitment(commitment, key, nonce, associatedData, ciphertextCore[^TagSize..]);

        bool valid = ConstantTime.Equals(commitment, ciphertext[^CommitmentSize..]);
        CryptographicOperations.ZeroMemory(commitment);
        if (!valid) {
            throw new CryptographicException();
        }

        // Timing difference if the ciphertext has been tampered with
        chaSIV.Decrypt(plaintext, ciphertextCore, nonce, key, associatedData);
    }

    private static void ComputeCommitment(Span<byte> commitment, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> tag)
    {
        // Assumes 2/3 message inputs are fixed-length
        using var blake2b = new IncrementalBLAKE2b(commitment.Length, key);
        blake2b.Update(nonce);
        blake2b.Update(associatedData);
        blake2b.Update(tag);
        blake2b.Finalize(commitment);
    }
}
