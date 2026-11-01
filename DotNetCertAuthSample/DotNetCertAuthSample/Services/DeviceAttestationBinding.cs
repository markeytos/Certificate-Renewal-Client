using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using DotNetCertAuthSample.Models;

namespace DotNetCertAuthSample.Services;

/// <summary>
/// The bytes an attestation signs or MACs to tie itself to one enrollment.
///
/// Everything the server acts on has to be in here. The certificate request is covered by its
/// hash, which also covers the EKUs and SANs it asks for, so no separate unsigned field may carry
/// anything the server reads. The scheme and the endpoint are covered too, so a binding produced
/// for one kind of attestation or for one CA cannot be presented as another.
/// </summary>
public static class DeviceAttestationBinding
{
    /// <summary>
    /// Version prefix. Changing what goes into the binding changes this, so an old client and a
    /// new server fail to agree rather than appearing to agree on different bytes.
    /// </summary>
    public const string Context = "EZCA-DEVICE-ENROLL-v1";

    public static byte[] Build(
        string attestationScheme,
        Uri enrollmentUrl,
        DeviceEnrollmentChallenge challenge,
        byte[] csrDer
    )
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(attestationScheme);
        ArgumentNullException.ThrowIfNull(enrollmentUrl);
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(csrDer);
        if (string.IsNullOrWhiteSpace(challenge.Nonce))
        {
            throw new ArgumentException(
                "The challenge carries no nonce, so there is nothing to bind to.",
                nameof(challenge)
            );
        }

        if (string.IsNullOrWhiteSpace(challenge.ChallengeId))
        {
            throw new ArgumentException(
                "The challenge carries no identifier, so the server cannot tell which one this is.",
                nameof(challenge)
            );
        }

        byte[] nonce = Convert.FromBase64String(challenge.Nonce);
        using MemoryStream bindingInput = new();
        AppendLengthPrefixed(bindingInput, Encoding.UTF8.GetBytes(Context));
        AppendLengthPrefixed(bindingInput, Encoding.UTF8.GetBytes(attestationScheme));
        AppendLengthPrefixed(
            bindingInput,
            Encoding.UTF8.GetBytes(enrollmentUrl.AbsoluteUri)
        );
        AppendLengthPrefixed(bindingInput, Encoding.UTF8.GetBytes(challenge.ChallengeId));
        AppendLengthPrefixed(bindingInput, nonce);
        AppendLengthPrefixed(bindingInput, SHA256.HashData(csrDer));
        return bindingInput.ToArray();
    }

    /// <summary>
    /// Each field is written with its length in front, so no combination of values can be
    /// rearranged into the same byte string as another.
    /// </summary>
    private static void AppendLengthPrefixed(Stream bindingInput, byte[] field)
    {
        // Written little-endian explicitly: BitConverter follows the host, which would make the
        // bytes of a security binding depend on the machine that produced them.
        Span<byte> length = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32LittleEndian(length, (uint)field.Length);
        bindingInput.Write(length);
        bindingInput.Write(field);
    }
}
