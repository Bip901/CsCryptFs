using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CsCryptFs;

/// <summary>
/// The JSON configuration file of a gocryptfs volume.
/// This object mirrors ConfFile in gocryptfs.
/// </summary>
public class CryptFsConfig
{
    /// <summary>
    /// The current supported On-Disk-Format version.
    /// </summary>
    public const int CURRENT_VERSION = 2;

    /// <summary>
    /// The current supported feature flags. Order doesn't matter.
    /// </summary>
    public static readonly List<string> ExpectedFeatureFlags = ["EMENames", "LongNames", "HKDF", "Raw64", "GCMIV128"];

    /// <summary>
    /// This only documents the config file for humans who look at it. The actual
    /// technical info is contained in FeatureFlags.
    /// </summary>
    public string Creator { get; set; } = string.Empty;

    /// <summary>
    /// Holds an encrypted AES key, unlocked using a password hashed with scrypt.
    /// </summary>
    public required byte[] EncryptedKey { get; set; }

    /// <summary>
    /// Parameters for key derivation.
    /// </summary>
    public required ScryptParams ScryptObject { get; set; }

    /// <summary>
    /// The On-Disk-Format version this filesystem uses
    /// </summary>
    public required int Version { get; set; }

    /// <summary>
    /// The name of the mounted volume.
    /// Used only by cppcryptfs (the Windows implementation).
    /// </summary>
    public string VolumeName { get; set; } = string.Empty;

    /// <summary>
    /// Features to disable.
    /// Used only by cppcryptfs (the Windows implementation).
    /// </summary>
    /// <remarks>The default value of 40000 disables alternate data streams.</remarks>
    public string FsFeatureDisableMask { get; set; } = "40000";

    /// <summary>
    /// A list of feature flags this filesystem has enabled.
    /// If gocryptfs encounters a feature flag it does not support, it will refuse
    /// mounting. This mechanism is analogous to the ext4 feature flags that are
    /// stored in the superblock.
    /// </summary>
    public List<string>? FeatureFlags { get; set; }

    /// <summary>
    /// Hash file names that (in encrypted form) exceed this length. The default is 255, which aligns with the usual name length limit on Linux and provides best performance.
    /// The lower the value, the more extra .name files must be created, which slows down directory listings.
    /// Values below 62 are not allowed as then the hashed name would be longer than the original name.
    /// </summary>
    public int LongNameMax { get; set; } = 255;

    /// <summary>
    /// All other JSON fields not recognized by CsCryptFs (but may be supported by gocryptfs or other implementations).
    /// </summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }

    /// <summary>
    /// Defines what to do when encountering a file with an invalid name.
    /// </summary>
    /// <remarks>This property is only used by CsCryptFs and not serialized to disk.</remarks>
    [JsonIgnore]
    public FileNameDecryptFailBehavior DecryptFailBehavior { get; set; } = FileNameDecryptFailBehavior.Ignore;

    /// <summary>
    /// Parameters for the scrypt key derivation function.
    /// </summary>
    public class ScryptParams : IEquatable<ScryptParams>
    {
        /// <summary>
        /// A random non-secret value.
        /// </summary>
        public required byte[] Salt { get; set; }

        /// <summary>
        /// N: scrypt CPU/Memory cost parameter
        /// </summary>
        public required int N { get; set; }

        /// <summary>
        /// R: scrypt block size parameter
        /// </summary>
        public required int R { get; set; }

        /// <summary>
        /// P: scrypt parallelization parameter
        /// </summary>
        public required int P { get; set; }

        /// <summary>
        /// Output data length in bytes.
        /// </summary>
        public required int KeyLen { get; set; }

        /// <summary>
        /// All other JSON fields not recognized by CsCryptFs (but may be supported by gocryptfs or other implementations).
        /// </summary>
        [JsonExtensionData]
        public Dictionary<string, JsonElement>? ExtensionData { get; set; }

        /// <inheritdoc/>
        public bool Equals(ScryptParams? other)
        {
            if (other == null)
            {
                return false;
            }
            return N == other.N
                && R == other.R
                && P == other.P
                && KeyLen == other.KeyLen
                && Salt.SequenceEqual(other.Salt);
        }

        /// <inheritdoc/>
        public override bool Equals(object? obj)
        {
            return Equals(obj as ScryptParams);
        }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            return HashCode.Combine(N, R, P, KeyLen);
        }
    }

    /// <summary>
    /// Defines what to do when encountering a file with an invalid name.
    /// </summary>
    public enum FileNameDecryptFailBehavior
    {
        /// <summary>
        /// Treats the file/directory as non-existent.
        /// </summary>
        Ignore = 0,

        /// <summary>
        /// Raises the original cause (usually <see cref="CryptographicException"/> or <see cref="FormatException"/>).
        /// </summary>
        Raise = 1,
    }

    /// <exception cref="InvalidDataException"></exception>
    /// <exception cref="JsonException"></exception>
    /// <exception cref="NotSupportedException"></exception>
    public static CryptFsConfig DeserializeAndValidate(ReadOnlySpan<byte> utf8Json)
    {
        CryptFsConfig config = Deserialize(utf8Json);
        if (config.Version != CURRENT_VERSION)
        {
            throw new InvalidDataException(
                $"Config file version {config.Version} is not supported (expected {CURRENT_VERSION})"
            );
        }
        if (
            config.FeatureFlags == null
            || !new HashSet<string>(config.FeatureFlags).SetEquals(new HashSet<string>(ExpectedFeatureFlags))
        )
        {
            string featureFlagsString = config.FeatureFlags == null ? "null" : string.Join(", ", config.FeatureFlags);
            throw new NotSupportedException($"Unsupported feature flags: [{featureFlagsString}]");
        }
        return config;
    }

    /// <summary>
    /// Deserializes a new <see cref="CryptFsConfig"/> instance from the on-disk format expected by gocryptfs.
    /// </summary>
    /// <exception cref="JsonException"/>
    /// <exception cref="InvalidDataException"/>
    public static CryptFsConfig Deserialize(ReadOnlySpan<byte> utf8Json)
    {
        return JsonSerializer.Deserialize(utf8Json, CryptFsJsonContext.Default.CryptFsConfig)
            ?? throw new InvalidDataException("Config file JSON contents were literally 'null'");
        ;
    }

    /// <summary>
    /// Serializes this instance to the on-disk format expected by gocryptfs.
    /// </summary>
    public byte[] Serialize()
    {
        return JsonSerializer.SerializeToUtf8Bytes(this, CryptFsJsonContext.Default.CryptFsConfig);
    }
}

/// <summary>
/// Json context to use for serializing/deserializing <see cref="CryptFsConfig"/>.
/// </summary>
[JsonSourceGenerationOptions(
    WriteIndented = true,
    ReadCommentHandling = JsonCommentHandling.Skip,
    PropertyNamingPolicy = JsonKnownNamingPolicy.Unspecified
)]
[JsonSerializable(typeof(CryptFsConfig))]
public partial class CryptFsJsonContext : JsonSerializerContext { }
