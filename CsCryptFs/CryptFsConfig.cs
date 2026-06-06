using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CsCryptFs;

public class CryptFsConfig
{
    public const int SUPPORTED_CONFIG_VERSION = 2;
    public static readonly List<string> ExpectedFeatureFlags = ["EMENames", "LongNames", "HKDF", "Raw64", "GCMIV128"];

    public string Creator { get; set; } = string.Empty;
    public required byte[] EncryptedKey { get; set; }
    public required ScryptParams ScryptObject { get; set; }
    public required int Version { get; set; }
    public string VolumeName { get; set; } = string.Empty;
    public string FsFeatureDisableMask { get; set; } = "40000";
    public List<string>? FeatureFlags { get; set; }
    public int LongNameMax { get; set; } = 255;

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }

    public class ScryptParams : IEquatable<ScryptParams>
    {
        public required byte[] Salt { get; set; }
        public required int N { get; set; }
        public required int R { get; set; }
        public required int P { get; set; }
        public required int KeyLen { get; set; }

        [JsonExtensionData]
        public Dictionary<string, JsonElement>? ExtensionData { get; set; }

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

        public override bool Equals(object? obj)
        {
            return Equals(obj as ScryptParams);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(N, R, P, KeyLen);
        }
    }

    public static CryptFsConfig? Deserialize(ReadOnlySpan<byte> utf8Json)
    {
        return JsonSerializer.Deserialize(utf8Json, CryptFsJsonContext.Default.CryptFsConfig);
    }

    public byte[] Serialize()
    {
        return JsonSerializer.SerializeToUtf8Bytes(this, CryptFsJsonContext.Default.CryptFsConfig);
    }
}

[JsonSourceGenerationOptions(
    WriteIndented = true,
    ReadCommentHandling = JsonCommentHandling.Skip,
    PropertyNamingPolicy = JsonKnownNamingPolicy.Unspecified
)]
[JsonSerializable(typeof(CryptFsConfig))]
public partial class CryptFsJsonContext : JsonSerializerContext { }
