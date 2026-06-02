using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CsCryptFs;

public class CryptFsConfig
{
    public string Creator { get; set; } = string.Empty;
    public required byte[] EncryptedKey { get; set; }
    public required ScryptParams ScryptObject { get; set; }
    public int Version { get; set; }
    public string VolumeName { get; set; } = string.Empty;
    public string FsFeatureDisableMask { get; set; } = "40000";
    public List<string> FeatureFlags { get; set; } = ["EMENames", "LongNames", "HKDF", "Raw64", "GCMIV128"];
    public int LongNameMax { get; set; } = 255;

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }

    public class ScryptParams
    {
        public required byte[] Salt { get; set; }
        public int N { get; set; } = 65536;
        public int R { get; set; } = 8;
        public int P { get; set; } = 1;
        public int KeyLen { get; set; } = 32;

        [JsonExtensionData]
        public Dictionary<string, JsonElement>? ExtensionData { get; set; }
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
