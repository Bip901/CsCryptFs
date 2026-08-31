using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using FileAbstractions;
using FileAbstractions.Implementations;
using Xunit;

namespace CsCryptFs.Tests;

public static class ReferenceVolume
{
    public const string RELATIVE_PATH = "reference";
    public const string PASSWORD = "1234";

    public const string LONG_FILE_NAME =
        "Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long.txt";
    public const string SUBDIR_NAME = "Example Directory";
    public const string EXAMPLE_FILE_NAME = "Example.bin";
    public const string EXAMPLE_FILE_NAME_ENCRYPTED = "26V1Ld8CgKoVQVmhZVkCcA";
    public const string EMPTY_FILE_NAME = "Empty.txt";

    public static readonly byte[] ContentKey = Convert.FromBase64String("eqMSN7poLIxO7mQ/UEemB802VXENE2GDedcQ1R86sgk=");

    private static string RootPath => Path.Combine(AppContext.BaseDirectory, RELATIVE_PATH);

    public static LocalDirectory Get()
    {
        return new LocalDirectory(RootPath);
    }

    /// <summary>
    /// Reads the ciphertext contents of file <see cref="EXAMPLE_FILE_NAME"/>.
    /// </summary>
    public static byte[] GetExampleFileCiphertext()
    {
        return File.ReadAllBytes(Path.Combine(RootPath, EXAMPLE_FILE_NAME_ENCRYPTED));
    }

    /// <summary>
    /// Returns the expected plaintext contents of file <see cref="EXAMPLE_FILE_NAME"/>.
    /// </summary>
    public static IEnumerable<byte> GetExampleFilePlaintext()
    {
        return Enumerable
            .Repeat((byte)'A', 4096)
            .Concat(Enumerable.Repeat((byte)0, 4096))
            .Concat(Enumerable.Repeat((byte)'C', 4096));
    }
}
