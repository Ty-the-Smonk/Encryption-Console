using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Enter your data:");
        string inputData = Console.ReadLine();

        if (string.IsNullOrEmpty(inputData))
        {
            Console.WriteLine("Input is too short.");
            return;
        }

        // Generate Key and IV
        var generator = new CipherKeyGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), 256)); // AES 256 bits
        byte[] key = generator.GenerateKey();
        byte[] iv = new byte[16]; // AES block size is 16 bytes
        new SecureRandom().NextBytes(iv);

        // Encrypt
        byte[] encrypted = Encrypt(inputData, key, iv);
        Console.WriteLine($"Encrypted: {Convert.ToBase64String(encrypted)}");
        File.WriteAllBytes("encryptedData.txt", encrypted);

        // Decrypt
        string decrypted = Decrypt(encrypted, key, iv);
        Console.WriteLine($"Decrypted: {decrypted}");
    }

    public static byte[] Encrypt(string plainText, byte[] key, byte[] iv)
    {
        var paddedBufferedBlockCipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
        paddedBufferedBlockCipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
        byte[] outputBytes = new byte[paddedBufferedBlockCipher.GetOutputSize(inputBytes.Length)];
        int length = paddedBufferedBlockCipher.ProcessBytes(inputBytes, 0, inputBytes.Length, outputBytes, 0);
        paddedBufferedBlockCipher.DoFinal(outputBytes, length);
        return outputBytes;
    }

    public static string Decrypt(byte[] cipherText, byte[] key, byte[] iv)
    {
        var paddedBufferedBlockCipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
        paddedBufferedBlockCipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] outputBytes = new byte[paddedBufferedBlockCipher.GetOutputSize(cipherText.Length)];
        int length = paddedBufferedBlockCipher.ProcessBytes(cipherText, 0, cipherText.Length, outputBytes, 0);
        length += paddedBufferedBlockCipher.DoFinal(outputBytes, length);
        byte[] resultBytes = new byte[length];
        Array.Copy(outputBytes, resultBytes, length);
        return Encoding.UTF8.GetString(resultBytes);
    }
}
