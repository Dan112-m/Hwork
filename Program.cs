using System;
using System.IO;
using System.Security.Cryptography;

class AesFileEncryption
{
    private static readonly int KeySize = 256;
    private static readonly int BlockSize = 128;

    public static void Main(string[] args)
    {
        string inputFile = "input.txt"; // Вхідний файл
        string encryptedFile = "encrypted.dat"; // Шифрований файл
        string decryptedFile = "decrypted.txt"; // Дешифрований файл

        try
        {
            // Генерація ключа та IV
            using (var aes = Aes.Create())
            {
                aes.KeySize = KeySize;
                aes.BlockSize = BlockSize;

                aes.GenerateKey();
                aes.GenerateIV();

                byte[] key = aes.Key;
                byte[] iv = aes.IV;

                Console.WriteLine("Generated Key: " + Convert.ToBase64String(key));
                Console.WriteLine("Generated IV: " + Convert.ToBase64String(iv));

                // Шифрування файлу
                Console.WriteLine("Encrypting file...");
                EncryptFile(inputFile, encryptedFile, key, iv);
                Console.WriteLine("Encryption completed. Encrypted file created: " + encryptedFile);

                // Дешифрування файлу
                Console.WriteLine("Decrypting file...");
                DecryptFile(encryptedFile, decryptedFile);
                Console.WriteLine("Decryption completed. Decrypted file created: " + decryptedFile);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
        }
    }

    public static void EncryptFile(string inputFile, string outputFile, byte[] key, byte[] iv)
    {
        using (var aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;

            using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            using (var fileStream = new FileStream(outputFile, FileMode.Create))
            using (var cryptoStream = new CryptoStream(fileStream, encryptor, CryptoStreamMode.Write))
            using (var inputStream = new FileStream(inputFile, FileMode.Open))
            {
                inputStream.CopyTo(cryptoStream);
            }

            // Додавання MAC
            var mac = ComputeMac(outputFile);
            File.WriteAllBytes(outputFile + ".mac", mac);
            
            // Збереження ключа та IV у файлі
            File.WriteAllBytes(outputFile + ".key", key);
            File.WriteAllBytes(outputFile + ".iv", iv);
        }
    }

    public static void DecryptFile(string inputFile, string outputFile)
    {
        byte[] key = File.ReadAllBytes(inputFile + ".key");
        byte[] iv = File.ReadAllBytes(inputFile + ".iv");

        using (var aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;

            // Перевірка MAC
            var macFile = inputFile + ".mac";
            var storedMac = File.ReadAllBytes(macFile);

            // Перевірка MAC на зашифрованому файлі
            var computedMac = ComputeMac(inputFile);

            if (!CompareArrays(computedMac, storedMac))
            {
                throw new InvalidOperationException("MAC verification failed!");
            }

            using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            using (var fileStream = new FileStream(inputFile, FileMode.Open))
            using (var cryptoStream = new CryptoStream(fileStream, decryptor, CryptoStreamMode.Read))
            using (var outputStream = new FileStream(outputFile, FileMode.Create))
            {
                cryptoStream.CopyTo(outputStream);
            }
        }
    }

    private static byte[] ComputeMac(string filePath)
    {
        using (var hmac = new HMACSHA256())
        using (var fileStream = new FileStream(filePath, FileMode.Open))
        {
            return hmac.ComputeHash(fileStream);
        }
    }

    private static bool CompareArrays(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;

        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i]) return false;
        }
        return true;
    }
}


