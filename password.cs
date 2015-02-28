using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Collections.Generic;		

namespace Util.Encryption {
    public class StringCipher
    {
        // This constant is used to determine the keysize of the encryption algorithm.
        private static int ivLength = 16;
        private const int keysize = 256;

        private static void GenerateRandomIv(byte[] iv) {
            RNGCryptoServiceProvider cryptoProvider = new RNGCryptoServiceProvider();
            cryptoProvider.GetBytes(iv);
        }

        public static string Encrypt(string plainText, string passPhrase)
        {
            byte[] initVectorBytes = new byte[ivLength];
            GenerateRandomIv(initVectorBytes);

            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            using (PasswordDeriveBytes password = new PasswordDeriveBytes(passPhrase, null))
            {
                byte[] keyBytes = password.GetBytes(keysize / 8);
                using (RijndaelManaged symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.Mode = CipherMode.CBC;
                    using (ICryptoTransform encryptor = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes))
                    {
                        using (MemoryStream memoryStream = new MemoryStream())
                        {
                            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                            {
                                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                                cryptoStream.FlushFinalBlock();
                                byte[] cipherTextBytes = memoryStream.ToArray();
                                byte[] ivAndCipherText = new byte[ivLength + cipherTextBytes.Length];
                                System.Buffer.BlockCopy(initVectorBytes, 0, ivAndCipherText, 0, ivLength);
                                System.Buffer.BlockCopy(cipherTextBytes, 0, ivAndCipherText, ivLength, cipherTextBytes.Length);


                                return Convert.ToBase64String(ivAndCipherText);
                            }
                        }
                    }
                }
            }
        }

        public static string Decrypt(string cipherText, string passPhrase)
        {
            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);
            byte[] iv = new byte[ivLength];

            System.Buffer.BlockCopy(cipherTextBytes, 0, iv, 0, ivLength);

            byte[] cipherTextBytesWithoutIv = new byte[cipherTextBytes.Length - ivLength];
            System.Buffer.BlockCopy(cipherTextBytes, ivLength, cipherTextBytesWithoutIv, 0, cipherTextBytesWithoutIv.Length);

            using(PasswordDeriveBytes password = new PasswordDeriveBytes(passPhrase, null))
            {
                byte[] keyBytes = password.GetBytes(keysize / 8);
                using(RijndaelManaged symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.Mode = CipherMode.CBC;
                    using(ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes, iv))
                    {
                        using(MemoryStream memoryStream = new MemoryStream(cipherTextBytesWithoutIv))
                        {
                            using(CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                            {
                                byte[] plainTextBytes = new byte[cipherTextBytesWithoutIv.Length];
                                int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                                return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
                            }
                        }
                    }
                }
            }
        }
    }

    public class Bootstrap
    {
        public static void Main(string[] args) 
        {
            Console.WriteLine("Please enter a password to use:");
            string password = Console.ReadLine();
            Console.WriteLine("Please enter a string to encrypt:");
            string plaintext = Console.ReadLine();


            Console.WriteLine("");

            Console.WriteLine("Your encrypted string is:");
            
            var cipherTexts = new List<String>();

            for(var i=0;i<5;i++) {
            	string encryptedstring = StringCipher.Encrypt(plaintext, password);
            	Console.WriteLine(encryptedstring);
            	cipherTexts.Add(encryptedstring);
        	}
            
            Console.WriteLine("");

            //string encryptedstring = Console.ReadLine();

            Console.WriteLine("Your decrypted string is:");

            for(var i=0;i<5;i++) {
           		string decryptedstring = StringCipher.Decrypt(cipherTexts[i], password);
            	Console.WriteLine(decryptedstring);
            }
  
            Console.WriteLine("");

            Console.ReadLine();
        }
    }
}