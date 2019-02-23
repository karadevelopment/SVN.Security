using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SVN.Security.Cryptography
{
    public static class Extensions
    {
        private static string STR_PASSWORD => "ouiveyxaqtd";
        private static byte[] RGB_SALT => new byte[] { 0x19, 0x59, 0x17, 0x41 };
        private static PasswordDeriveBytes PDB => new PasswordDeriveBytes(Extensions.STR_PASSWORD, Extensions.RGB_SALT);

        public static string CryptPassword(this string param)
        {
            if (param is null || param.Length == default(int))
            {
                return string.Empty;
            }

            using (var md5 = new MD5CryptoServiceProvider())
            {
                var bytes = Encoding.Default.GetBytes(param);
                var hash = md5.ComputeHash(bytes);

                return BitConverter.ToString(hash);
            }
        }

        private static byte[] Encrypt(this byte[] param)
        {
            if (param.Length == default(int))
            {
                return new byte[] { };
            }

            using (var ms = new MemoryStream())
            {
                using (var aes = new AesManaged())
                {
                    aes.Key = Extensions.PDB.GetBytes(aes.KeySize / 8);
                    aes.IV = Extensions.PDB.GetBytes(aes.BlockSize / 8);

                    using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(param, default(int), param.Length);
                    }

                    return ms.ToArray();
                }
            }
        }

        private static byte[] Decrypt(this byte[] param)
        {
            if (param.Length == default(int))
            {
                return new byte[] { };
            }
            
            using (var ms = new MemoryStream())
            {
                using (var aes = new AesManaged())
                {
                    aes.Key = Extensions.PDB.GetBytes(aes.KeySize / 8);
                    aes.IV = Extensions.PDB.GetBytes(aes.BlockSize / 8);

                    using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(param, default(int), param.Length);
                    }

                    return ms.ToArray();
                }
            }
        }

        public static string Encrypt(this string param)
        {
            if (string.IsNullOrWhiteSpace(param))
            {
                return string.Empty;
            }

            var bytes = Encoding.UTF8.GetBytes(param).Encrypt();
            return Convert.ToBase64String(bytes);
        }

        public static string Decrypt(this string param)
        {
            if (string.IsNullOrWhiteSpace(param))
            {
                return string.Empty;
            }

            var bytes = Convert.FromBase64String(param).Decrypt();
            return Encoding.UTF8.GetString(bytes);
        }
    }
}