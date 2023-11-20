using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            string keystream = "";
            string keys = "";

            for (int i = 0; i < cipherText.Length; i++)
                keystream += alphabet[((alphabet.IndexOf(cipherText[i]) - alphabet.IndexOf(plainText[i])) + 26) % 26];

            keys = keys + keystream[0];
            for (int i = 1; i < keystream.Length; i++)
            {
                if (cipherText.Equals(Encrypt(plainText, keys), StringComparison.InvariantCultureIgnoreCase))
                    return keys;
                keys = keys + keystream[i];
            }
            return keystream;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();

            string Plain_Text = "";

            for (int i = 0; i < cipherText.Length; i++)
            {
                string newKey = key;
                if (i >= key.Length)
                    newKey = key + Plain_Text.ToUpper();

                int x = (cipherText[i] - newKey[i]) % 26;
                x = (x < 0) ? x + 26 : x;
                x += 'A';
                Plain_Text += (char)(x);
            }
            return Plain_Text.ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToUpper();
            key = key.ToUpper();

            string newKey = key + plainText;
            newKey = newKey.Substring(0, newKey.Length - key.Length);

            string Cipher_Text = "";

            for (int i = 0, j = 0; i < plainText.Length; i++, j++)
            {
                // converting in range 0-25 ( Ceaser Cipher )
                int x = (plainText[i] + newKey[j]) % 26;

                // convert into alphabets(ASCII)
                x += 'A';
                Cipher_Text += (char)(x);
            }
            return Cipher_Text;
        }
    }
}
