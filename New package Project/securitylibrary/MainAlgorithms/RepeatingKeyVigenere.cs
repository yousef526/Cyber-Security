using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            string keystream = "";
            string keys = "";

            for (int i = 0; i < plainText.Length; i++)
            {
                keystream = keystream + alphabet[((alphabet.IndexOf(cipherText[i]) - alphabet.IndexOf(plainText[i])) + 26) % 26];
            }

            keys = keys + keystream[0];
            for (int i = 1; i < keystream.Length; i++)
            {

                if (plainText.Equals(Decrypt(cipherText, keys)))
                {
                    return keys;
                }
                keys = keys + keystream[i];

            }
            return keystream;


        }

        public string Decrypt(string cipherText, string key)
        {

            cipherText = cipherText.ToLower();
            string pt = "";
            string alphabet = "abcdefghijklmnopqrstuvwxyz";



            for (int i = 0; i < cipherText.Length; i++)
            {
                if (key.Length != cipherText.Length)
                {
                    key = key + key[i];
                }
                pt = pt + alphabet[((alphabet.IndexOf(cipherText[i]) - alphabet.IndexOf(key[i])) + 26) % 26];

            }

            return pt;


        }


        public string Encrypt(string plainText, string key)
        {
            string ct = "";
            string alphabet = "abcdefghijklmnopqrstuvwxyz";


            for (int i = 0; i < plainText.Length; i++)

            {
                if (key.Length != plainText.Length)
                {
                    key = key + key[i];
                }
                ct = ct + alphabet[((alphabet.IndexOf(plainText[i]) + alphabet.IndexOf(key[i])) + 26) % 26];

            }
            return ct;

        }
    }
}