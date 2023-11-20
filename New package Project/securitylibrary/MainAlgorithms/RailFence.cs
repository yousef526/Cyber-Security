using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            for (int key = 2; key < 100; key++)
            {
                string CT = Encrypt(plainText, key);
                if (CT.Equals(cipherText, StringComparison.InvariantCultureIgnoreCase))
                    return key;
            }

            return 0;
        }

        public string Decrypt(string cipherText, int key)
        {
            int len22 = cipherText.Length;

            if (cipherText.Length % key != 0)
                for (int i = 0; i < key - 1; i++)
                    cipherText += "x";

            int len = (int)Math.Ceiling((float)cipherText.Length / key);
            string Plain_Text = "";

            for (int i = 0; i < len; i++)
            {
                Plain_Text += cipherText[i];
                for (int j = 1; j < key; j++)
                    Plain_Text += cipherText[i + len * j];
            }


            Plain_Text = Plain_Text.Substring(0, len22);

            return Plain_Text;
        }

        public string Encrypt(string plainText, int key)
        {
            string Cipher_Text = "";

            for (int i = 0; i < key; i++)
                for (int j = i; j < plainText.Length; j += key)
                    Cipher_Text += plainText[j];

            return Cipher_Text;
        }
    }
}
