using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        Dictionary<string, string> charTochar =
             new Dictionary<string, string>(){
                                  {"a","" },
                                  {"b", ""},
                                  {"c", ""},
                                  {"d", ""},
                                  {"e", ""},
                                  {"f", ""},
                                  {"g", ""},
                                  {"h", ""},
                                  {"i", ""},
                                  {"j", ""},
                                  {"k", ""},
                                  {"l", ""},
                                  {"m", ""},
                                  {"n", ""},
                                  {"o", ""},
                                  {"p", ""},
                                  {"q", ""},
                                  {"r", ""},
                                  {"s", ""},
                                  {"t", ""},
                                  {"u", ""},
                                  {"v", ""},
                                  {"w", ""},
                                  {"x", ""},
                                  {"y", ""},
                                  {"z", ""}
             };

        public string Analyse(string plainText, string cipherText)
        {
            #region Initaliztions 
            char[] alphabet = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
            string key = "";
            plainText = new string(plainText.ToCharArray().Distinct().ToArray());
            cipherText = new string(cipherText.ToCharArray().Distinct().ToArray()).ToLower();
            string x_alpha = "";

            // for loop used to get only letters of cipher from alphabet
            for (int i = 0; i < alphabet.Length; i++)
            {
                if (cipherText.Contains(alphabet[i]))
                    continue;
                else
                    x_alpha += alphabet[i];
            }

            Dictionary<char, String> pairs = new Dictionary<char, String>();

            // for to initalize the keys in the Dict in order
            for (int i = 0; i < alphabet.Length; i++)
            {
                pairs.Add(alphabet[i],"");
            }
            #endregion

            #region Get key solution
            //used to get every char in cipher text to be from key
            for (int i = 0; i < plainText.Length; i++)
            {
                if (pairs.ContainsKey(plainText[i]))
                {
                    pairs[plainText[i]] = cipherText[i].ToString();
                }
                

            }
            
            // for loop used to put what left of alphabet in main dict
            int count = 0;
            foreach (var item in pairs.Keys.ToList())
            {
                if(pairs[item]=="")
                {
                    pairs[item] = x_alpha[count].ToString();
                    count++;
                }
            }

            // for loop to get the key
            foreach (var item in pairs)
            {
                key += item.Value;
            }
            #endregion

            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            char[] alphabet = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
            Dictionary<string, string> charToNumberCopy = new Dictionary<string, string>();
            string plainText = "";

            for (int i = 0; i < key.Length; i++)
            {
                string x =Char.ToString(alphabet[i]) ;
                string y = Char.ToString(key[i]);
                charToNumberCopy.Add(y, x);
            }

            foreach (var item in cipherText)
            {
                plainText += charToNumberCopy[Char.ToString(item).ToLower()];
            }


            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            int counter = 0;

            Dictionary<string, string> charToNumberCopy = new Dictionary<string, string>();
            foreach (var item in charTochar.Keys)
            {
                charToNumberCopy.Add(item, Char.ToString(key[counter]));
                counter++;
            }

            foreach (var item in plainText)
            {
                cipherText += charToNumberCopy[Char.ToString(item)];
            }

            return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher = cipher.ToLower();
            int[] charFreq = new int[26];
            string ans = "";
            for (int i = 0; i < cipher.Length; i++)
            {
                if (cipher[i] == ' ')
                    continue;
                charFreq[cipher[i] - 'a'] += 1;
            }
            int mxFreq = 0;
            for (int i = 0; i < 26; i++)
            {
                mxFreq = Math.Max(mxFreq, charFreq[i]);
            }

            
            int idx = 0;

            for (int j = 0; j < 26; j++)
            {
                if (mxFreq == charFreq[j])
                {
                    idx = j;
                    break;
                }

            }

            int shift = 'e' - 'a';
            shift -= idx;

            for (int i = 0; i < cipher.Length; i++)
            {

                if (cipher[i] == ' ')
                {
                    ans += ' ';
                }
                else
                {
                    int cur = cipher[i] - 'a';
                    cur += shift;
                    cur = (cur < 0 ? cur + 26 : cur > 25 ? cur - 26 : cur);
                    ans += (char)(cur + 'a');
                }

            }
            return ans;
        }
    }
}

