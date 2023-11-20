using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        #region Permuations Matrices
        int[,] Perm_choice_1 = new int[8, 7] { // Perm_choice_1
                { 57, 49, 41, 33, 25, 17, 9 },
                { 1, 58, 50, 42, 34, 26, 18 },
                { 10, 2, 59, 51, 43, 35, 27 },
                { 19, 11, 3, 60, 52, 44, 36 },
                { 63, 55, 47, 39, 31, 23, 15 },
                { 7, 62, 54, 46, 38, 30, 22 },
                { 14, 6, 61, 53, 45, 37, 29 },
                { 21, 13, 5, 28, 20, 12, 4 } };
        int[,] Perm_choice_2 = new int[8, 6] {
                { 14, 17, 11, 24, 1, 5 },
                { 3, 28, 15, 6, 21, 10 },
                { 23, 19, 12, 4, 26, 8 },
                { 16, 7, 27, 20, 13, 2 },
                { 41, 52, 31, 37, 47, 55 },
                { 30, 40, 51, 45, 33, 48 },
                { 44, 49, 39, 56, 34, 53 },
                { 46, 42, 50, 36, 29, 32 } };
         
         int[,] Permutaion_32 = new int[8, 4] {
                { 16, 7, 20, 21 },
                { 29, 12, 28, 17 },
                { 1, 15, 23, 26 },
                { 5, 18, 31, 10 },
                { 2, 8, 24, 14 },
                { 32, 27, 3, 9 },
                { 19, 13, 30, 6 },
                { 22, 11, 4, 25 } };
         int[,] Expansion = new int[8, 6] {
                { 32, 1, 2, 3, 4, 5 },
                { 4, 5, 6, 7, 8, 9  },
                { 8, 9, 10, 11, 12, 13 },
                { 12, 13, 14, 15, 16, 17 },
                { 16, 17, 18, 19, 20, 21 },
                { 20, 21, 22, 23, 24, 25 },
                { 24, 25, 26, 27, 28, 29 },
                { 28, 29, 30, 31, 32, 1  } };
         int[,] Initial_Perm = new int[8, 8] {
                { 58, 50, 42, 34, 26, 18, 10, 2 },
                { 60, 52, 44, 36, 28, 20, 12, 4 },
                { 62, 54, 46, 38, 30, 22, 14, 6 },
                { 64, 56, 48, 40, 32, 24, 16, 8 },
                { 57, 49, 41, 33, 25, 17, 9, 1  },
                { 59, 51, 43, 35, 27, 19, 11, 3 },
                { 61, 53, 45, 37, 29, 21, 13, 5 },
                { 63, 55, 47, 39, 31, 23, 15, 7 } };
         int[,] Inverse_Perm = new int[8, 8] {
                { 40, 8, 48, 16, 56, 24, 64, 32 },
                { 39, 7, 47, 15, 55, 23, 63, 31 },
                { 38, 6, 46, 14, 54, 22, 62, 30 },
                { 37, 5, 45, 13, 53, 21, 61, 29 },
                { 36, 4, 44, 12, 52, 20, 60, 28 },
                { 35, 3, 43, 11, 51, 19, 59, 27 },
                { 34, 2, 42, 10, 50, 18, 58, 26 },
                { 33, 1, 41, 9, 49, 17, 57, 25  } };
        #endregion

        #region Sbox
        int[,] s_box_1 = new int[4, 16] {
                { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
        int[,] s_box_2 = new int[4, 16] {
                { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
        int[,] s_box_3 = new int[4, 16] {
                { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
        int[,] s_box_4 = new int[4, 16] {
                { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
        int[,] s_box_5 = new int[4, 16] {
                { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
        int[,] s_box_6 = new int[4, 16] {
                { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
        int[,] s_box_7 = new int[4, 16] {
                { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
        int[,] s_box_8 = new int[4, 16] {
                { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };
        #endregion

        #region Functions
        public string Permutaion(int[,] p_table, string arr, int row, int column)
        {
            string tmp = "";
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < column; j++)
                {
                    tmp += arr[p_table[i, j] - 1];
                }
            }
            return tmp;
        }
        public void CircularShiftLeft(List<string> a1, List<string> a2, string key2_28, string key1_28)
        {
            int[] shiftBits = new int[] { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
            int totalShifts = shiftBits.Sum();

            for (int i = 0; i < shiftBits.Length; i++)
            {
                for (int j = 0; j < shiftBits[i]; j++)
                {
                    key1_28 = key1_28.Substring(1) + key1_28[0];
                    key2_28 = key2_28.Substring(1) + key2_28[0];
                }

                a1.Add(key1_28);
                a2.Add(key2_28);
            }
        }

        public List<string> Add_round_keys(List<string> keys_56)
        {
            List<string> keys_48_bit = new List<string>();
            int counter = 0;
            while (counter < keys_56.Count)
            {
                keys_48_bit.Add(Permutaion(Perm_choice_2, keys_56[counter], 8, 6));
                counter++;
            }
            
            return keys_48_bit;
        }

        public string SBOX(List<string> Separated_plain)
        {
            string Sbox_res = "";
            for (int s = 0; s < Separated_plain.Count; s++)
            {
                string t = Separated_plain[s];
                string tmp1 = t[0].ToString() + t[5];
                string tmp2 = t[1].ToString() + t[2] + t[3] + t[4];

                int row = Convert.ToInt32(tmp1, 2);
                int col = Convert.ToInt32(tmp2, 2);

                int result;

                if (s == 0)
                {
                    result = s_box_1[row, col];
                    Sbox_res += Convert.ToString(result, 2).PadLeft(4, '0');
                }
                else if (s == 1)
                {
                    result = s_box_2[row, col];
                    Sbox_res += Convert.ToString(result, 2).PadLeft(4, '0');
                }
                else if (s == 2)
                {
                    result = s_box_3[row, col];
                    Sbox_res += Convert.ToString(result, 2).PadLeft(4, '0');
                }
                else if (s == 3)
                {
                    result = s_box_4[row, col];
                    Sbox_res += Convert.ToString(result, 2).PadLeft(4, '0');
                }
                else if (s == 4)
                {
                    result = s_box_5[row, col];
                    Sbox_res += Convert.ToString(result, 2).PadLeft(4, '0');
                }
                else if (s == 5)
                {
                    result = s_box_6[row, col];
                    Sbox_res += Convert.ToString(result, 2).PadLeft(4, '0');
                }
                else if (s == 6)
                {
                    result = s_box_7[row, col];
                    Sbox_res += Convert.ToString(result, 2).PadLeft(4, '0');
                }
                else if (s == 7)
                {
                    result = s_box_8[row, col];
                    Sbox_res += Convert.ToString(result, 2).PadLeft(4, '0');
                }

            }
            return Sbox_res;
        }

        public List<String> GenerateRoundKeys(string key)
        {
            string key_64 = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');
            List<string> key1_shifted = new List<string>();
            List<string> key2_shifted = new List<string>();
            string key_56 = Permutaion(Perm_choice_1, key_64, 8, 7);

            string key1_28 = key_56.Substring(0, 28);
            string key2_28 = key_56.Substring(28, 28);

            CircularShiftLeft(key1_shifted, key2_shifted, key2_28, key1_28);
            List<string> keys_56 = new List<string>();
            for (int i = 0; i < key2_shifted.Count; i++)
            {
                keys_56.Add(key1_shifted[i] + key2_shifted[i]);
            }
            List<string> keys_16 = Add_round_keys(keys_56);
            return keys_16;
        }

        public string EncryptBlock(string plain_64,List<string>keys_16)
        {
            string plain_56 = Permutaion(Initial_Perm, plain_64, 8, 8);
            List<string> Left_plain = new List<string>();
            List<string> Right_plain = new List<string>();
            string l_plain = plain_56.Substring(0, 32);
            string r_plain = plain_56.Substring(32, 32);
            Left_plain.Add(l_plain);
            Right_plain.Add(r_plain);
            List<string> Separated_plain = new List<string>();
            for (int i = 0; i < 16; i++)
            {
                Left_plain.Add(r_plain);
                string XOR = "";
                Separated_plain.Clear();

                string plain_48 = Permutaion(Expansion, r_plain, 8, 6);

                for (int j = 0; j < plain_48.Length; j++)
                {
                    XOR += (keys_16[i][j] ^ plain_48[j]).ToString();
                }
                for (int w = 0; w < XOR.Length; w += 6)
                {
                    string tmp = "";
                    for (int o = w; o < w + 6; o++)
                    {
                        tmp += XOR[o];
                    }

                    Separated_plain.Add(tmp);
                }
                string sbox_result = SBOX(Separated_plain);
                string last_permutation = Permutaion(Permutaion_32, sbox_result, 8, 4);
                XOR = "";
                for (int k = 0; k < last_permutation.Length; k++)
                {
                    XOR += (last_permutation[k] ^ l_plain[k]).ToString();
                }
                l_plain = r_plain;
                r_plain = XOR;
                Right_plain.Add(r_plain);
            }
            string result_16 = Right_plain[16] + Left_plain[16];

            string cInitial_Permhertext = Permutaion(Inverse_Perm, result_16, 8, 8);
            return cInitial_Permhertext;
        }
        #endregion

        

        public override string Encrypt(string plainText, string key)
        {

            List<string> keys_16 = GenerateRoundKeys(key);

            string plain_64 = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0');

            string cInitial_Permhertext = EncryptBlock(plain_64,keys_16);

            string ct = Convert.ToInt64(cInitial_Permhertext, 2).ToString("X");

            return "0x" + ct;
        }

        public override string Decrypt(string cInitial_PermherText, string key)
        {
            List<string> keys_16 = GenerateRoundKeys(key);
            keys_16.Reverse();
            string cipher_64 = Convert.ToString(Convert.ToInt64(cInitial_PermherText, 16), 2).PadLeft(64, '0');
            string pt = EncryptBlock(cipher_64, keys_16);
            string text = bin2hex(pt);
            return "0x" + text;
        }

        // Binary to hexadecimal conversion
        static string bin2hex(string s)
        {
            Dictionary<string, char> mp = new Dictionary<string, char>()
            {
                {"0000", '0'},
                {"0001", '1'},
                {"0010", '2'},
                {"0011", '3'},
                {"0100", '4'},
                {"0101", '5'},
                {"0110", '6'},
                {"0111", '7'},
                {"1000", '8'},
                {"1001", '9'},
                {"1010", 'A'},
                {"1011", 'B'},
                {"1100", 'C'},
                {"1101", 'D'},
                {"1110", 'E'},
                {"1111", 'F'}
        };
            string hex = "";
            for (int i = 0; i < s.Length; i += 4)
            {
                string ch = "";
                ch = ch + s[i];
                ch = ch + s[i + 1];
                ch = ch + s[i + 2];
                ch = ch + s[i + 3];
                hex = hex + mp[ch];
            }
            return hex;
        }

    }
}