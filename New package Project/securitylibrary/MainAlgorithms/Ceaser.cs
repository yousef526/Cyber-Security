using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {

        Dictionary<string, int> charToNumber =
             new Dictionary<string, int>(){
                                  {"a", 0},
                                  {"b", 1},
                                  {"c", 2},
                                  {"d", 3},
                                  {"e", 4},
                                  {"f", 5},
                                  {"g", 6},
                                  {"h", 7},
                                  {"i", 8},
                                  {"j", 9},
                                  {"k", 10},
                                  {"l", 11},
                                  {"m", 12},
                                  {"n", 13},
                                  {"o", 14},
                                  {"p", 15},
                                  {"q", 16},
                                  {"r", 17},
                                  {"s", 18},
                                  {"t", 19},
                                  {"u", 20},
                                  {"v", 21},
                                  {"w", 22},
                                  {"x", 23},
                                  {"y", 24},
                                  {"z", 25}
             };

        Dictionary<int, string> NumberToChar =
          new Dictionary<int, string>(){
                                  {0,"a"},
                                  {1,"b"},
                                  {2,"c"},
                                  {3,"d"},
                                  {4,"e"},
                                  {5,"f"},
                                  {6,"g"},
                                  {7,"h"},
                                  {8,"i"},
                                  {9,"j"},
                                  {10,"k"},
                                  {11,"l"},
                                  {12,"m"},
                                  {13,"n"},
                                  {14,"o"},
                                  {15,"p"},
                                  {16,"q"},
                                  {17,"r"},
                                  {18,"s"},
                                  {19,"t"},
                                  {20,"u"},
                                  {21,"v"},
                                  {22,"w"},
                                  {23,"x"},
                                  {24,"y"},
                                  {25,"z"}
          };
        public string Encrypt(string plainText, int key)
        {
            string cipher_text = "";

            foreach (var x in plainText)
            {
                int num = charToNumber[Char.ToString(x)];
                num += key;
                num = num % 26;
                cipher_text += NumberToChar[num];
            }


            return cipher_text;

        }

        public string Decrypt(string cipherText, int key)
        {
            string plainText = "";
            cipherText = cipherText.ToLower();

            foreach (var x in cipherText)
            {
                int num = charToNumber[Char.ToString(x)];
                
                num -= key;
                
                if (num < 0)
                    num += 26;


                plainText += NumberToChar[num];
            }


            return plainText;
        }

        public int Analyse(string plainText, string cipherText)
        {
            int key = 0;

            int num1 = charToNumber[Char.ToString(plainText[0]).ToLower()];
            int num2 = charToNumber[Char.ToString(cipherText[0]).ToLower()];

            if(num1 <= num2)
            {
                key = num2 - num1;
            }
            else
            {
                num2 += 26;
                key = num2 - num1;
            }
            return key;
        }
    }
}