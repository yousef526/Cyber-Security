using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        List<List<int>> permutationsList = new List<List<int>>();
        void Permuteation_tabadel(int[] list, int s, int e)
        {
            if (e != s)

                for (var i = s; i <= e; i++)
                {
                    swapElement(ref list[s], ref list[i]);

                    Permuteation_tabadel(list, s + 1, e);
                    swapElement(ref list[s], ref list[i]);
                }


            else

                permutationsList.Add(new List<int>(list));

        }
        int Fact(int f)
        {
            int fact = 1;
            for (int i = 1; i <= f; i++)
            {
                fact = fact * i;
            }
            return fact;
        }
        void swapElement(ref int x, ref int y)
        {
            int temp = x;
            x = y;
            y = temp;
        }

        public List<int> Analyse(string plainText, string cipherText)
        {

            int col = 2;
            int s = 0, e = 0;
            List<int> key = new List<int>();
            while (col < cipherText.Length)
            {
                int[] listOfKey = new int[col];
                for (int i = 0; i < col; i++)
                {
                    listOfKey[i] = i + 1;
                }
                Permuteation_tabadel(listOfKey, 0, col - 1);
                foreach (var a in permutationsList)
                {
                    key = a;
                    string decryptedciphertext = Encrypt(plainText, key);

                    if (decryptedciphertext.Equals(cipherText, StringComparison.InvariantCultureIgnoreCase))

                        return key;

                }
                col++;
                permutationsList.Clear();

            }

            // No valid key found (pretty much impossible, but C# needs a default return path to compile anyway)
            return new List<int> { -1 };
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            string output = "";
            int column = key.Count();

            int ptNumber = cipherText.Length;
            cipherText = cipherText.ToLower();
            float test = ptNumber / (float)column;
            int mod = ptNumber % column;
            
            double row = Math.Ceiling(test);

            int x = 0, y, c = 0;
            y = (int)row;
            char[,] coar = new char[y, column];
            for (int i = 0; i < column; i++)
            {
                for (int k = 0; k < column; k++)
                {
                    c++;
                    if (key[k] == i + 1)
                        break;
                }

                for (int j = 0; j < row; j++)
                {


                    if (c > mod && mod > 0 && j == row - 1)
                        coar[j, c - 1] = ' ';
                    
                    else
                    {
                        coar[j, c - 1] = cipherText[x];
                        x++;
                    }
                }
                c = 0;
            }

            for (int i = 0; i < row; i++)
            {


                for (int j = 0; j < column; j++)
                {
                    output += coar[i, j];

                }


            }
            
            return output;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            string output = "";
            int column = key.Count();

            int ptNumber = plainText.Length;
            float test = ptNumber / (float)column;

            double row = Math.Ceiling(test);

            int x = 0, y;
            y = (int)row;
            char[,] coar = new char[y, column];
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < column; j++)
                {
                    coar[i, j] = plainText[x];
                    x++;
                    if (x == plainText.Length)
                        break;

                }
            }
            int c = 0;
            for (int i = 0; i < column; i++)
            {
                
                for (int k = 0; k < column; k++)
                {
                    c++;
                    if (key[k] == i + 1)
                        break;
                }

                for (int j = 0; j < row; j++)
                {
                    output += coar[j, c - 1];
                    
                }
                c = 0;

            }
            output = output.ToUpper();
            

            return output;
        }
    }
}
