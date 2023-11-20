using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        string alphabet = "abcdefghiklmnopqrstuvwxyz";
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            #region declartions
            //char[,] cipherMatrix = new char[5, 5];
            Dictionary<char, string> cipherMatrix = new Dictionary<char, string>();
            Dictionary<string, char> indexMatrix = new Dictionary<string, char>();


            string key2 = key + alphabet;
            string final_key = new string(key2.ToCharArray().Distinct().ToArray());

            int counter_key = 0;
            // key: row+coulmn
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    //cipherMatrix[i,j] = final_key[counter_key];
                    cipherMatrix.Add(final_key[counter_key], i + "" + j);
                    indexMatrix.Add(i + "" + j, final_key[counter_key]);
                    counter_key++;
                }
            }

            #endregion

            List<string> digraph = new List<string>();

            for (int i = 0; i < cipherText.Length; i += 2)
            {
                digraph.Add(Char.ToString(cipherText[i]) + cipherText[i + 1]);
            }

            return create_plain(cipherMatrix, digraph, indexMatrix);
        }

        public string Encrypt(string plainText, string key)
        {

            #region declartions
            //char[,] cipherMatrix = new char[5, 5];
            Dictionary<char, string> cipherMatrix = new Dictionary<char, string>();
            Dictionary<string, char> indexMatrix = new Dictionary<string, char>();


            string key2 = key + alphabet;
            string final_key = new string(key2.ToCharArray().Distinct().ToArray());
            
            int counter_key = 0;
            // key:char  value:row+coulmn
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    cipherMatrix.Add(final_key[counter_key], i + "" + j);
                    indexMatrix.Add(i + "" + j, final_key[counter_key]);
                    counter_key ++;
                }   
            }

            #endregion

            List<string> digraph = new List<string>();

            for (int i = 0; i < plainText.Length;)
            {

                if (i == plainText.Length - 1)
                {

                    digraph.Add(Char.ToString(plainText[i]) + "x");


                    break;
                }
                if (plainText[i] != plainText[i + 1])
                {
                    digraph.Add(Char.ToString(plainText[i]) + plainText[i + 1]);
                    i += 2;
                }
                else
                {
                    digraph.Add(Char.ToString(plainText[i]) + "x");
                    i++;
                }

            }

            return create_cipher(cipherMatrix,digraph,indexMatrix);
        }

        public string create_cipher(Dictionary<char, string> cipher_Mat,List<string>digraph, Dictionary<string, char> indexMatrix)
        {
            string cipher_text = "";
            
            
            for (int i = 0; i < digraph.Count; i++)
            {
                //chars of the string
                char first_char = digraph[i][0];
                char second_char = digraph[i][1];

                //index for each char 
                string first_index = cipher_Mat[first_char];
                string second_index = cipher_Mat[second_char];

                #region
                // first case in same row
                if (first_index[0] == second_index[0])
                {
                    int x = Int16.Parse(Char.ToString(first_index[1]));
                    int y = Int16.Parse(Char.ToString(second_index[1]));

                    x++;
                    y++;

                    int c = x % 5;
                    int c2 = y % 5;

                    first_char =  indexMatrix[Int16.Parse(Char.ToString(first_index[0])) + "" + c];
                    second_char = indexMatrix[Int16.Parse(Char.ToString(first_index[0])) + "" + c2];

                }
                // second case in same column
                else if (first_index[1] == second_index[1])
                {
                    int x = Int16.Parse(Char.ToString(first_index[0]));
                    int y = Int16.Parse(Char.ToString(second_index[0]));

                    x++;
                    y++;

                    int c = x % 5;
                    int c2 = y % 5;

                    first_char =  indexMatrix[c + "" + Int16.Parse(Char.ToString(first_index[1]))];
                    second_char = indexMatrix[c2 + "" + Int16.Parse(Char.ToString(second_index[1]))];
                }
                #endregion

                //different places
                else
                {
                    int first_column = Int16.Parse(Char.ToString(first_index[1]));
                    int second_column = Int16.Parse(Char.ToString(second_index[1]));
                    int first_row = Int16.Parse(Char.ToString(first_index[0]));
                    int second_row = Int16.Parse(Char.ToString(second_index[0]));
                    // to know which has the biggest index

                    
                        
                    
                        // to get cipher letter for first letter
                        first_char = indexMatrix[first_row + "" + second_column];

                        // to get cipher letter for second letter
                        second_char = indexMatrix[second_row + "" + first_column];
                    


                }

                cipher_text = cipher_text + first_char + second_char;
            }
            return cipher_text.ToUpper();
        }

        public string create_plain(Dictionary<char, string> cipher_Mat, List<string> digraph, Dictionary<string, char> indexMatrix)
        {
            string plain_text = "";


            for (int i = 0; i < digraph.Count; i++)
            {
                //chars of the string
                char first_char = digraph[i][0];
                char second_char = digraph[i][1];

                //index for each char 
                string first_index = cipher_Mat[first_char];
                string second_index = cipher_Mat[second_char];

                #region
                // first case in same row
                if (first_index[0] == second_index[0])
                {
                    int x = Int16.Parse(Char.ToString(first_index[1]));
                    int y = Int16.Parse(Char.ToString(second_index[1]));

                    x--;
                    y--;

                    int c = x == -1 ? 4 : x;
                    int c2 = y == -1 ? 4 : y;

                    first_char = indexMatrix[Int16.Parse(Char.ToString(first_index[0])) + "" + c];
                    second_char = indexMatrix[Int16.Parse(Char.ToString(first_index[0])) + "" + c2];

                }
                // second case in same column
                else if (first_index[1] == second_index[1])
                {
                    int x = Int16.Parse(Char.ToString(first_index[0]));
                    int y = Int16.Parse(Char.ToString(second_index[0]));

                    x--;
                    y--;

                    int c = x == -1 ? 4 : x;
                    int c2 = y == -1 ? 4 : y;

                    first_char = indexMatrix[c + "" + Int16.Parse(Char.ToString(first_index[1]))];
                    second_char = indexMatrix[c2 + "" + Int16.Parse(Char.ToString(second_index[1]))];
                }
                #endregion

                //different places
                else
                {
                    int first_column = Int16.Parse(Char.ToString(first_index[1]));
                    int second_column = Int16.Parse(Char.ToString(second_index[1]));
                    int first_row = Int16.Parse(Char.ToString(first_index[0]));
                    int second_row = Int16.Parse(Char.ToString(second_index[0]));

                    //to get cipher letter for first letter

                    first_char = indexMatrix[first_row + "" + second_column];

                    //to get cipher letter for second letter

                    second_char = indexMatrix[second_row + "" + first_column];
                }

                plain_text = plain_text + first_char + second_char;
            }

            plain_text = removeCharX(plain_text);
            return plain_text;
        }

        //used for create_plain only
        string removeCharX(string my_word)
        {
            string plain_text = "";
            for (int i = 0; i < my_word.Length; i++)
            {
                if (my_word[i] != 'x')
                    plain_text += my_word[i];
                else
                {
                    if (i == my_word.Length - 1)
                    {

                    }
                    else if (my_word[i - 1] == my_word[i + 1] && i % 2 != 0)
                        continue;
                    else
                        plain_text += my_word[i];
                }
            }


            return plain_text;
        }
        
    }
}