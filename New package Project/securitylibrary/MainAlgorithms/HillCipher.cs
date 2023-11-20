using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> mayBeKey = new List<int>();
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            mayBeKey = new List<int>(new[] { i, j, k, l });
                            List<int> aa = Encrypt(plainText, mayBeKey);
                            if (aa.SequenceEqual(cipherText))
                            {
                                return mayBeKey;
                            }
                        }
                    }
                }
            }
            throw new InvalidAnlysisException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> Ptext = new List<int>();
            int Rows = 0;
            // Caculate Matrixsize of key first
            int[,] keyMatrixInv = new int[3, 3];
            int[,] keyMatrix = new int[3, 3];
            int n = (int)Math.Sqrt(key.Count);
            //check key size
            if (n == 2)
            {
                keyMatrixInv = new int[2, 2];
                Rows = 2;
                int B = key[0] * key[3] - key[1] * key[2];
                int A = 1 / B;
                if (A == 0) { throw new InvalidAnlysisException(); }
                keyMatrixInv[0, 0] = A * key[3];
                keyMatrixInv[0, 1] = A * -key[1];
                keyMatrixInv[1, 0] = A * -key[2];
                keyMatrixInv[1, 1] = A * key[0];
            }
            if (n == 3)
            {
                Rows = 3;
                int coun = 0;
                for (int i = 0; i < 3; i++)
                {
                    for (int j = 0; j < 3; j++)
                    {   //check nonagative numbers
                        if (key[coun] >= 0)
                        {
                            keyMatrix[i, j] = key[coun];
                            coun++;
                        }
                        else
                        {
                            throw new InvalidAnlysisException();
                        }
                    }
                }
                int[,] subdetermatrix = new int[3, 3];
                //caculate dat(K)
                int dete = 0;
                dete = det(keyMatrix);
                dete = ((dete % 26) + 26) % 26;
                List<int> subdet = new List<int>();
                for (int x = 0; x < 3; x++)
                {
                    for (int j = 0; j < 3; j++)
                    {

                        subdet = new List<int>();
                        for (int w = 0; w < 3; w++)
                        {
                            for (int q = 0; q < 3; q++)
                            {
                                if (w != x & q != j) { subdet.Add(keyMatrix[w, q]); }
                            }
                        }
                        subdetermatrix[x, j] = ((((subdet[0] * subdet[3]) - (subdet[1] * subdet[2])) + 26 + 26) % 26) % 26;
                    }
                }
                //check det not equal 0
                if (dete == 0 & GCD(26, dete) != 1)
                { throw new InvalidAnlysisException(); }
                //Caculate b 
                int b = 0;
                int modresult = 1;
                int diff = 26 - dete;
                int c = 0;
                while (c < 1)
                {
                    if (modresult % diff == 0)
                    {
                        c = modresult / diff;
                    }
                    modresult = modresult + 26;
                }
                b = 26 - c;
                if (b <= 0) { throw new InvalidAnlysisException(); }
                int[,] Keyinerse = new int[3, 3];
                keyMatrixInv = new int[3, 3];
                for (int x = 0; x < 3; x++)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        Keyinerse[x, j] = ((b * (int)Math.Pow(-1, x + j) * subdetermatrix[x, j]) + 26) % 26;
                    }
                }

                for (int x = 0; x < 3; x++)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        keyMatrixInv[x, j] = Keyinerse[j, x];
                    }
                }

            }
            // Caculate Matrixsize of ciphertext Second
            int Cols = cipherText.Count / n;
            int count = 0;
            int[,] Cmatrix = new int[n, Cols];
            for (int col = 0; col < Cols; col++)
            {
                for (int row = 0; row < n; row++)
                {
                    Cmatrix[row, col] = cipherText[count];
                    count++;
                }
            }
            int[,] plainmatrix = new int[n, Cols];
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < Cols; j++)
                {
                    plainmatrix[i, j] = 0;
                    for (int k = 0; k < n; k++)
                    {
                        plainmatrix[i, j] += keyMatrixInv[i, k] * Cmatrix[k, j];
                    }
                    plainmatrix[i, j] = plainmatrix[i, j] % 26;

                }
            }
            for (int col = 0; col < Cols; col++)
            {
                for (int row = 0; row < n; row++)
                {
                    Ptext.Add((((plainmatrix[row, col] % 26) + 26) % 26));

                }

            }

            return Ptext;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> MatrixMultiply(List<List<int>> KeyMatrix, List<int> small)
        {
            List<int> ans = new List<int>();

            int n = KeyMatrix.Count();
            for (int i = 0; i < n; i++)
            {
                int cur = 0;
                for (int j = 0; j < n; j++)
                {
                    cur += KeyMatrix[i][j] * small[j];
                    cur %= 26;
                }
                ans.Add(cur);
            }
            return ans;
        }
        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> ans = new List<int>();
            int n = (int)Math.Sqrt(key.Count());
            List<List<int>> KeyMatrix = new List<List<int>>();

            int s = 0;

            for (int i = 0; i < n; i++)
            {
                List<int> tmp = new List<int>();
                for (int j = 0; j < n; j++)
                {
                    tmp.Add(key[s++]);
                }
                KeyMatrix.Add(tmp);
            }
            int all = plainText.Count();

            for (int i = 0; i <= all - n; i += n)
            {
                List<int> small = new List<int>();
                for (int j = 0; j < n; j++)
                {
                    small.Add(plainText[i + j]);
                }
                List<int> SmallAnswer = MatrixMultiply(KeyMatrix, small);
                for (int z = 0; z < SmallAnswer.Count(); z++)
                {
                    ans.Add(SmallAnswer[z]);
                }
            }
            return ans;

        }

        public string Encrypt(string plainText, string key)
        {
            List<int> text = new List<int>();
            List<int> keys = new List<int>();
            for (int i = 0; i < plainText.Length; i++)
            {
                text.Add(plainText[i] - 'a');
            }
            for (int i = 0; i < key.Length; i++)
            {
                keys.Add(key[i] - 'a');
            }
            List<int> tmp = new List<int>();
            tmp = Encrypt(text, keys);
            string ans = "";
            for (int i = 0; i < tmp.Count; i++)
            {
                ans += (tmp[i] + 'a');
            }

            return ans;
        }
        public int Find_determinant_2(List<int> matrix)
        {
            int ans = 0;
            ans = (matrix[0] * matrix[3]) - (matrix[1] * matrix[2]);
            return ans;
        }
        public int Find_determinant_3(List<List<int>> matrix)
        {
            int ans = 0;
            if (matrix.Count == 4)
            {
                ans = (matrix[0][0] * matrix[1][1]) - (matrix[0][1] * matrix[1][0]);
            }
            else
            {
                for (int i = 0; i < 3; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        matrix[i].Add(matrix[i][j]);
                    }
                }
                int left = 0, right = 0;

                for (int i = 0; i < 3; i++)
                {
                    int inside = 1, l = i;
                    for (int j = 0; j < 3; j++)
                    {
                        inside *= matrix[j][l];
                        l++;
                    }
                    left += inside;
                }

                for (int i = 2; i < 5; i++)
                {
                    int inside = 1, l = i;
                    for (int j = 0; j < 3; j++)
                    {
                        inside *= matrix[j][l];
                        l--;
                    }
                    right += inside;
                }
                ans = (left - right);

            }

            return ans;
        }
        public List<List<int>> get_Factors(List<List<int>> matrix)
        {
            //List<List<int>> matrix = new List<List<int>>();
            //List<int> tmp = new List<int> { 2, -5, 3 };
            //List<int> tmp1 = new List<int> { 0, 7, -2 };
            //List<int> tmp2 = new List<int> { -1, 4, 1 };
            List<List<int>> coFac = new List<List<int>>();
            List<int> tmp1 = new List<int>();
            tmp1.Add(matrix[1][1]);
            tmp1.Add(matrix[1][2]);
            tmp1.Add(matrix[2][1]);
            tmp1.Add(matrix[2][2]);
            int det1 = Find_determinant_2(tmp1);

            tmp1.Clear();

            tmp1.Add(matrix[1][0]);
            tmp1.Add(matrix[1][2]);
            tmp1.Add(matrix[2][0]);
            tmp1.Add(matrix[2][2]);
            int det2 = Find_determinant_2(tmp1);
            tmp1.Clear();

            tmp1.Add(matrix[1][0]);
            tmp1.Add(matrix[1][1]);
            tmp1.Add(matrix[2][0]);
            tmp1.Add(matrix[2][1]);
            int det3 = Find_determinant_2(tmp1);
            tmp1.Clear();
            List<int> First_Row = new List<int>();

            First_Row.Add(det1);
            First_Row.Add(det2);
            First_Row.Add(det3);
            coFac.Add(First_Row);


            tmp1.Add(matrix[0][1]);
            tmp1.Add(matrix[0][2]);
            tmp1.Add(matrix[2][1]);
            tmp1.Add(matrix[2][2]);
            det1 = Find_determinant_2(tmp1);
            tmp1.Clear();

            tmp1.Add(matrix[0][0]);
            tmp1.Add(matrix[0][2]);
            tmp1.Add(matrix[2][0]);
            tmp1.Add(matrix[2][2]);
            det2 = Find_determinant_2(tmp1);
            tmp1.Clear();

            tmp1.Add(matrix[0][0]);
            tmp1.Add(matrix[0][1]);
            tmp1.Add(matrix[2][0]);
            tmp1.Add(matrix[2][1]);
            det3 = Find_determinant_2(tmp1);
            tmp1.Clear();

            List<int> Second_Row = new List<int>();
            Second_Row.Add(det1);
            Second_Row.Add(det2);
            Second_Row.Add(det3);

            coFac.Add(Second_Row);


            //
            tmp1.Add(matrix[0][1]);
            tmp1.Add(matrix[0][2]);
            tmp1.Add(matrix[1][1]);
            tmp1.Add(matrix[1][2]);
            det1 = Find_determinant_2(tmp1);
            tmp1.Clear();

            tmp1.Add(matrix[0][0]);
            tmp1.Add(matrix[0][2]);
            tmp1.Add(matrix[1][0]);
            tmp1.Add(matrix[1][2]);
            det2 = Find_determinant_2(tmp1);
            tmp1.Clear();

            tmp1.Add(matrix[0][0]);
            tmp1.Add(matrix[0][1]);
            tmp1.Add(matrix[1][0]);
            tmp1.Add(matrix[1][1]);
            det3 = Find_determinant_2(tmp1);
            tmp1.Clear();
            List<int> Third_Row = new List<int>();

            Third_Row.Add(det1);
            Third_Row.Add(det2);
            Third_Row.Add(det3);

            coFac.Add(Third_Row);

            return coFac;
        }
        public int modInverse(int A, int M)
        {
            for (int X = 1; X < M; X++)
                if (((A % M) * (X % M)) % M == 1)
                    return X;
            return 0;
        }
        public List<int> MatrixMult3_3(List<List<int>> matrix1, List<List<int>> matrix2)
        {
            List<int> tmp = new List<int>();
            List<int> ans = new List<int>();
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    int cur = 0;

                    for (int k = 0; k < 3; k++)
                    {
                        cur += matrix1[i][k] * matrix2[k][j];
                    }
                    tmp.Add(cur);

                }
            }
            for (int i = 0; i < 3; i++)
            {
                for (int j = i; j < 9; j += 3)
                {
                    ans.Add(tmp[j] % 26);
                }
            }
            return ans;
        }
        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            List<int> ans = new List<int>();

            List<List<int>> plain = new List<List<int>>();
            List<List<int>> cipher = new List<List<int>>();
            int s = 0;

            for (int i = 0; i < 3; i++)
            {
                List<int> tmp = new List<int>();
                List<int> tmp1 = new List<int>();
                for (int j = 0; j < 3; j++)
                {
                    tmp.Add(plain3[s]);
                    tmp1.Add(cipher3[s]);
                    s++;
                }
                plain.Add(tmp);
                cipher.Add(tmp1);
            }
            int determ = Find_determinant_3(plain);
            determ = ((determ % 26) + 26) % 26;

            List<int> top = new List<int>();
            List<List<int>> coFactors = new List<List<int>>();
            coFactors = get_Factors(plain);
            List<List<int>> Inverse = new List<List<int>>();
            for (int i = 0; i < 3; i++)
            {
                List<int> temp = new List<int>();
                for (int j = 0; j < 3; j++)
                {
                    temp.Add(coFactors[j][i]);
                }
                Inverse.Add(temp);
            }
            int modinv = modInverse(determ, 26);
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    Inverse[i][j] *= modinv * (int)(Math.Pow(-1, i + j));
                    Inverse[i][j] = ((Inverse[i][j] % 26) + 26) % 26;
                }
            }

            ans = MatrixMult3_3(Inverse, cipher);

            return ans;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }

        public int GCD(int a, int b)
        {

            while (a != 0 && b != 0)
            {
                if (a > b)
                    a %= b;
                else
                    b %= a;
            }

            return a | b;

        }

        public int det(int[,] keymatrix)
        {
            int det_value = 0;
            if (keymatrix.Length == 9)
            {
                for (int j = 0; j < 3; j++)
                {
                    det_value = det_value + (keymatrix[0, j] * (keymatrix[1, (j + 1) % 3] * keymatrix[2, (j + 2) % 3] - keymatrix[1, (j + 2) % 3] * keymatrix[2, (j + 1) % 3]));
                }
            }
            else
            {
                det_value = ((keymatrix[0, 0] * keymatrix[1, 1]) - (keymatrix[1, 0] * keymatrix[0, 1]));

            }


            return (det_value);


        }
    }
}
