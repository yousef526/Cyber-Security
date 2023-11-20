using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.AES;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        /// 

        long gcd(long M, long e, int n)
        {
            long res = 1;
            for (int i = 0; i < e; i++)
            {
                res = (res * (M % n)) % n;
            }
            return res;
        }
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> x = new List<long>();
            x.Add(gcd(alpha, k, q));
            x.Add((gcd(y, k, q) * m) % q);
            return x;

        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            ExtendedEuclid xloc = new ExtendedEuclid();   

            int k_inverse = xloc.GetMultiplicativeInverse((int)gcd(c1, x, q), q);
            int ahm = (c2 * k_inverse) % q;
            

            return ahm;
        }
    }
}
