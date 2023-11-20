using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {

        //n = p*q
        /*gcd function to caluclate M^e mod p*q
         * in case of decrypt we cal mutlvipcative inverse then C^d mod p*q
         * inverse cal by send e and Q(p*q) = (p-1)*(q-1)
         */
        int gcd(int M,int e,int n)
        {
            int res = 1;
            for (int i = 0; i < e; i++)
            {
                res = (res * (M % n)) % n;
            }
            return res;
        }
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;// to get the number will be used for Q(n)

            return gcd(M, e, n);
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            ExtendedEuclid x = new ExtendedEuclid();
            int n = p * q;
            int d = x.GetMultiplicativeInverse(e,(q-1)*(p-1));

            return gcd(C, d, n);

        }
    }
}
