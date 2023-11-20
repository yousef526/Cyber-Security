using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        int gcd(int M, int e, int n)
        {
            int res = 1;
            for (int i = 0; i < e; i++)
            {
                res = (res * (M % n)) % n;
            }
            return res;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> res = new List<int>();

            int public_key_1 = gcd(alpha,xa,q);
            int public_key_2 = gcd(alpha, xb, q);

            int key_1 = gcd(public_key_2, xa, q);
            int key_2 = gcd(public_key_1, xb, q);
            res.Add(key_1);
            res.Add(key_2);

            return res;
        }
    }
}