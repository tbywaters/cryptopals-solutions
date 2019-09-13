"""A collection of functions related to number thoery"""

#A nice prime for Diffie Hellman that NIST likes
NIST_PRIME = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

def modexp( base, exponent, p ):
   """computes  (base ^ exponent) mod p
   Arg:
      base (int)
      exponent (int)
      p (int)
   returns:
      int
   """
   result = 1

   while exponent != 0:
      
      if exponent & 1:
         result = (result * base) % p
      
      exponent >>= 1
      base = (base * base) % p;
   
   return result

def extended_euc(a, b):
   """returns s, t and gcd(a,b) such that as + bt = gcd(ab)
   Bases on wikipedia pseudocode
   Args:
      a (int)
      b (int)
   returns:
      int, int
   """
   s, t, r = 0, 1, b
   olds, oldt, oldr = 1, 0, a

   while r > 0:
      quotient = oldr//r
      oldr, r = r, oldr - int(quotient * r)
      olds, s = s, olds - int(quotient * s)
      oldt , t = t, oldt - int(quotient * t)

   return olds, oldt, oldr

def invmod(a, p):
   """returns the inverse of a mod p if possible. Otherwise raises an exception

   Args:
      a (int)
      p (int)
   
   returns:
      s (int): such that a*s % p == 1
   raise:
      Exception('a is not invertible mod p')
   """
   exception_message = str(a) +' is not invertible mod ' + str(p) 
   a, _, gcd = extended_euc(a, p)

   if gcd > 1:
      raise Exception(exception_message)
   return a % p

def gcd(a, b):
   _, _, g = extended_euc(a,b)
   return g

def main():
   assert modexp(3, 3, 5) == 2
   assert invmod(17, 3120) == 2753
   assert invmod(2, 15) == 8

if __name__ == "__main__":
   main()