

def modexp( base, exponent, p ):
   """computes  (base ^ exponent) mod p"""
   result = 1

   while exponent != 0:
      
      if exponent & 1:
         result = (result * base) % p
      
      exponent >>= 1
      base = (base * base) % p;
   
   return result