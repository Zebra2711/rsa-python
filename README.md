# RSA python

[RSA Cryptography Specifications Version 2.0](https://datatracker.ietf.org/doc/html/rfc2437)

## Preview
<div align = center>
  
![2024-12-31_12-58](https://github.com/user-attachments/assets/7b4f9b9f-5133-4bad-89a0-37e32a44d7d7)

</div>

## Support:
- [ ] GUI
- [x] CLI
- [x] Key size: 128,256,512,1024,2048,4069. Larger not tested
- [x] Generate prime with mutil-core (It only use 2 CPU core to generate 2 prime number)
- [x] Fast Large-Integer Extended GCD
- [x] Cypher text Base64 endcode
- [x] Plant text UTF-8 endcode

## Test

I tested with a key size of 4096 bits. The plaintext length was 197, and it took 34.58 seconds to encrypt and decrypt.
Sometimes, encryption took only 4.48 seconds with the same key size and plaintext length. With a 256-bit key, it took only 67.27 milliseconds.

/PS: This was just my test, so it is not an average value, but I think I did my best.

My system infor: Linux 6.13.5-arch1-1, 11th Gen Intel(R) Core(TM) i5-11400H

## Special Thanks

[xcgd](https://github.com/kavyasreedhar/sreedhar-xgcd-hardware-ches2022.git) - For fast large-integer extended GCD
