# BrotXOR
Simple XOR Reduction Based Attack

Attacking rolling-xor encrypted data with the following assumptions:

 1. You know the size of the key and the character set it consists of
 2. You know enough about the possible character set of the plaintext version
 3. Encryption key repeats a max of 2 times (because encrypted blob is too small)
 4. Otherwise, known attack(s) exist that attempt to determine the size of the key and recover it

note: this work was inspired while reviewing a TM ctf challenge.

The data is rolling-xor encrypted with an md5 hash value. The decryption algorithm simply takes the entered md5 hash value (32 characters) as a string, and xors each of the encrypted bytes, one character at a time from the md5 hash value, in a rolling fashion.

The problem here is that not enough encrypted data with same repeating key exists. Otherwise, the problem could be reduced to [Challenge 6](https://cryptopals.com/sets/1/challenges/6) of the [cryptopals crypto challenges](https://cryptopals.com/). Multiple solutions of said challenge are already published under [1](https://laconicwolf.com/2018/06/30/cryptopals-challenge-6-break-repeating-key-xor/), [2](https://carterbancroft.com/breaking-repeating-key-xor-theory/) and [3](https://thmsdnnr.com/tutorials/javascript/cryptopals/2017/09/16/cryptopals-set1-challenge-6-break-repeating-key-XOR.html).

There are a couple of interesting observations in this scenario that we can exploit to reduce the search space and possibilities needed to decrypt the data, but not fully! It simply gives us an insight to reason about the possible key:value pairs at a given offset in the encrypted payload.

The idea is simple, for a key of 32-byte size, the first byte of the key that decrypts the byte at offset 0 has to be the same 1-byte key that decrypts the byte at offset 32, and so on. And since we know all the possible characters of the key and the plaintext version of the encrypted data, we can limit the decryption step to those inputs, and thereby generating a reduced list of possible key:value pairs. We can further filter the possible key:value pairs such that only alpha, numeric, or not-alpha-numeric values exist.

**Note**: Please check the code for more information.

 1. Get a list of all possible keys and chars for p_1
 2. Get a list of all possible keys and chars for p_2 (Key search space is limited to step 1 list of keys)
 3. p_1 and p_2 lists of keys must match
 4. p_3 is left alone since no matching bytes exist to compare it against
