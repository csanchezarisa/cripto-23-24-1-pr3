#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sympy as sp
import random

class UOCRandom:
    """
    Example:
    >>> rnd = UOCRandom()
    >>> rnd.get(1, 100)
    7
    >>> rnd = UOCRandom()
    >>> rnd.get(1, 100)
    7

    Example with seed:
    >>> rnd = UOCRandom(7)
    >>> rnd.get(1, 100)
    42
    >>> rnd = UOCRandom(7)
    >>> rnd.get(1, 100)
    42
    """
    random_values = []

    def __init__(self, seed=None):
        random.seed(seed)

    def get(self, min_value, max_value):
        if UOCRandom.random_values:
            return UOCRandom.random_values.pop()
        return random.randint(min_value, max_value)




# --- IMPLEMENTATION GOES HERE -----------------------------------------------
#  Student helpers (functions, constants, etc.) can be defined here, if needed
uoc_random = UOCRandom()

def generate_p(L: int, q: int) -> int:
    """
    Generates a random p prime number, between 2^(L-1) and 2^L
    :param L: L value of the DSA algorithm
    :returns: random p prime number, between 2^(L-1) and 2^L
    """
    a, b = pow(2, L-1), pow(2, L)
    while True:
        k = uoc_random.get(a, b) // q
        p = k * q + 1
        if sp.isprime(p):
            return p


def generate_g(p: int, q: int) -> int:
    for h in range(2, p):
        g = pow(h, (p-1) // q, p)
        if g > 1:
            return g






def uoc_dsa_genkey(L, N):
    """
    EXERCISE 1.1: Create a pair of DSA keys of num_bits bits
    :L: L value of the DSA algorithm
    :N: N value of the DSA algorithm
    :return: key pair in format [[p,q,g,y], [p,q,g,x]]
    """

    result = [[], []]

    #### IMPLEMENTATION GOES HERE ####
    q = sp.randprime(pow(2, N-1) + 1, pow(2, N))
    p = generate_p(L, q)
    g = generate_g(p, q)
    x = uoc_random.get(1, q)
    y = pow(g, x, p)

    result = [[p, q, g, y],[p, q, g, x]]

    ##################################

    return result


def uoc_dsa_sign(privkey, message):
    """
    EXERCISE 1.2: Sign a message using DSA
    :privkey: Private key in format [p,q,g,x]
    :message: Message to sign
    :return: Signature of the message in [r,s] format 
    """
    result = [0, 0]
        
    #### IMPLEMENTATION GOES HERE ####
    p, q, g, x = privkey

    k = uoc_random.get(1, q-1)
    r = pow(g, k, p) % q
    k_inv = sp.mod_inverse(k, q)
    s = (k_inv * (message + x * r)) % q

    result = [r, s]

    ##################################
    
    return result


def uoc_dsa_verify(pubkey, message, signature):
    """
    EXERCISE 1.3: Verify a DAS signature
    :pubkey: Public key in format [p,q,g,y]
    :message: Message to verify
    :signature: Signature of the message in [r,s] format 
    :return: True if the signature is valid or False
    """

    result = None
   
    #### IMPLEMENTATION GOES HERE ####
    p, q, g, y = pubkey
    r, s = signature

    if 0 >= r or 0 >= s:
        return False

    w = sp.mod_inverse(s, q)
    u1 = message * w % q
    u2 = r * w % q
    gu1 = pow(g, u1, p)
    yu2 = pow(y, u2, p)
    v = (gu1 * yu2 % p) % q

    result = v == r % q
        
    ##################################  

    return result


def uoc_sha1(message, num_bits):
    """
    EXERCISE 2.1: SHA1 hash
    :message: String with the message
    :num_bits: number of bits from 1 to 160 (it will always be a multiple of 4)
    :return: hexadecimal string with the num_bits least significant bits from 
             the SHA1 hash of the message
    """
    result = ''
    
    #### IMPLEMENTATION GOES HERE ####
    
    
    ##################################  
    
    return result


def uoc_sha1_find_preimage(message, num_bits):    
    """
    EXERCISE 2.2: Find SHA1 preimage
    :message: String with the message
    :num_bits: number of bits from 1 to 160 (it will always be a multiple of 4)
    :return: another string (different from message) which has identical 
             uoc_sha1() hash. 
    """
    
    preimg = ""
    
    #### IMPLEMENTATION GOES HERE ####
    
         
    ##################################     
        
    return preimg


def uoc_sha1_collisions(num_bits):
    """
    EXERCISE 2.3: Find SHA1 collisions
    :num_bits: number of bits from 1 to 160 (it will always be a multiple of 4)
    :return: a pair of (different) strings with the same uoc_sha1() hash. 
    """
    
    collisions = (None, None)
    
    #### IMPLEMENTATION GOES HERE ####
    
    
    ##################################   
    
    return collisions





def uoc_dsa_extract_private_key(pubkey, m1, sig1, m2, sig2):
    """
    EXERCISE 3.1: Implements the algorithm used by an attacker to recover 
    :pubkey: Public key in format [p,q,g,y]
    :m1: Message signed
    :sig1: Signature of m1
    :m2: Message signed
    :sig2: Signature of m2
    :privkey: Private key in format [p,q,g,x]
    """

    privkey = None

    # --- IMPLEMENTATION GOES HERE ---


    # --------------------------------

    return privkey



def uoc_dsa_deterministic_sign(privkey, message):
    """
    EXERCISE 3.2: Sign a message using DSA
    :privkey: Private key in format [p,q,g,x]
    :message: Message to sign
    :return: Signature of the message in [r,s] format 
    """
    result = [0, 0]
        
    #### IMPLEMENTATION GOES HERE ####


    ##################################
    
    return result













