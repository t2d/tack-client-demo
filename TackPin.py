#!/usr/bin/env python
from __future__ import print_function
from tack.structures.Tack import Tack
from tack.util.Time import Time
import time

class TackPin():
    
    def __init__(self, tack):
        assert isinstance(tack, Tack), "Obj was no TACK"
        self.initial_time = time.time()
        self.end_time = 0
        self.public_key = tack.public_key
        self.min_generation = tack.min_generation
        
    def __str__(self):
        s = """initial_time   = %s
end_time       = %s
public_key     = %s
min_generation = %s""" %\
        (Time.posixTimeToStr(self.initial_time),
        Time.posixTimeToStr(self.end_time),
        self.public_key,
        self.min_generation)
        
        return s

    def fitsTack(self, tack):
        return self.public_key.getRawKey() == tack.public_key.getRawKey()

            
    def extend(self, tack): # which means also activate
        if self.fitsTack(tack):
            diff = time.time() - self.initial_time
            self.end_time = time.time() + min(diff, 2592000) # max 30days
            
            '''If a tack has matching pins and a min_generation greater than the 
               stored min_generation, the stored value SHALL be set to the tack's value.'''
            self.min_generation = tack.min_generation
            
        else:
            raise SyntaxError("active TACK and pin don't fit!")
