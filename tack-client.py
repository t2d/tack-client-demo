#!/usr/bin/env python
from __future__ import print_function
import socket
from tlslite import TLSConnection, HandshakeSettings, tackpyLoaded
from TackPin import TackPin
#from sys import exit
import argparse
import shelve
import time

def pinActivation(pin, tack, min_generation):
    '''will only be called when there is a active, valid TACK'''
    if tack.generation >= min_generation: 
        if pin == None:
            pin = TackPin(tack)
            print("New inactive Pin:")
            print(pin)
            
        elif isinstance(pin, TackPin):
            if pin.end_time < time.time(): # pin inactive
                if pin.fitsTack(tack):
                    print("Activating pin:")
                    pin.extend(tack)
                else :
                    pin = TackPin(tack)
                    print("Replacing old inactive pin by new inactive pin:")
            else:
                print("Extending pin:")
                pin.extend(tack)
            print(pin)
                
        else:
            raise TypeError
        
        print("------------------------------")
        assert (pin != None), "This should be a pin."
        return pin


if __name__ == "__main__":

    PATH = "pin.store"
    havePin = False
    haveActivePin = False
    usingTACK = False
    newPins = False
    min_generation = 0
    
    parser = argparse.ArgumentParser(description="TACK client demo")
    parser.add_argument("-s", "--server", help="connect to server", required=True)
    parser.add_argument("-p", "--port", help="connect to port", required=True)
    parser.add_argument("--show", action="store_true", help="show the content of your pin store for that domain")
    args = parser.parse_args()
    
    if not tackpyLoaded:
        print("You need tackpy to test TACK")
        exit(1)
    
    ### get pins from store
    store = shelve.open(PATH)
    sockString = args.server + ":" + args.port # identifier of connection
    
    if store.has_key(sockString):
        pins = store[sockString]
        havePin = True
        for pin in pins:
            try:
                if pin.end_time < time.time():
                    haveActivePin = True
                min_generation = max(min_generation, pin.min_generation) # update min_generation
            except AttributeError:
                pass
    else:
        # print("no pins at all")
        pins = [None, None]
        
    assert  not (haveActivePin and not havePin) , "Cant't have activePin, but no pins"
    
    if args.show:
        for pin in pins:
            print("------------------------------")
            print(pin)
        print("------------------------------")
        exit(0)
    ### end get pins
    
    
    # open socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.server, int(args.port)))
    
    # construct TLS Connection
    conn = TLSConnection(sock)
    settings = HandshakeSettings()
    settings.useExperimentalTackExtension = True
    conn.handshakeClientCert(settings=settings)
    
    if conn.session.tackExt:
        tackExt = conn.session.tackExt
        print("TACK is working on " + sockString)
        print("------------------------------")
        print(tackExt)
        print("------------------------------")
        if tackExt.activation_flags != 0:
            usingTACK = True
        

    # if no active TACKs in TLS-Connection
    if not usingTACK:
        if haveActivePin:
            raise SyntaxError("Active PIN, but no active TACK. Connection might be compromised!")
        elif havePin:
            del store[sockString] # del inactive pin
            print("deleting inactive pin")
        else:
            print(sockString + " doesn't seem to you use TACK.")
        
        store.close()
        conn.close()
        exit(0)
        
        
    if not tackExt.verifySignatures():
        raise SyntaxError("TACK doesn't belong to Cert!")
    # from here exist only one or two valid TACKs
    
    # check tack generations
    '''If a tack has matching pins in the pin store and a generation
       less than the stored min_generation, then that tack is revoked and 
       the client SHALL send a fatal "certificate_revoked" error alert.'''
    for tack in tackExt.tacks:
        if tack.min_generation < min_generation:
            raise Error("Certificate revoked")
            
    # TODO: "those two pins MUST reference different public keys"
    if tackExt.activation_flags % 2 == 1: # 1 and 3
        pins[0] = pinActivation(pins[0], tackExt.tacks[0], min_generation)
    if tackExt.activation_flags >= 2: # 2 and 3
        pins[1] = pinActivation(pins[1], tackExt.tacks[1], min_generation)
    
    # sync min_generation
    for pin in pins:
        if pin != None:
            min_generation = max(min_generation, pin.min_generation) # update min_generation
    for pin in pins:
        if pin != None:
            pin.min_generation = min_generation

    # write and close    
    # print("writing: " + str(pins))
    store[sockString] = pins
    store.close()
    conn.close() 
    
