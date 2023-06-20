from django.shortcuts import render, redirect
from .models import User
import struct
from django.contrib.auth import authenticate, login
from .models import UserProfile
import hashlib

def rotate_left(value, n):
    return ((value << n) | (value >> (32 - n))) & 0xFFFFFFFF


def SHA1(password):

    '''Similar implementation to SHA1'''
    """Input < 2^64, block size 512, output 160"""

    # Step 1: Padding
    padd_pass = password.encode() # encodes the password string into bytes.
    padd_len = (56 - (len(padd_pass) + 1) % 64) % 64 # ensures the resulting length is a multiple of 64
    
    # appending a b'\x80' byte (binary 10000000) followed by zero bytes (b'\x00') to achieve a length that is a multiple of 64 bytes.
    padd_pass += b'\x80' + b'\x00' * padd_len 

    # Step 2: Append length
    # The length of the original password is appended to the padded password (multiplied by 8 to represent the number of bits.)
    # >Q: Pack a single unsigned long long integer (64 bits) into a binary representation. (most significant byte comes first (big endian))
    padded_len = struct.pack('>Q', len(password) * 8)
    padd_pass += padded_len

    # Step 3: hash buffer is initialized with five 32-bit variables (h0 to h4), each assigned an initial value
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # Step 4: padded password is processed in 512-bit blocks. 
    # loop processes the padd_pass in 512-bit blocks (64 bytes) by iterating over the range with a step size of 64. 
    # The block variable represents each block in the iteration.
    for i in range(0, len(padd_pass), 64):
        block = padd_pass[i:i+64]

        # loop initializes the message schedule (w) with the first 16 words from the current block. 
        # Each word is extracted from the block by unpacking 4 bytes using 
        w = [0] * 80
        for j in range(16):
            w[j] = struct.unpack('>I', block[j*4:j*4+4])[0] # Pack a single unsigned integer (32 bits) into a binary representation

        # The message schedule is expanded to 80 words (w[16] to w[79]) using a combination of XOR and rotation operations
        for j in range(16, 80):
            w[j] = rotate_left((w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16]), 1)

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

    # loop processes the message schedule (w) in the SHA-1 specific operations. 
    # Based on the index j, it calculates different logical functions (f) and constant values (k) for each iteration.
        for j in range(80):
            if j < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif j < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif j < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
    # Update the temporary variables ased on the SHA-1 compression function operations, including rotation operations.
            temp = (rotate_left(a, 5) + f + e + k + w[j]) & 0xFFFFFFFF
            e = d
            d = c
            c = rotate_left(b, 30)
            b = a
            a = temp
    #  update the hash variables (h0 to h4) with the new values obtained after processing each block, performing addition modulo 2^32.
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    # Step 5: Output the 160-bit message digest
    # packs the final values of the hash variables into a binary representation.
    # Then it converts the packed value to a hexadecimal string 
    msg_dig = struct.pack('>5I', h0, h1, h2, h3, h4)
    return msg_dig.hex().upper()
    

def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        
        # I) Store only hash code instead of raw passwords (identification):
        # Hash the password using SHA1 manual hashing method
        custom_hashed_password = SHA1(password)
        # We can use hashlib's buil-in sha256 algorithm too:
        # custom_hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

        # Create the user and save the hashed password in the UserProfile model
        user = User.objects.create_user(username=username, password=custom_hashed_password)
        UserProfile.objects.create(user=user, custom_hashed_password=custom_hashed_password)
        
        return redirect('login')
    
    return render(request, 'register.html')

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        #II) When a user requests an authentication, for an attempt to verification, create a hash code of password and compare the stored one:
        user = authenticate(request, username=username, password=SHA1(password))
        # we can use built-in sha256: 
        # user = authenticate(request, username=username, password=hashlib.sha256(password.encode('utf-8')).hexdigest())

        # III) If a match occurs, then authenticate the user. If authentication fails, inform the user properly
        if user is not None:
            login(request, user)
            return redirect('welcome')
        else:
            return render(request, 'login.html', {'error': 'Invalid credentials'})
    return render(request, 'login.html')

def welcome(request):
    return render(request, 'welcome.html')
