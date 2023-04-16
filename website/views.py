from flask import Blueprint, render_template, redirect, url_for, request, Flask
from Crypto.Cipher import AES
import hashlib
import numpy as np
import cv2 as cv2
from matplotlib import pyplot as plt
from PIL import Image
import os 

views = Blueprint("views", __name__)


@views.route("/")
@views.route("/home")
def home():
    return render_template("home.html")

@views.route("/Steganography")
def Steganography():

    return render_template("Steganography.html")

@views.route("/Generate")
def generate():
    return render_template("generate.html")

@views.route("/generate500")
def generate500():
    generated500 =  "a\n" * 500
    return render_template("generated500.html",generated=generated500)


@views.route("/generate1000")
def generate1000():
    generated1000 = "a\n" * 1000
    return render_template("generated1000.html",generated=generated1000)
    
@views.route("/Cryptography")
def Cryptography():

    return render_template("Cryptography.html")

@views.route("/Histogram", methods=['GET','POST'])
def histogram():
    if request.method == "POST":
        q1=request.form["text1"]
        q2=request.form["text2"]
        q3=request.form["text3"]
        if os.path.exists(q1):
            images=cv2.imread(q1)

            red_hist = cv2.calcHist([images],[2], None,[256],[0, 256])
            green_hist =cv2.calcHist([images],[1], None, [256], [0,256])
            blue_hist = cv2.calcHist([images],[0], None, [256], [0,256])

            red_hist.shape

            fig, axs = plt.subplots(1,3, figsize=(15, 4), sharey=True)
            axs[0].plot(red_hist,color='r')
            axs[1].plot(green_hist,color='g')
            axs[2].plot(blue_hist,color='b')
            plt.title(q3)
            plt.savefig(q2)

                             
            return render_template("histogram.html")
        else:
            return render_template("Filedoesnotexist.html")    
    else:
        return  render_template("histogram.html")

@views.route("/About")
def About():

    return render_template("About.html")

@views.route("/LSB", methods=['GET','POST'])
def LSB():
    if request.method =="POST":
        image_name = request.form["text1"]
        file_name = request.form["text2"]
        data = request.form["text3"]
        if os.path.exists(image_name):
            
            def data2binary(data):
                if type(data) == str:
                    return ''.join([format(ord(i),"08b") for i in data])
                elif type(data) == bytes or type(data) == np.ndarray:
                    return [format(i,"08b") for i in data]


            def hideData(image,secret_data):
                secret_data += "#####"      

                data_index = 0
                binary_data = data2binary(secret_data)
                data_length = len(binary_data)
    
                for values in image:
                    for pixel in values:
            
                        r,g,b = data2binary(pixel)

                        if data_index < data_length:
                            pixel[0] = int(r[:-1] + binary_data[data_index])
                            data_index += 1
                        if data_index < data_length:
                            pixel[1] = int(g[:-1] + binary_data[data_index])
                            data_index += 1
                        if data_index < data_length:
                            pixel[2] = int(b[:-1] + binary_data[data_index])
                            data_index += 1
                        if data_index >= data_length:
                            break

                return image

            def encode_text():
                image = cv2.imread(image_name)
                encoded_data = hideData(image,data)
                cv2.imwrite(file_name,encoded_data)

            encode_text()
            return render_template("LSBencoded.html")
        else:
            return render_template("Filedoesnotexist.html")
    else:
        return render_template("LSBencoded.html")


@views.route("/LSBdecode", methods=['GET', 'POST'])
def LSBdecoded():
    if request.method =="POST":
        image_name=request.form["text1"]
        if os.path.exists(image_name):
            def data2binary(data):
                if type(data) == str:
                    return ''.join([format(ord(i),"08b") for i in data])
                elif type(data) == bytes or type(data) == np.ndarray:
                    return [format(i,"08b") for i in data]

            def show_data(image):
                binary_data = ""
                for values in image:
                    for pixel in values:
                        r,g,b = data2binary(pixel)
            
                        binary_data += r[-1]
                        binary_data += g[-1]
                        binary_data += b[-1]

                all_bytes = [binary_data[i: i+8] for i in range (0,len(binary_data),8)]

                decoded_data = ""
                for byte in all_bytes:
                    decoded_data += chr(int(byte,2))
                    if decoded_data[-5:] == "#####":
                        break

                return decoded_data[:-5]
    


            def decode_text():
                
                image = cv2.imread(image_name)
                global text
                text=show_data(image)
                
                
            decode_text()
            return render_template("LSBdecodedoutput.html", data=text)
             
    else:

        return render_template("LSBdecoded.html")
  
@views.route("/Simple", methods=['GET', 'POST'])
def Simple():
    if request.method == "POST":
        image_name = request.form["text1"]
        file_name = request.form["text2"]
        data = request.form["text3"]
        if os.path.exists(image_name):
            end_hex = b"\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82"
            image = Image.open(image_name)
            image.save(file_name, format="PNG")
            with open(f"{file_name}", "ab") as f:
                message = data.encode()
                f.write(message)
            return render_template("home.html")
        else:
            return render_template("Filedoesnotexist.html")
    else:    
        return render_template("Simpleencoded.html")

@views.route("/Simpledecode", methods=['GET','POST'])
def simpledecode():
    if request.method == "POST":
        image_name = request.form["text1"]
        if os.path.exists(image_name):
            end_hex = b"\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82"
            with open (f"{image_name}", "rb") as f:
                content = f.read()
                offset = content.index(end_hex)
                f.seek(offset + len(end_hex))
                data = f.read().decode()
                return render_template("Simpledecodedoutput.html",message=data)
        else:
            return render_template("Filedoesnotexist.html")
    else:
        return render_template("Simpledecoded.html")

@views.route("/Encrypt", methods=['GET','POST'])
def Encrypt():
    if request.method == "POST":
        message = request.form["text"]
#Hashing of the password will automatically give us a 32 bit key in line with the standard length requirement of AES
        password = "SecretPassword".encode()
        key = hashlib.sha256(password).digest()
        mode = AES.MODE_CBC
        IV = 'This is an IVVVV'
# The initialization vector will be 16 bytes and helps randomise the cipher text
        def pad_message(message):
            while len(message)% 16 != 0:
                message = message + " "
            return message
        cipher = AES.new(key, mode, IV)

        padded_message = pad_message(message)

        encrypted_message = cipher.encrypt(padded_message)
        return render_template("AESencryptedoutput.html",SecretMessage=encrypted_message)
    else:
        return render_template("AESencryption.html")




#@views.route("/Decrypt", methods=['GET','POST'])
#def Decrypt():
#    if request.method == "POST":
#        message = request.form["text"]
#        password = b'SecretPassword'
 #       key = hashlib.sha256(password).digest()
#        mode = AES.MODE_CBC
#        IV = 'This is an IVVVV'
#        cipher = AES.new(key,mode,IV)
#        decrypt_text = cipher.decrypt(message)
#        decrypted_text = decrypt_text.rstrip().decode()
#        return render_template("AESdecryptedoutput.html",Decryptedtext=decrypted_text)   
#    else:

#        return render_template("AESdecryption.html")


