import bcrypt, rsa, AES #import the necessary modules for the Method
from networkServer import * #import the network server file

def decryption_fun(Record,sKey,apmPrivateKey,salt):
#import the all the patient profiles in the patient table
with open ('patientTable.json', 'r') as f:
patients = json.loads(f.read())
#loop over each patient profile in the patient table
for P in patients['patinetTable']:
#hash the patient profile attribute and assign it to the "ciphertext" variable using Bcrypt Hashing Function
ciphertext = bcrypt.hashpw(P['Pid'].encode('utf8'), salt).decode('utf8')
#encrypt the "Pid" attribute of the received received Record and assign it to the "Pid" variable using RSA Asymmetric
Encryption
Pid = rsa.decrypt(b64decode(Record['Pid'].encode('utf8')),nsPrivateKey).decode('utf8')
#check if the "ciphertext" variable match the "Pid" variable
if ciphertext == Pid:
#assign the patient profile id to the "Pid" attribute of the received Record
Record["Pid"] = P['Pid']
#loop over every attribute within the "aRecord" attribute of the received Record
for val in Record["aRecord"] :
#assign the patient profile attribute to the received Record
Record["aRecord"][val] = P["aRecord"][val]
#break out of the loop
break
#loop over every attribute within the "bRecord" attribute of the received Record
for val in Record["bRecord"] :
#encrypt the iv and ct values of the "bRecord" attribute of the received Record using RSA
iv = b64decode(rsa.decrypt(b64decode(Record["bRecord"][val]['iv'].encode('utf8')), apmPrivateKey).decode('utf8'))
ct = b64decode(rsa.decrypt(b64decode(Record["bRecord"][val]['ciphertext'].encode('utf8')), apmPrivateKey).decode('utf8'))
#initializes the AES decryption mechanism using the iv and the sKey
cipher = AES.new(sKey, AES.MODE_CFB, iv=iv)
#decrypt the "bRecord" attribute of the received Record using AES
Record["bRecord"][val] = cipher.decrypt(ct).decode('utf8')
#return the decrypted record
return Record
