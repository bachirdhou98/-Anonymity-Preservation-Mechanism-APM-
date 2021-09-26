import bcrypt, rsa, AES #import the necessary modules for the Method
from networkServer import * #import the network server file

def encryption_fun(pID,bRecord,sKey,nsPublicKey,salt):
#the declaration of the new anonymized patient record
newRecord = json.loads('{ "Rid":"", "Pid":"", "aRecord":{}, "bRecord":{}}')
#encrypt the generated random id and assign it to the "Rid" atribute of the aPR
newRecord["Rid"] =b64encode(rsa.encrypt( randomID.encode('utf8'), nsPublicKey)).decode('utf8')
#import the all the patient profiles in the patient table
with open ('patientTable.json', 'r') as f:
patients = json.loads(f.read())
#loop over each patient profile in the patient table
for P in patients['patinetTable']:
#check if the patient profile id match the received patient id
if P['Pid'] == pID:
#hash and encrypt the received patient id and assign it to the "Pid" attribute of the aPR
pID = bcrypt.hashpw(pID.encode('utf8'), salt)
newRecord["Pid"] = b64encode(rsa.encrypt(pID, nsPublicKey)).decode('utf8')
#loop over every attribute within the "aRecord" attribute of the patient profile
for val in P['aRecord']:
#hash the patient profile attribute and assign it to the "hashVal" variable using Bcrypt Hashing Function
hashVal = bcrypt.hashpw(P['aRecord'][val].encode('utf8'), salt)
#encrypt the "hashVal" variable and assign it to the aPR using RSA Asymmetric Encryption
newRecord["aRecord"][val] = b64encode(rsa.encrypt( hashVal, nsPublicKey)).decode('utf8')
#loop over every attribute within the "bRecord" attribute of the patient profile
for val in P['bRecord']:
#assign the patient profile attribute to the received bRecord
bRecord[val] = P['bRecord'][val]
#break out from the loop
break
#loop over every attribute in the bRecord
for val in bRecord :
#initialize the AES encryption mechanism and generate new cipher object of the bRecord attribute
cipher = AES.new(sKey, AES.MODE_CFB)
ct_bytes = cipher.encrypt(bRecord[val].encode('utf8'))
#extract the Initialization Vector and ciphertext from the cipher object
iv = b64encode(cipher.iv).decode('utf8')
ct = b64encode(ct_bytes).decode('utf8')
#create a new json object and assign it to the aPR attribute
newRecord["bRecord"][val] = json.loads('{ "iv":"iv", "ciphertext":"ciphertext"}')
#encrypt the iv and ct variable and assign it to the aPR using RSA Asymmetric Encryption
newRecord["bRecord"][val]["iv"] = b64encode(rsa.encrypt(iv.encode('utf8'),nsPublicKey)).decode('utf8')
newRecord["bRecord"][val]["ciphertext"]= b64encode(rsa.encrypt(ct.encode('utf8'),nsPublicKey)).decode('utf8')
#send the generated aPR to the TV method of the network server and return the result
return transactionValidator (newRecord)
