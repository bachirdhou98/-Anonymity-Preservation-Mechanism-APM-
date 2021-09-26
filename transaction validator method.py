import pymongo #import the mongodb module of python
#connect to the Atlas mongodb cluster
client = pymongo.MongoClient("mongodb+srv://adminEHR:<adminpassword>@ehrdatabase.aqnrs.mongodb.net/myFirstDatabase?retryWrites
=true&w=majority")
#connect to the EHR database
db = client.EHR
#select the patient record collection
patientRecord = db.patientRecord

def transactionValidator (aRecord):
#check if the code bellow doesn't returns an error
try:
#decrypt the "Pid" attribute of the received received aRecord
aRecord["Pid"] = rsa.decrypt(b64decode(aRecord["Pid"].encode('utf8')),nsPrivateKey).decode('utf8')
#insert the received aRecord to the patient record collection of the EHR database in Atlas mongodb cluster
patientRecord.insert_one(aRecord)
return True
#if the code above returns an error
except:
return False
