"""
    beA.expert BEA-API / EXPERIMENTAL
    ---------------------------------
    Demo script not intented for production
    Version 2.2 / 12.08.2024
    (c) be next GmbH (Licence: GPL-2.0 & BSD-3-Clause)
    https://opensource.org/licenses/GPL-2.0
    https://opensource.org/licenses/BSD-3-Clause

    Dependencies: 
    - pycryptodomex
    - cryptography

    notice: to use this script you first need to
            subscribe to the beA.expert API 
            more info: https://bea.expert/api/
"""

import requests
import json
import base64
import os.path
import configparser
from types import SimpleNamespace
import xml.etree.ElementTree as ET
import platform, shutil, subprocess, time, os

# pip install pycryptodomex
from Cryptodome.Cipher import AES
from Crypto.Hash import SHA256

# pip install cryptography 
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

import tempfile


__current_path = os.getcwd()
__current_path = os.path.dirname(os.path.realpath(__file__))

__config=[]
__config_file=os.path.join(__current_path,'private.config.ini')

if os.path.exists(__config_file):
    __config = configparser.ConfigParser()
    __config.read(__config_file)
    __DEBUG__ = __config["DEBUG"]["PRINT"]
else :
    __config = {
        "BEA_EXPERT_API": {
            "HOST": "http://127.0.0.1:8422/",
            "BEX_IDENT": "..."
        }
    }
    #__config["BEA_EXPERT_API"]["HOST"] = "...."
    #__config["BEA_EXPERT_API"]["BEX_IDENT"] = "...."    
    __DEBUG__ = True


def send_request(__req, __func):    
    url = __config["BEA_EXPERT_API"]["HOST"] + __func
    req_b64 = base64.b64encode(__req.encode('utf-8'))
    data = 'j=' + str(req_b64, "utf-8")
    headers = {
        'Content-type': 'application/x-www-form-urlencoded', 
        'bex-ident': __config["BEA_EXPERT_API"]["BEX_IDENT"]
    }
    
    r = requests.post(url, data=data, headers=headers)
    #r.encoding = r.apparent_encoding
    r.encoding = 'utf-8'

    if __DEBUG__:
        print(__func + ":\n" + r.text)

    try:
        ret = json.loads(r.text.encode('utf-8'))
    except ValueError as e:
        if __DEBUG__:
            print("ValueError in 'send_request'")
            print(e)
        ret = json.loads('{ "error": "Decoding JSON has failed"}')

    return ret


def remove_namespace(doc, namespace):
    ns = u'{%s}' % namespace
    nsl = len(ns)
    for elem in list(doc.iter()):
        if elem.tag.startswith(ns):
            elem.tag = elem.tag[nsl:]


def bea_login(__sw_token, __sw_pin, __token_b64 = ''):
    if __token_b64 == '':
        token_raw = open(__sw_token, 'rb').read()
    else:
        token_raw = base64.b64decode(__token_b64)

    (pkey,cert,add_cert) = serialization.pkcs12.load_key_and_certificates(token_raw, password=__sw_pin.encode("ascii"), backend=default_backend())
    thumbprint = bytearray(cert.fingerprint(hashes.SHA1())).hex()
    cert_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode("ascii")

    if __DEBUG__:
        print('certificate object: ' + str(cert))
        print('certificate private key: ' + str(pkey))
        print('certificate thumbprint: ' + str(thumbprint))

    req = str(json.JSONEncoder().encode({"thumbprint": thumbprint}))
    res_login_step1 = send_request(req, 'bea_login_step1')
    
    if __DEBUG__:
        print(res_login_step1)

    try:
        challengeVal = res_login_step1['challengeVal']
        challengeValidation = res_login_step1['challengeValidation']
        tokenPAOS = res_login_step1['tokenPAOS']
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_login_step1'")
            print(e)
        exit()

    if __DEBUG__:
        print("challengeVal: " + challengeVal)
        print("challengeValidation: " + challengeValidation)
        print("tokenPAOS: " + tokenPAOS)


    challengeVal_signed = base64.b64encode(pkey.sign(
        base64.b64decode(challengeVal),
        padding.PKCS1v15(),
        hashes.SHA256()
    )).decode('ascii')

    challengeValidation_signed = base64.b64encode(pkey.sign(
        base64.b64decode(challengeValidation),
        padding.PKCS1v15(),
        hashes.SHA256()
    )).decode('ascii')

    if __DEBUG__:
        print("challengeVal_signed: " + challengeVal_signed)
        print("challengeValidation_signed: " + challengeValidation_signed)

    return bea_login_step2(tokenPAOS, pkey, cert_b64, challengeVal_signed, challengeValidation_signed)



def bea_login_step2(__tokenPAOS, __pkey, __cert_b64, __challengeVal_signed, __challengeValidation_signed): 

    if __DEBUG__:
        print("cert_b64: \n" + __cert_b64)

    req_json = {
        "tokenPAOS": __tokenPAOS,
        "userCert": __cert_b64,
        "challengeSigned": __challengeVal_signed,
        "validationSigned": __challengeValidation_signed
    }
    req = str(json.JSONEncoder().encode(req_json))
    res_login_step2 = send_request(req, 'bea_login_step2')
    
    if __DEBUG__:
        print(res_login_step2)

    try:
        safeId = res_login_step2['safeId']
        sessionKey = res_login_step2['sessionKey']
        validationKey = res_login_step2['validationKey']
        tokenValidation = res_login_step2['tokenValidation']
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_login_step2'")
            print(e)
        exit()

    if __DEBUG__:
        print("safeId: " + safeId)
        print("sessionKey: " + sessionKey)
        print("validationKey: " + validationKey)
        print("tokenValidation: " + tokenValidation)


    try:
        sessionKey_dec = __pkey.decrypt(
            base64.b64decode(sessionKey),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except:
        sessionKey_dec = b"12345678901234567890123456789000"


    try:
        validationKey_dec = __pkey.decrypt(
            base64.b64decode(validationKey),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except:
        validationKey_dec = b"12345678901234567890123456789000"

    if __DEBUG__:#
        print("sessionKey_dec: ")
        print(sessionKey_dec)
        print("validationKey_dec: ")
        print(validationKey_dec)

    token = bea_login_step3(tokenValidation, validationKey_dec)
    return token, safeId, sessionKey_dec



def bea_login_step3(__tokenValidation, __validationKey):
    req_json = {
        "tokenValidation": __tokenValidation,
        "validationKey": base64.b64encode(__validationKey).decode('ascii')
    }
    req = str(json.JSONEncoder().encode(req_json))
    res_login_step3 = send_request(req, 'bea_login_step3')
    
    if __DEBUG__:
        print(res_login_step3)

    try:
        token = res_login_step3['token']
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_login_step3'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)

    return token


def bea_logout(__token):
    req_json = { 
        "token": __token
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_logout')

    if __DEBUG__:
        print(res)

    try:
        info = res['info']
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_logout'")
            print(e)
        exit()

    if __DEBUG__:
        print("info: " + info)

    return info  



def bea_check_session(__token):
    req_json = { 
        "token": __token
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_check_session')

    if __DEBUG__:
        print(res)

    try:
        info = res['info']
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_check_session'")
            print(e)
        exit()

    if __DEBUG__:
        print("info: " + info)

    return info  


def bea_get_postboxes(__token):
    req_json = { "token": __token }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_get_postboxes')
    
    if __DEBUG__:
        print(res)

    try:
        token = res['token']
        postboxes_struct = json.loads(
            str(json.JSONEncoder().encode(res['postboxes'])), 
            object_hook=lambda 
            d: SimpleNamespace(**d)
        )
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_get_postboxes'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)
        print("postboxes_struct: " + str(postboxes_struct))

    return token, postboxes_struct   



def bea_get_folderoverview(__token, __folderId, __sessionKey):
    req_json = { 
        "token": __token,
        "folderId": __folderId
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_get_folderoverview')
    
    if __DEBUG__:
        print(res)

    try:
        token = res['token']
        messages_struct = json.loads(
            str(json.JSONEncoder().encode(res['messages'])), 
            object_hook=lambda 
            d: SimpleNamespace(**d)
        )
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_get_folderoverview'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)
        print("messages_struct: " + str(messages_struct))

    if(__sessionKey != ''):
        #decrypt subject
        counter = 0
        if messages_struct is not None:
            for m in messages_struct:
                if __DEBUG__:
                    #print(m)
                    print(m.messageId)

                if(m.encSubject.iv != '') and (m.encSubject.tag != '') and (m.encSubject.value != ''):
                    iv = base64.b64decode(m.encSubject.iv)
                    tag = base64.b64decode(m.encSubject.tag)
                    value = base64.b64decode(m.encSubject.value)
                    aesCipher = AES.new(__sessionKey, AES.MODE_GCM, nonce=iv)
                    decSubject = str(aesCipher.decrypt_and_verify(value, tag), 'utf-8')
                else:
                    decSubject = ''

                if __DEBUG__:
                    print(decSubject)

                messages_struct[counter].decSubject = decSubject
                del messages_struct[counter].encSubject #remove the key, its no more needed
                counter = counter + 1

    return token, messages_struct  


def bea_get_folderstructure(__token, __postboxSafeId):
    req_json = { 
        "token": __token,
        "postboxSafeId": __postboxSafeId
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_get_folderstructure')

    if __DEBUG__:
        print(res)

    try:
        token = res['token']
        folder_struct = json.loads(
            str(json.JSONEncoder().encode(res)), 
            object_hook=lambda 
            d: SimpleNamespace(**d)
        )

    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_get_folderstructure'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)

    return token, folder_struct   



def bea_get_identitydata(__token):
    req_json = { 
        "token": __token
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_get_identitydata')

    if __DEBUG__:
        print(res)

    try:
        token = res['token']

        identitydata_struct = json.loads(
            str(json.JSONEncoder().encode(res)), 
            object_hook=lambda 
            d: SimpleNamespace(**d)
        )        
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_get_identitydata'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)

    return token, identitydata_struct       


def bea_get_username(__token, __identitySafeId):
    req_json = { 
        "token": __token,
        "identitySafeId": __identitySafeId
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_get_username')

    if __DEBUG__:
        print(res)

    try:
        token = res['token']
        username = res['userName']
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_get_username'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)
        print("username: " + username)

    return token, username       


def bea_get_messageconfig(__token):
    req_json = { 
        "token": __token
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_get_messageconfig')

    if __DEBUG__:
        print(res)

    try:
        token = res['token']
        messageconfig_struct = json.loads(
            str(json.JSONEncoder().encode(res)), 
            object_hook=lambda 
            d: SimpleNamespace(**d)
        )
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_get_messageconfig'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)

    return token, messageconfig_struct       


def bea_get_addressbook(__token):
    req_json = { 
        "token": __token
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_get_addressbook')

    if __DEBUG__:
        print(res)

    try:
        token = res['token']
        addressbook_struct = json.loads(
            str(json.JSONEncoder().encode(res['addressbook'])), 
            object_hook=lambda 
            d: SimpleNamespace(**d)
        )
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_get_addressbook'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)

    return token, addressbook_struct       


def bea_add_addressbookentry(__token, __identitySafeId):
    req_json = { 
        "token": __token,
        "identitySafeId": __identitySafeId
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_add_addressbookentry')

    if __DEBUG__:
        print(res)

    try:
        token = res['token']
        info = res["info"]
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_add_addressbookentry'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)

    return token, info  


def bea_delete_addressbookentry(__token, __identitySafeId):
    req_json = { 
        "token": __token,
        "addressbookEntrySafeId": __identitySafeId
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_delete_addressbookentry')

    if __DEBUG__:
        print(res)

    try:
        token = res['token']
        info = res["info"]
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_delete_addressbookentry'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)

    return token, info           


def bea_remove_folder(__token, _folderId):
    req_json = { 
        "token": __token,
        "folderId": _folderId
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_remove_folder')

    if __DEBUG__:
        print(res)

    try:
        token = res['token']
        info = res['info']
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_remove_folder'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)

    return token, info       


def bea_add_folder(__token, __parentFolderId, __newFolderName):
    req_json = { 
        "token": __token,
        "parentFolderId": __parentFolderId,
        "newFolderName": __newFolderName
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_add_folder')

    if __DEBUG__:
        print(res)

    try:
        token = res['token']
        add_folder_struct = json.loads(
            str(json.JSONEncoder().encode(res)), 
            object_hook=lambda 
            d: SimpleNamespace(**d)
        )
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_add_folder'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)

    return token, add_folder_struct       


def bea_move_messagetofolder(__token, __folderId, __messageId):
    req_json = { 
        "token": __token,
        "folderId": __folderId,
        "messageId": __messageId
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_move_messagetofolder')

    if __DEBUG__:
        print(res)

    try:
        token = res['token']
        info = res['info']
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_move_messagetofolder'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)

    return token, info       


def bea_move_messagetotrash(__token, __messageId):
    req_json = { 
        "token": __token,
        "messageId": __messageId
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_move_messagetotrash')

    if __DEBUG__:
        print(res)

    try:
        token = res['token']
        info = res['info']
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_move_messagetotrash'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)

    return token, info       


def bea_restore_messagefromtrash(__token, __messageId):
    req_json = { 
        "token": __token,
        "messageId": __messageId
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_restore_messagefromtrash')

    if __DEBUG__:
        print(res)

    try:
        token = res['token']
        info = res['info']
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_restore_messagefromtrash'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)

    return token, info       



def bea_delete_message(__token, __messageId):
    req_json = { 
        "token": __token,
        "messageId": __messageId
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_delete_message')

    if __DEBUG__:
        print(res)

    try:
        token = res['token']
        info = res['info']
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_delete_message'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)

    return token, info       





def decrypt_message_subject(__iv, __tag, __value, __key):
    iv = base64.b64decode(__iv)
    tag = base64.b64decode(__tag)
    value = base64.b64decode(__value)
    aesCipher = AES.new(__key, AES.MODE_GCM, nonce=iv)
    decSubject = str(aesCipher.decrypt_and_verify(value, tag), 'utf-8')
    return decSubject


def decrypt_message_object(encryptedObject, __key):
    # decrypt objectKey with sessionKey
    iv = base64.b64decode(encryptedObject.encKeyInfo.encKey.iv)
    tag = base64.b64decode(encryptedObject.encKeyInfo.encKey.tag)
    value = base64.b64decode(encryptedObject.encKeyInfo.encKey.value)
    aesCipher = AES.new(__key, AES.MODE_GCM, nonce=iv)
    objectKey = aesCipher.decrypt_and_verify(value, tag)

    # decrypt encryptedObject with objectKey
    iv = base64.b64decode(encryptedObject.enc_iv)
    tag = base64.b64decode(encryptedObject.enc_tag)
    value = base64.b64decode(encryptedObject.enc_data)
    aesCipher = AES.new(objectKey, AES.MODE_GCM, nonce=iv)
    return str(aesCipher.decrypt_and_verify(value, tag), 'utf-8')
  
            
def decrypt_message_attachment(encAttachment, att_key):
    # decrypt attachment with att_key
    if(encAttachment.symEncAlgorithm == "http://www.w3.org/2001/04/xmlenc#aes256-cbc") or ((encAttachment.iv == '') and (encAttachment.tag == '')): #CBC
        if(encAttachment.iv == ''):
            data_tmp = base64.b64decode(encAttachment.data)
            iv = data_tmp[:16]
            value = data_tmp[16:]
        else:
            iv = base64.b64decode(encAttachment.iv)
            value = base64.b64decode(encAttachment.data)

        if(att_key == ''):
            aesCipher = AES.new(encAttachment.key, AES.MODE_CBC, iv)
        else:
            aesCipher = AES.new(att_key, AES.MODE_CBC, iv)

        decAttachment = aesCipher.decrypt_and_verify(value)

    else: #GCM
        iv = base64.b64decode(encAttachment.iv)
        tag = base64.b64decode(encAttachment.tag)
        value = base64.b64decode(encAttachment.data)
        aesCipher = AES.new(att_key, AES.MODE_GCM, nonce=iv)
        decAttachment = aesCipher.decrypt_and_verify(value, tag)

    return decAttachment



def get_message_attachment_keys(decryptedObject):
    attachmensKey = []
    root = ET.fromstring(decryptedObject)
    remove_namespace(root, u'http://www.w3.org/2000/09/xmldsig#')
    remove_namespace(root, u'http://www.osci.de/2002/04/osci')
    remove_namespace(root, u'http://schemas.xmlsoap.org/soap/envelope/')
    remove_namespace(root, u'http://www.w3.org/2001/04/xmlenc#')
    remove_namespace(root, u'http://www.w3.org/2001/XMLSchema-instance')

    enc_data = root.findall("EncryptedData")
    att_names = [e.find("CipherData/CipherReference").attrib['URI'] for e in enc_data]
    att_keys = [e.find("KeyInfo/MgmtData").text for e in enc_data]

    if __DEBUG__:
        print('att_names:')
        print(att_names)
        print('att_keys:')
        print(att_keys)

    counter = 0
    for n in att_names:
        tmp_att_k = SimpleNamespace()
        tmp_att_k.name = n.replace("cid:", "")
        tmp_att_k.key = att_keys[counter]
        attachmensKey.append(tmp_att_k)  
        counter = counter + 1  

    return attachmensKey               



def bea_get_message(__token, __messageId, __sessionKey):
    req_json = { 
        "token": __token,
        "messageId": __messageId
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_get_message')
    
    if __DEBUG__:
        print(res)

        #f = open("log_message.txt", "w")
        #_b64 = base64.b64encode(__sessionKey)
        #f.write("sessionKey: " + str(_b64) + "\n" + json.JSONEncoder().encode(res))
        #f.close()

    try:
        token = res['token']
        message_struct = json.loads(
            str(json.JSONEncoder().encode(res)), 
            object_hook=lambda 
            d: SimpleNamespace(**d)
        )

        encSubject = message_struct.metaData.subject
        message_encObjects = json.loads(
            str(json.JSONEncoder().encode(res['encryptedObjects'])), 
            object_hook=lambda 
            d: SimpleNamespace(**d)
        )

        message_encAttachments = json.loads(
            str(json.JSONEncoder().encode(res['attachments'])), 
            object_hook=lambda 
            d: SimpleNamespace(**d)
        )
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_get_message'")
            print(e)
        exit()
    except AttributeError as e: 
        if __DEBUG__:
            print("AttributeError in 'bea_get_message'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)
        print("encSubject: " + str(encSubject))
        print("message_encObjects: " + str(message_encObjects))
        print("message_encAttachments: " + str(message_encAttachments))

    if(__sessionKey != ''):  
        # 1. decrypt subject 
        if(encSubject.iv != '') and (encSubject.tag != '') and (encSubject.value != ''):
            decSubject = decrypt_message_subject(encSubject.iv, encSubject.tag, encSubject.value, __sessionKey)
        else:
            decSubject = ''    

        if __DEBUG__:
            print(decSubject)

        message_struct.metaData.decSubject = decSubject
        del message_struct.metaData.subject

        # 2. decrypt encryptedObjects
        decryptedObjects = []
        attachmensKey = []
        for o in message_encObjects:
            if __DEBUG__:
                print(o)
            
            decObject = decrypt_message_object(o, __sessionKey)

            if __DEBUG__:
                print(decObject)

            tmp_obj = SimpleNamespace()
            tmp_obj.name = o.enc_name
            tmp_obj.data = decObject
            decryptedObjects.append(tmp_obj)
            

            if(o.enc_name == "project_coco"):
                attachmensKey = get_message_attachment_keys(decObject)
                
                if __DEBUG__:
                    print('attachmensKey:')
                    print(attachmensKey)

        message_struct.decryptedObjects = decryptedObjects
        del message_struct.encryptedObjects


        # 3. decrypt attachments
        decryptedAttachments = []
        if message_encAttachments is not None:
            for a in message_encAttachments:
                if __DEBUG__:
                    print(a)

                att_key = ''
                for k in attachmensKey:
                    if(k.name == a.reference):
                        att_key = base64.b64decode(k.key)
                        break

                decAttachment = decrypt_message_attachment(a, att_key)
                
                tmp_att = SimpleNamespace()
                tmp_att.reference = a.reference
                tmp_att.data = decAttachment
                tmp_att.type = a.type
                tmp_att.sizeKB = a.sizeKB
                tmp_att.hashValue = a.hashValue
                decryptedAttachments.append(tmp_att)

        message_struct.attachments = decryptedAttachments                    

    return token, message_struct 




def bea_init_message(__token, __postboxSafeId, __msg_infos, __sessionKey):
    req_json = { 
        "token": __token,
        "postboxSafeId": __postboxSafeId,
        "msg_infos": __msg_infos
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_init_message')

    if __DEBUG__:
        print(res)

    try:
        messageToken = res['messageToken']

        new_message = json.loads(
            str(json.JSONEncoder().encode(res)), 
            object_hook=lambda 
            d: SimpleNamespace(**d)
        )        
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_init_message'")
            print(e)
        exit()

    if __DEBUG__:
        print("messageToken: " + messageToken)
        print('new_message:')
        print(new_message)

    iv = base64.b64decode(new_message.key.iv)
    tag = base64.b64decode(new_message.key.tag)
    value = base64.b64decode(new_message.key.value)
    aesCipher = AES.new(__sessionKey, AES.MODE_GCM, nonce=iv)
    key = aesCipher.decrypt_and_verify(value, tag)        

    return messageToken, key  


def bea_encrypt_message(__token, __postboxSafeId, __msg_infos, __msg_att, __sessionKey, __messageDraft = None):
    messageToken, key = "", ""

    if __messageDraft is None:
        messageToken, key = bea_init_message(__token, __postboxSafeId, __msg_infos, __sessionKey)
    else:
        key = __messageDraft["key"]
        messageToken = __messageDraft["messageToken"]

    msg_infos_struct = json.loads(
        str(json.JSONEncoder().encode(__msg_infos)), 
        object_hook=lambda 
        d: SimpleNamespace(**d)
    )
    msg_att_struc = json.loads(
        str(json.JSONEncoder().encode(__msg_att)), 
        object_hook=lambda 
        d: SimpleNamespace(**d)
    )

    aesCipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = aesCipher.encrypt_and_digest(msg_infos_struct.betreff.encode('utf-8'))

    encSubject_struct = SimpleNamespace()
    encSubject_struct.data = base64.b64encode(ciphertext).decode('utf-8')
    encSubject_struct.tag = base64.b64encode(tag).decode('utf-8')
    encSubject_struct.iv = base64.b64encode(aesCipher.nonce).decode('utf-8')
    encSubject_struct.key = base64.b64encode(key).decode('utf-8')
    encSubject = json.loads(json.dumps(encSubject_struct, default=lambda o: o.__dict__, sort_keys=True, indent=4))
    #encSubject = encSubject_struct
    
    if __DEBUG__:
        print("encSubject:")
        print(encSubject)

    enc_attachment_data = []
    for a in msg_att_struc.attachments:
        aesCipher = AES.new(key, AES.MODE_GCM)
        data_raw = base64.b64decode(a.data.encode('ascii'))
        ciphertext, tag = aesCipher.encrypt_and_digest(data_raw)

        h = SHA256.new()
        h.update(data_raw)

        encAtt_struct = SimpleNamespace()
        encAtt_struct.data = base64.b64encode(ciphertext).decode('utf-8')
        encAtt_struct.tag = base64.b64encode(tag).decode('utf-8')
        encAtt_struct.iv = base64.b64encode(aesCipher.nonce).decode('utf-8')
        encAtt_struct.key = base64.b64encode(key).decode('utf-8')
        encAtt_struct.name = a.name
        encAtt_struct.sizeKB = int(len(data_raw) / 1024)
        encAtt_struct.hash = base64.b64encode(h.digest()).decode('utf-8')
        encAtt_struct.att_type = a.att_type
        encAtt = json.loads(json.dumps(encAtt_struct, default=lambda o: o.__dict__, sort_keys=True, indent=4))

        if __DEBUG__:
            print("encAtt:")
            print(encAtt)

        enc_attachment_data.append(encAtt)
        #enc_attachment_data.append(encAtt_struct)

    req_json = { 
        "messageToken": messageToken,
        "encrypted_data": {
            "encSubject": encSubject,
            "attachments": enc_attachment_data
        }
    }

    if __messageDraft is not None:
        req_json["msg_infos"] = __msg_infos

    return req_json   


def bea_save_message(__token, __postboxSafeId, __msg_infos, __msg_att, __sessionKey, __messageDraft = None):
    req_json = bea_encrypt_message(__token, __postboxSafeId, __msg_infos, __msg_att, __sessionKey, __messageDraft)
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_save_message')
    info = ''
    messageId = ''

    if __DEBUG__:
        print(res)

    try:
        token = res['token']
        messageId = res['messageId']
        if hasattr(res, "info") : info = res['info']
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_save_message'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)

    return token, info, messageId


def bea_send_message(__token, __postboxSafeId, __msg_infos, __msg_att, __sessionKey, __messageDraft = None, no_v2 = False):
    req_json = bea_encrypt_message(__token, __postboxSafeId, __msg_infos, __msg_att, __sessionKey, __messageDraft)
    req = str(json.JSONEncoder().encode(req_json))
    
    if no_v2 is True:
        res = send_request(req, 'bea_send_message_nov2')
    else:
        res = send_request(req, 'bea_send_message')

    if __DEBUG__:
        print(res)

    try:
        validationTokenMSG = res['validationTokenMSG']

        if("validations" in res):
            validations = json.loads(
                str(json.JSONEncoder().encode(res['validations'])), 
                object_hook=lambda 
                d: SimpleNamespace(**d)
            )
        else:
            validations = []

    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_send_message'")
            print(e)
        exit()

    if __DEBUG__:
        print("validationTokenMSG:")
        print(validationTokenMSG)
        print("validations:")
        print(validations)

    token, info, messageId = bea_send_message_validation(validationTokenMSG, validations, __sessionKey, no_v2 = no_v2)
    return token, info, messageId     


def bea_send_message_validation(__validationTokenMSG, __validations, __sessionKey, no_v2 = False):
    dec_validations = []

    for v in __validations:
        iv = base64.b64decode(v.iv)
        tag = base64.b64decode(v.tag)
        value = base64.b64decode(v.data)
        aesCipher = AES.new(__sessionKey, AES.MODE_GCM, nonce=iv)
        decValidation_data = aesCipher.decrypt_and_verify(value, tag)

        decValidation_struct = SimpleNamespace()
        decValidation_struct.data = base64.b64encode(decValidation_data).decode('utf-8')
        decValidation_struct.id = v.id
        decValidation = json.loads(json.dumps(decValidation_struct, default=lambda o: o.__dict__, sort_keys=True, indent=4))  
        dec_validations.append(decValidation)      

    req_json = { 
        "validationTokenMSG": __validationTokenMSG,
        "validations": dec_validations
    }
    req = str(json.JSONEncoder().encode(req_json))
    #res = send_request(req, 'bea_send_message_validation')
    if no_v2 is True: res = send_request(req, 'bea_send_message_validation_nov2')
    else: res = send_request(req, 'bea_send_message_validation')


    if __DEBUG__:
        print(res)

    try:
        token = res['token']
        info = res['info']
        messageId = res['messageId']
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_send_message_validation'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)

    return token, info, messageId   



def bea_get_accessrights(__token):
    req_json = { 
        "token": __token
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_get_accessrights')

    if __DEBUG__:
        print(res)

    try:
        token = res['token']
        accessrights_struct = json.loads(
            str(json.JSONEncoder().encode(res)), 
            object_hook=lambda 
            d: SimpleNamespace(**d)
        )
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_get_accessrights'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)

    return token, accessrights_struct   


def bea_get_configuration(__token):
    req_json = { 
        "token": __token
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_get_configuration')

    if __DEBUG__:
        print(res)

    try:
        token = res['token']
        configuration_struct = json.loads(
            str(json.JSONEncoder().encode(res)), 
            object_hook=lambda 
            d: SimpleNamespace(**d)
        )
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_get_configuration'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)

    return token, configuration_struct    


def bea_search(__token, 
               __identitySafeId = '',
               __identityStatus = '',
               __identityType = '',
               __identityUsername = '',
               __identityFirstname = '',
               __identitySurname = '',
               __identityPostalcode = '',
               __identityCity = '',
               __identityChamberType = '',
               __identityChamberMembershipId = '',
               __identityOfficeName = ''):

    req_json = { 
        "token": __token,
        "identitySafeId": __identitySafeId,
        "identityStatus": __identityStatus,
        "identityType": __identityType,
        "identityUsername": __identityUsername,
        "identityFirstname": __identityFirstname,
        "identitySurname": __identitySurname,
        "identityPostalcode": __identityPostalcode,
        "identityCity": __identityCity,
        "identityChamberType": __identityChamberType,
        "identityChamberMembershipId": __identityChamberMembershipId,
        "identityOfficeName": __identityOfficeName
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_search')

    if __DEBUG__:
        print(res)

    try:
        token = res['token']

        results = json.loads(
            str(json.JSONEncoder().encode(res['results'])), 
            object_hook=lambda 
            d: SimpleNamespace(**d)
        )
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_search'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)

    return token, results    





def bea_init_message_draft(__token, __messageId, __sessionKey):
    req_json = { 
        "token": __token,
        "messageId": __messageId
    }
    req = str(json.JSONEncoder().encode(req_json))
    res = send_request(req, 'bea_init_message_draft')
    
    if __DEBUG__:
        print(res)

    try:
        messageToken = res['messageToken']
        message_struct = json.loads(
            str(json.JSONEncoder().encode(res)), 
            object_hook=lambda 
            d: SimpleNamespace(**d)
        )

        encSubject = message_struct.msg_infos.betreff
        message_encObjects = json.loads(
            str(json.JSONEncoder().encode(res["msg_infos"]['encryptedObjects'])), 
            object_hook=lambda 
            d: SimpleNamespace(**d)
        )

        message_encAttachments = json.loads(
            str(json.JSONEncoder().encode(res["msg_infos"]['attachments'])), 
            object_hook=lambda 
            d: SimpleNamespace(**d)
        )
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bea_get_message'")
            print(e)
        exit()

    if __DEBUG__:
        print("messageToken: " + messageToken)
        print("encSubject: " + str(encSubject))
        print("message_encObjects: " + str(message_encObjects))
        print("message_encAttachments: " + str(message_encAttachments))

    if(__sessionKey != ''): 
        # 1. decrypt key  
        iv = base64.b64decode(message_struct.key.iv)
        tag = base64.b64decode(message_struct.key.tag)
        value = base64.b64decode(message_struct.key.value)
        aesCipher = AES.new(__sessionKey, AES.MODE_GCM, nonce=iv)
        key = aesCipher.decrypt_and_verify(value, tag)    

        # 2. decrypt subject 
        if(encSubject.iv != '') and (encSubject.tag != '') and (encSubject.value != ''):
            decSubject = decrypt_message_subject(encSubject.iv, encSubject.tag, encSubject.value, __sessionKey)
        else:
            decSubject = ''    

        if __DEBUG__:
            print(decSubject)

        message_struct.msg_infos.betreff = decSubject

        # 3. decrypt encryptedObjects
        decryptedObjects = []
        attachmensKey = []
        for o in message_encObjects:
            if __DEBUG__:
                print(o)
            
            decObject = decrypt_message_object(o, __sessionKey)

            if __DEBUG__:
                print(decObject)

            tmp_obj = SimpleNamespace()
            tmp_obj.name = o.enc_name
            tmp_obj.data = decObject
            decryptedObjects.append(tmp_obj)
            

            if(o.enc_name == "project_coco"):
                attachmensKey = get_message_attachment_keys(decObject)
                
                if __DEBUG__:
                    print('attachmensKey:')
                    print(attachmensKey)

        message_struct.msg_infos.decryptedObjects = decryptedObjects
        del message_struct.msg_infos.encryptedObjects


        # 4. decrypt attachments
        decryptedAttachments = []
        if message_encAttachments is not None:
            for a in message_encAttachments:
                if __DEBUG__:
                    print(a)

                att_key = ''
                for k in attachmensKey:
                    if(k.name == a.reference):
                        att_key = base64.b64decode(k.key)
                        break

                decAttachment = decrypt_message_attachment(a, att_key)
                
                tmp_att = SimpleNamespace()
                tmp_att.reference = a.reference
                tmp_att.data = decAttachment
                tmp_att.type = a.type
                tmp_att.sizeKB = a.sizeKB
                tmp_att.hashValue = a.hashValue
                decryptedAttachments.append(tmp_att)

        
        msg_attachments_data = {
            "attachments": []
        }
        msg_attachments_info = []
        for a in decryptedAttachments:
            msg_attachments_data["attachments"].append({
                "name": a.reference,
                "data": base64.b64encode(a.data).decode('utf-8'),
                "att_type": a.type
            })
            msg_attachments_info.append(a.reference)

        #message_struct.attachments = decryptedAttachments       
        message_struct.msg_infos.attachments = msg_attachments_info    


    new_receivers = []
    for r in message_struct.msg_infos.receivers:
        new_receivers.append(r.safeId)

    message_struct.msg_infos.receivers = new_receivers

    # TODO: read XJustiz
    message_struct.msg_infos.is_eeb_response = False
    message_struct.msg_infos.is_eeb = False
    message_struct.msg_infos.dringend = False
    message_struct.msg_infos.pruefen = False
    message_struct.msg_infos.eeb_fremdid = ""
    message_struct.msg_infos.eeb_date = ""
    message_struct.msg_infos.verfahrensgegenstand = ""
    message_struct.msg_infos.eeb_erforderlich = False
    message_struct.msg_infos.eeb_accept = False
    message_struct.msg_infos.xj = True


    # convert simpleNamespce struct to json
    msg_infos = json.loads(json.dumps(message_struct.msg_infos, default=lambda o: o.__dict__, sort_keys=True, indent=4))  
    msg_att = json.loads(json.dumps(msg_attachments_data, default=lambda o: o.__dict__, sort_keys=True, indent=4))                


    message_draft = {
        "messageToken": messageToken,
        "key": key
    }

    return message_draft, msg_infos, msg_att 


def bex_login(sw_token, __sw_pin, token_b64=''):
    if token_b64 == '':
        token_raw = open(sw_token, 'rb').read()
    else:
        token_raw = base64.b64decode(token_b64)

    (pkey,cert,add_cert) = serialization.pkcs12.load_key_and_certificates(token_raw, password=__sw_pin.encode("ascii"), backend=default_backend())
    thumbprint = bytearray(cert.fingerprint(hashes.SHA1())).hex()
    cert_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode("ascii")

    fn_params = {
        "config": {
            "disable_login_v1": False,                  # <- default: false
            "disable_login_v2": False,                  # <- default: true
            "fallback_ksw_v8_extra_session": False,     # <- default: false
            "p12_certificate_file": base64.b64encode(token_raw).decode("ascii"),          # <- default: "" (if not "" with pass -> api decrypt/sign etc)
            "p12_certificate_pass": __sw_pin,                # <- default: "" (if not "" with file -> api decrypt/sign etc)
            "allow_endless_sessions": False,            # <- default: false (needs p12 + pass!)
        },
        "thumbprint": thumbprint
    }
    fn_name = "bex_login_step1"
    fn_args = str(json.JSONEncoder().encode(fn_params))

    
    #result = bea_module.bea_api_request(fn_name, fn_args)
    result = send_request(fn_args, fn_name)
    print(result)

    return result["token"], result["safeId"], result["sessionKey"]




# Example usage:
# convert_p12_to_pem('path/to/your_certificate.p12', 'path/to/your_certificate.pem', 'p12password')
def convert_p12_to_pem(p12_path, pem_out_path, p12_password):
    # Read the .p12 file
    with open(p12_path, 'rb') as p12_file:
        p12_data = p12_file.read()
    
    # Load the private key and certificate from the .p12 file
    private_key, certificate, additional_certificates = load_key_and_certificates(
        p12_data, 
        p12_password.encode(), 
        default_backend()
    )
    
    # Write the private key and certificate(s) to a .pem file
    with open(pem_out_path, 'wb') as pem_file:
        
        # Write the private key
        pem_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
        
        # Write the main certificate
        pem_file.write(
            certificate.public_bytes(serialization.Encoding.PEM)
        )

        # Write any additional certificates
        if additional_certificates:
            for cert in additional_certificates:
                pem_file.write(cert.public_bytes(serialization.Encoding.PEM))

           
                
    print(f'Conversion complete. The PEM file is saved as {pem_out_path}')




def sign_cms_command_line_edition(p12_struct: dict, to_sign_challenge: str, path_to_openssl: str = "") -> str:
    # extract p12_struct
    sw_token = p12_struct["sw_token"] if "sw_token" in p12_struct else ""
    sw_pin = p12_struct["sw_pin"] if "sw_pin" in p12_struct else ""
    token_b64 = p12_struct["token_b64"] if "token_b64" in p12_struct else ""

    is_windows = False

    # define temp dir
    if platform.system() == "Windows":
        tempdir = os.environ['TEMP']
        is_windows = True
    elif platform.system()=="Darwin":
        tempdir = os.environ['TMPDIR']
    else:
        tempdir = tempfile.gettempdir()

    tempdir = os.path.join(tempdir, "bex_python_cms_signer_temp/")
    if os.path.exists(tempdir): shutil.rmtree(tempdir)
    os.makedirs(tempdir)


    # save p12 token to temp
    if token_b64 != '': # save the buffer
        user_p12_file = os.path.join(tempdir, "x.p12")
        token_raw = base64.b64decode(token_b64)
        with open(user_p12_file, 'wb') as file:
            file.write(token_raw)
    else:
        user_p12_file = sw_token

    tmp_pem_file = os.path.join(tempdir, "x.pem")
    convert_p12_to_pem(user_p12_file, tmp_pem_file, sw_pin)


    # define signature input file
    challenge_txt_file = os.path.join(tempdir, "challenge.txt")
    with open(challenge_txt_file, "w") as file:
        file.write(to_sign_challenge)


    # define signature out file
    signature_p7m_file = os.path.join(tempdir, "response.p7m")


    # define openssl exe with path
    openssl_exe = "openssl.exe" if is_windows else "openssl"
    if path_to_openssl != "": openssl_exe = os.path.join(path_to_openssl, openssl_exe)

    # execute signature cmd line
    cmd = [
        openssl_exe, 
        "cms", "-sign", 
        "-in", challenge_txt_file, 
        "-out", signature_p7m_file, 
        "-signer", tmp_pem_file, 
        "-keyopt", "rsa_padding_mode:pss", 
        "-keyopt", "rsa_pss_saltlen:32", 
        "-outform", "pem", 
        "-md", "SHA256", 
        '-passin', "pass:"+sw_pin #"pass:000000"#
    ]
    process = subprocess.Popen(cmd,
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               close_fds=True)

    time.sleep(.5)

    # read response signed
    signature_ugly = ""
    with open(signature_p7m_file, 'r') as file:
        signature_ugly = file.read()

    signature_clean = signature_ugly.replace("-----BEGIN CMS-----", "")\
                                   .replace("-----END CMS-----", "")\
                                   .replace("\r", "")\
                                   .replace("\n", "")


    # cleanup temp dir
    shutil.rmtree(tempdir)


    # return signed value
    return signature_clean




def bex_login_step1(sw_token, sw_pin, token_b64):
    if token_b64 == '':
        token_raw = open(sw_token, 'rb').read()
    else:
        token_raw = base64.b64decode(token_b64)

    (pkey,cert,add_cert) = serialization.pkcs12.load_key_and_certificates(token_raw, password=sw_pin.encode("ascii"), backend=default_backend())
    thumbprint = bytearray(cert.fingerprint(hashes.SHA1())).hex()
    cert_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode("ascii")

    if __DEBUG__:
        print('certificate object: ' + str(cert))
        print('certificate private key: ' + str(pkey))
        print('certificate thumbprint: ' + str(thumbprint))

    fn_params = {
        "thumbprint": thumbprint
    }
    req = str(json.JSONEncoder().encode(fn_params))
    res = send_request(req, 'bex_login_step1')
    
    if __DEBUG__: print("bex_login_step1", res)
    try:
        tokenPAOS = res['tokenPAOS']
        challengeVal = res['challengeVal']
        challengeValidation = res['challengeValidation']

    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bex_login_step1'")
            print(e)
        exit()

    if __DEBUG__: print("tokenPAOS: " + tokenPAOS)
                

    p12_struct = {
        "sw_token": sw_token,
        "sw_pin": sw_pin,
        "token_b64": token_b64,
    }

    challengeVal_signed = sign_cms_command_line_edition(p12_struct, challengeVal)
    challengeValidation_signed = sign_cms_command_line_edition(p12_struct, challengeValidation)

    return bex_login_step2(tokenPAOS, challengeVal_signed, challengeValidation_signed, pkey, cert_b64)






def bex_login_step2(__tokenPAOS, __challengeVal_signed, __challengeValidation_signed, __pkey, cert_b64):
    if __DEBUG__:
        print("cert_b64: \n" + cert_b64)

    req_json = {
        "tokenPAOS": __tokenPAOS,
        "userCert": cert_b64,
        "challengeSigned": __challengeVal_signed,
        "validationSigned": __challengeValidation_signed
    }
    req = str(json.JSONEncoder().encode(req_json))
    res_login_step2 = send_request(req, 'bex_login_step2')
    
    if __DEBUG__:
        print(res_login_step2)

    try:
        safeId = res_login_step2['safeId']
        sessionKey = res_login_step2['sessionKey']
        validationKey = res_login_step2['validationKey']
        tokenValidation = res_login_step2['tokenValidation']
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bex_login_step2'")
            print(e)
        exit()


    try:
        sessionKey_dec = __pkey.decrypt(
            base64.b64decode(sessionKey),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except:
        sessionKey_dec = b"12345678901234567890123456789000"


    try:
        validationKey_dec = __pkey.decrypt(
            base64.b64decode(validationKey),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except:
        validationKey_dec = b"12345678901234567890123456789000"

    if __DEBUG__:#
        print("sessionKey_dec: ")
        print(sessionKey_dec)
        print("validationKey_dec: ")
        print(validationKey_dec)

    token = bex_login_step3(tokenValidation, validationKey_dec)
    return token, safeId, sessionKey_dec



def bex_login_step3(__tokenValidation, __validationKey):
    req_json = {
        "tokenValidation": __tokenValidation,
        "validationKey": base64.b64encode(__validationKey).decode('ascii')
    }
    req = str(json.JSONEncoder().encode(req_json))
    res_login_step3 = send_request(req, 'bex_login_step3')
    
    if __DEBUG__:
        print(res_login_step3)

    try:
        token = res_login_step3['token']
    except KeyError as e: 
        if __DEBUG__:
            print("KeyError in 'bex_login_step3'")
            print(e)
        exit()

    if __DEBUG__:
        print("token: " + token)

    return token
