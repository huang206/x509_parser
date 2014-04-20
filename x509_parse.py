from binascii import hexlify

from pkcs7.asn1_models.X509_certificate import Certificate
from pkcs7_models import X509Certificate, PublicKeyInfo, ExtendedKeyUsageExt

from pkcs7.asn1_models.decoder_workarounds import decode
import chilkat
import datetime

'''
the dictionary of certificate algorithm type comes from http://msdn.microsoft.com/en-us/library/ff635603.aspx
and http://msdn.microsoft.com/en-us/library/ff635835.aspx
'''
CERT_ALG = {
	'''
	hash alg OID
	'''
	'1.2.840.113549.1.1.4' : 'md5RSA',
	'1.2.840.113549.1.1.5' : 'sha1RSA',
	'1.2.840.10040.4.3' : 'sha1DSA',
	'1.3.14.3.2.29' : 'sha1RSA',
	'1.3.14.3.2.15' : 'shaRSA',				
	'1.3.14.3.2.3' : 'md5RSA',
	'1.2.840.113549.1.1.2' : 'md2RSA',
	'1.2.840.113549.1.1.3' : 'md4RSA',
	'1.3.14.3.2.2' : 'md4RSA',
	'1.3.14.3.2.4' : 'md4RSA',
	'1.3.14.7.2.3.1':'md2RSA',
	'1.3.14.3.2.13' : 'sha1DSA',
	'1.3.14.3.2.27' : 'dsaSHA1',
	'2.16.840.1.101.2.1.1.19' : 'mosaicUpdatedSig',
	'1.3.14.3.2.26' : 'sha1NoSign',
	'1.2.840.113549.2.5' : 'md5NoSign',
	'2.16.840.1.101.3.4.2.1' : 'sha256NoSign',
	'2.16.840.1.101.3.4.2.2' : 'sha384NoSign',
	'2.16.840.1.101.3.4.2.3' : 'sha512NoSign',
	'1.2.840.113549.1.1.11' : 'sha256RSA',
	'1.2.840.113549.1.1.12' : 'sha384RSA',
	'1.2.840.113549.1.1.13' : 'sha512RSA',
	'1.2.840.113549.1.1.10' : 'RSASSA-PSS',
	'1.2.840.10045.4.1' : 'sha1ECDSA',
	'1.2.840.10045.4.3.2' : 'sha256ECDSA',
	'1.2.840.10045.4.3.3' : 'sha384ECDSA',
	'1.2.840.10045.4.3.4' : 'sha512ECDSA',
	'1.2.840.10045.4.3' : 'specifiedECDSA',
	'''
	pulic key OID
	'''
	'1.2.840.113549.1.1.1' : 'RSA',
	'1.2.840.10040.4.1' : 'DSA',
	'1.2.840.10046.2.1' : 'DH',
	'1.2.840.113549.1.1.10' : 'RSASSA-PSS',
	'1.3.14.3.2.12' : 'DSA',
	'1.2.840.113549.1.3.1' : 'DH',
	'1.3.14.3.2.22' : 'RSA_KEYX',
	'2.16.840.1.101.2.1.1.20' : 'mosaicKMandUpdSig',
	'1.2.840.113549.1.9.16.3.5' : 'ESDH',
	'1.3.6.1.5.5.7.6.2' : 'NO_SIGN',
	'1.2.840.10045.2.1' : 'ECC',
	'1.2.840.10045.3.1.7' : 'ECDSA_P256',
	'1.3.132.0.34' : 'ECDSA_P384',
	'1.3.132.0.35' : 'ECDSA_P521',
	'1.2.840.113549.1.1.7' : 'RSAES_OAEP',
	'1.3.133.16.840.63.0.2' : 'ECDH_STD_SHA1_KDF'
} 

CA = {
	'1.3.6.1.4.1.34697.2.1' : 'AffirmTrust',
	'1.3.6.1.4.1.34697.2.2' : 'AffirmTrust',
	'1.3.6.1.4.1.34697.2.3' : 'AffirmTrust',
	'1.3.6.1.4.1.34697.2.4' : 'AffirmTrust',
	'1.2.40.0.17.1.22' : 'A-Trust',
	'2.16.578.1.26.1.3.3' : 'Buypass',
	'1.3.6.1.4.1.17326.10.14.2.1.2' : 'Camerfirma',
	'1.3.6.1.4.1.17326.10.8.12.1.2' : 'Camerfirma',
	'1.3.6.1.4.1.6449.1.2.1.5.1' : 'Comodo Group',
	'2.16.840.1.114412.2.1' : 'DigiCert',
	'2.16.840.1.114412.1.3.0.2' : 'DigiCert',
	'2.16.528.1.1001.1.1.1.12.6.1.1.1' : 'DigiNotar',
	'2.16.840.1.114028.10.1.2' : 'Entrust',
	'0.4.0.2042.1.4' : 'ETSI',
	'0.4.0.2042.1.5' : 	'ETSI',
	'1.3.6.1.4.1.13177.10.1.3.10' : 'Firmaprofesional',
	'1.3.6.1.4.1.14370.1.6' : 'GeoTrust',
	'1.3.6.1.4.1.4146.1.1' : 'GlobalSign',
	'2.16.840.1.114413.1.7.23.3' : 'Go Daddy',
	'2.16.840.1.114413.1.7.23.3' : 'Izenpe',
	'2.16.792.1.2.1.1.5.7.1.9' : 'Kamu Sertifikasyon Merkezi',
	'1.3.6.1.4.1.22234.2.5.2.3.1' : 'Keynectis',
	'1.3.6.1.4.1.782.1.2.1.8.1' : 'Network Solutions',
	'1.3.6.1.4.1.8024.0.2.100.1.2' : 'QuoVadis',
	'1.2.392.200091.100.721.1' : 'SECOM Trust Systems',
	'2.16.840.1.114414.1.7.23.3' : 'Starfield Technologies',
	'1.3.6.1.4.1.23223.2' : 'StartCom Certification Authority',
	'1.3.6.1.4.1.23223.1.1.1' : 'StartCom Certification Authority',
	'2.16.756.1.83.21.0' : 'Swisscom',
	'2.16.756.1.89.1.2.1.1' : 'SwissSign',
	'2.16.840.1.113733.1.7.48.1' : 'Thawte',
	'2.16.840.1.114404.1.1.2.4.1' : 'Trustwave*',
	'2.16.840.1.113733.1.7.23.6' : 'VeriSign',
	'1.3.6.1.4.1.6334.1.100.1' : 'Verizon Business (formerly Cybertrust)',
	'2.16.840.1.114171.500.9' : 'Wells Fargo',
	'1.3.6.1.4.1.36305.2' : 'WoSign',
	'2.23.140.1.2.2': 'Comodo',
	'2.16.840.1.114412.1.1' : 'Digicert',
	'2.16.840.1.114412.2' : 'Digicert',
	'1.3.6.1.4.1.4788.2.200.1' : 'D-Trust',
	'2.23.140.1.2.2' : 'Entrust',
	'2.16.840.1.114413.1.7.23.2' : 'GoDaddy (Starfield)',
	'2.16.840.1.113839.0.6.3' : 'Identrust(Commercial)',
	'2.16.840.1.101.3.2.1.1.5' : 'Identrust(Public Sector)',
	'1.3.6.1.4.1.14777.1.2.1' : 'Izenpe',
	'2.16.528.1.1003.1.2.5.6' : 'Logius',
	'1.3.6.1.4.1.8024.0.2.100.1.1' : 'QuoVadis',
	'2.16.840.1.113733.1.7.54' : 'Symantec (Verisign, Thawte, GeoTrust)',
	'1.3.6.1.4.1.34697.1.1' : 'Trend Micro (AffirmTrust)',
	'1.3.6.1.4.1.5237.1.1.3' : 'Trustis',
	'1.3.6.1.4.1.30360.3.3.3.3.4.4.3.0' : 'Trustwave'
}

def x509_parse(derData):
	"""Decodes certificate.
	@param derData: DER-encoded certificate string
	@returns: pkcs7_models.X509Certificate
	"""
	cert = decode(derData, asn1Spec=Certificate())[0]
	x509cert = X509Certificate(cert)
	return x509cert

def parse_pem(pemstr):
	cert = chilkat.CkCert()
	dict = {}
	f = open('temp.crt','w')
	f.write(pemstr)
	f.close()
	cert.LoadFromFile('temp.crt')
	cert.ExportCertDerFile('temp_der.der')
	f = open('temp_der.der','r')
	cer = f.read()
	f.close()
	x509cert = x509_parse(cer)
	tbs = x509cert.tbsCertificate
	if tbs != None:
		'''
		version
		'''
		dict["Version"] = tbs.version + 1
		'''
		Serial no
		'''
		dict["Serial No"] = str(hex(tbs.serial_number))
		'''
		Signatue algorithm
		'''
		dict['Sig Alg'] = CERT_ALG[x509cert.signature_algorithm] if x509cert.signature_algorithm in CERT_ALG.keys() else ''
		'''
		Issuer
		'''
		temp = tbs.issuer.get_attributes()
		temp_dict = {}

		if 'CN' in temp.keys():
			value = temp.get('CN')[0]
		else:
			value = ''
		
		temp_dict['CN'] = value
		
		if 'C' in temp.keys():
			value = temp.get('C')[0]
		else:
			value = ''
		
		temp_dict['C'] = value
		
		if 'L' in temp.keys():
			value = temp.get('L')[0]
		else:
			value = ''
		
		temp_dict['L'] = value
		
		if 'ST' in temp.keys():
			value = temp.get('ST')[0]
		else:
			value = ''
		
		temp_dict['ST'] = value
		
		if 'O' in temp.keys():
			value = temp.get('O')[0]
		else:
			value = ''
		
		temp_dict['O'] = value
		    
		if 'OU' in temp.keys():
			value = temp.get('OU')[0]
		else:
			value = ''
		
		temp_dict['OU'] = value
		
		dict['Issuer'] = temp_dict
        
        '''    		
		Not Before Not After
		'''
		dict['Not Before'] = tbs.validity.get_valid_from_as_datetime() or ''
		dict['Not After'] = tbs.validity.get_valid_to_as_datetime() or ''
		
		'''
		Subject
		'''
		temp = tbs.subject.get_attributes()
		temp_dict = {}
		if 'CN' in temp.keys():
			value = temp.get('CN')[0]
		else:
			value = ''
		
		temp_dict['CN'] = value	    
		
		if 'C' in temp.keys():
			value = temp.get('C')[0]
		else:
			value = ''
		
		temp_dict['C'] = value
		
		if 'L' in temp.keys():
			value = temp.get('L')[0]
		else:
			value = ''
		
		temp_dict['L'] = value
		
		if 'ST' in temp.keys():
			value = temp.get('ST')[0]
		else:
			value = ''
		
		temp_dict['ST'] = value
		
		if 'O' in temp.keys():
			value = temp.get('O')[0]
		else:
			value = ''
		
		temp_dict['O'] = value	
		if 'OU' in temp.keys():
			value = temp.get('OU')[0]
		else:
			value = ''
		
		temp_dict['OU'] = value	
		dict['Subject'] = temp_dict

		'''
		public key algorithm && type
		'''
		if tbs.pub_key_info.alg in CERT_ALG.keys():
			dict['pKeyAlg'] = CERT_ALG[tbs.pub_key_info.alg]
		else:
			dict['pKeyAlg'] = 'UNKNOWN'
		temp_dict = {}

		'''
		Extensions
		'''
		if tbs.authInfoAccessExt:
			son_dict = {}
			son_dict['is_critical'] = tbs.authInfoAccessExt.is_critical
			temp = []
			for aia in tbs.authInfoAccessExt.value:
				temp.append(str(aia.access_location) + ' ' + str(aia.access_method) + ' ' + str(aia.id))
			son_dict['value'] = temp
			temp_dict['authInfoAccessExt'] = son_dict	
	
		if tbs.authKeyIdExt:
			aki = tbs.authKeyIdExt.value
			tmp = []
			if hasattr(aki, "key_id") :
				kd = str(hexlify(aki.key_id))
				tmp.append(kd)
			if hasattr(aki, "auth_cert_sn"):
				acs = str(aki.auth_cert_sn)
				tmp.append(acs)
			if hasattr(aki, "auth_cert_issuer"):
				aci = aki.auth_cert_issuer
				tmp.append(aci)

			son_dict = {}
			son_dict['is_critical'] = tbs.authKeyIdExt.is_critical
			son_dict['value'] = tmp
			temp_dict['authKeyIdExt'] = son_dict

		if tbs.basicConstraintsExt:
			bc = tbs.basicConstraintsExt.value
			son_dict = {}
			son_dict['is_critical'] = tbs.basicConstraintsExt.is_critical
			son_dict['value'] = []
			if bc.ca:
				son_dict['value'].append(str(bc.ca))
			if bc.max_path_len:
				son_dict['value'].append(str(bc.max_path_len))
			temp_dict['basicConstraintsExt'] = son_dict
 		
		if tbs.certPoliciesExt:
			son_dict = {}
			policies = tbs.certPoliciesExt.value
			son_dict['is_critical'] = tbs.certPoliciesExt.is_critical
			temp = []
			for policy in policies:
				temp = [str(policy.id)]
				for qualifier in policy.qualifiers:
					qid = CA[str(qualifier.id)] if  str(qualifier.id) in CA.keys() else str(qualifier.id)
					qua = str(qualifier.qualifier) if qualifier.qualifier else ''
					temp.append( qid + ':' + qua)
			son_dict['value'] = temp
			temp_dict['certPoliciesExt'] = son_dict

		if tbs.crlDistPointsExt:
			son_dict = {}
			son_dict['is_critical'] = tbs.crlDistPointsExt.is_critical
			crls = tbs.crlDistPointsExt.value
			temp = []
			for crl in crls:
				if crl.dist_point:
					temp.append(crl.dist_point)
				if crl.issuer:
					temp.append(crl.issuer)
				if crl.reasons:
					temp.append(crl.reasons)
			son_dict['value'] = temp
			temp_dict['crlDistPointsExt'] = son_dict

		if tbs.extKeyUsageExt:
			eku = tbs.extKeyUsageExt.value
			set_flags = [flag for flag in ExtendedKeyUsageExt._keyPurposeAttrs.values() if getattr(eku, flag)]
			son_dict = {}
			son_dict['is_critical'] = tbs.extKeyUsageExt.is_critical
			son_dict['value'] = set_flags
			temp_dict['extKeyUsageExt'] = son_dict

	
		if tbs.keyUsageExt:
			ku = tbs.keyUsageExt.value
			flags = ["digitalSignature","nonRepudiation", "keyEncipherment",
				 "dataEncipherment", "keyAgreement", "keyCertSign",
				 "cRLSign", "encipherOnly", "decipherOnly",
				]
			
			set_flags = [flag for flag in flags if getattr(ku, flag)]
			son_dict = {}
			son_dict['is_critical'] = tbs.keyUsageExt.is_critical
			son_dict['value'] = set_flags
			temp_dict['KeyUsageExt'] = son_dict
		
		if tbs.policyConstraintsExt:
			pc = tbs.policyConstraintsExt.value
			son_dict = {}
			son_dict['is_critical'] = tbs.policyConstraintsExt.is_critical
			tmp = []
			if str(pc.requireExplicitPolicy):
				tmp.append(str(pc.requireExplicitPolicy))
			if str(pc.inhibitPolicyMapping):
				tmp.append(str(pc.inhibitPolicyMapping))
			son_dict['value'] = tmp
			temp_dict['policyConstraintsExt'] = son_dict
		
		if tbs.subjAltNameExt:
			san = tbs.subjAltNameExt.value
			son_dict = {}
			son_dict['is_critical'] = tbs.subjAltNameExt.is_critical
			son_dict['value'] = san.names
			temp_dict['subjAltNameExt'] = son_dict

				
		if tbs.subjKeyIdExt:
			ski = tbs.subjKeyIdExt.value
			son_dict = {}
			son_dict['is_critical'] = tbs.subjKeyIdExt.is_critical
			son_dict['value'] = [str(hexlify(ski.subject_key_id))] if str(hexlify(ski.subject_key_id)) else []
			temp_dict['subjKeyIdExt'] = son_dict

		
		if tbs.nameConstraintsExt:
			nce = tbs.nameConstraintsExt.value
			subtreeFmt = lambda subtrees: ", ".join([str(x) for x in subtrees])
			tmp = []
			if nce.permittedSubtrees:
				permit = subtreeFmt(nce.permittedSubtrees)
				tmp.append(permit)
			if nce.excludedSubtrees:
				exc = subtreeFmt(nce.excludedSubtrees)
				tmp.append(exc)
			son_dict = {}
			son_dict['is_critical'] = tbs.nameConstrainsExt.is_critical
			son_dict['value'] = tmp
			temp_dict['nameConstraintsExt'] = son_dict
	
	dict['Extension'] = temp_dict
	'''
	signature
	'''
	dict['Signature'] = hexlify(x509cert.signature)
	return dict
