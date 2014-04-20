'''
This file contains sufficient database operations to insert issuers,subjects,extensions and certificates into databases
'''

import MySQLdb
import datetime


'''
Insert issuer into database
'''
def insertIssuer(db,contry_name,state_name,org_name,org_unit_name,common_name,locality_name):
	contry_name = str(contry_name) or 'NULL'
	state_name = str(state_name) or 'NULL'
	org_name = str(org_name) or 'NULL'
	org_unit_name = str(org_unit_name) or 'NULL'
	common_name = str(common_name) or 'NULL'
	locality_name = str(locality_name) or 'NULL'
	insert_str = "INSERT INTO cert_issuer(issuer_c,issuer_st,issuer_o,issuer_ou,issuer_cn,issuer_l) VALUES(%s,%s,%s,%s,%s,%s)" %(`contry_name`,`state_name`,`org_name`,`org_unit_name`,`common_name`,`locality_name`)
	cursor = db.cursor()
	try:
		cursor.execute(insert_str)
		issuer_id = int(cursor.lastrowid)
		cursor.close()
		return issuer_id
	except Exception, e:
		cursor.close()
		raise Exception('INSERT ISSUER INTO %s Error.' %(`e`))
			

'''
Insert Subject into database
'''
def insertSubject(db,contry_name,state_name,org_name,org_unit_name,common_name,locality_name,pubkey_alg):
    contry_name = str(contry_name) or 'NULL'
    state_name = str(state_name) or 'NULL'
    org_name = str(org_name) or 'NULL'
    org_unit_name = str(org_unit_name) or 'NULL'
    common_name = str(common_name) or 'NULL'
    locality_name = str(locality_name) or 'NULL'
    pubkey_alg = str(pubkey_alg) or 'NULL'
    insert_str = "INSERT INTO cert_subject(sub_c,sub_st,sub_o,sub_ou,sub_cn,sub_l,sub_pk_alg) VALUES(%s,%s,%s,%s,%s,%s,%s)" %(`contry_name`,`state_name`,`org_name`,`org_unit_name`,`common_name`,`locality_name`,`pubkey_alg`)
    cursor = db.cursor()
    try:
        cursor.execute(insert_str)
        sub_id = int(cursor.lastrowid)
        cursor.close()
        return sub_id
    except Exception, e:
        cursor.close()
        raise Exception('INSERT SUBJECT INTO %s Error.' %(`e`))
        


'''
Insert Extensions into database
'''
def insertExtension(db,entry_type,entry_critical,entry_value,cert_id):
    entry_type = str(entry_type) or 'NULL'
    entry_critical = str(entry_critical) or 'NULL'
    entry_value = str(entry_value) or 'NULL'
    insert_str = "INSERT INTO ext_entry(entry_type,entry_critical,entry_value,cert_id) VALUES(%s,%s,%s,%d)" %(`entry_type`,`entry_critical`,`entry_value`,cert_id)
    cursor = db.cursor()
    try:
        cursor.execute(insert_str)
        ext_id = int(cursor.lastrowid)
        cursor.close()
        return ext_id
    except Exception, e:
        cursor.close()
        raise Exception('INSERT EXTENSION INTO %s Error.' %(`e`))


'''
Insert Certificate into database
'''
def insertCert(db,version,serial_num,sig_alg,not_before,not_after):
    version = int(version)
    serial_num = str(serial_num) or 'NULL'
    sig_alg = str(sig_alg) or 'NULL'
    not_before = str(not_before) or 'NULL'
    not_after = str(not_after) or 'NULL'
    insert_str = "INSERT INTO certificate(cert_version,cert_serial_num,cert_sig_alg,cert_not_before,cert_not_after) VALUES(%d,%s,%s,%s,%s)" %(version,`serial_num`,`sig_alg`,`not_before`,`not_after`)
    cursor = db.cursor()
    try:
        cursor.execute(insert_str)
        cert_id = int(cursor.lastrowid)
        cursor.close()
        return cert_id
    except Exception, e:
        cursor.close()
        raise Exception('INSERT CERT INTO %s Error.' %(`e`))

'''
Connect to database;
'''
def connectDB(mhost,mport,muser,mpasswd,mdb):
    try:
        db = MySQLdb.connect(host=mhost,port=mport,user=muser,passwd=mpasswd,db=mdb)
        return db
    except Exception, e:
        print ('DB connection Error: %s.' %(`e`))

'''
Clean database
'''
def cleanDB(db,tables):
    cursor = db.cursor()
    clean_str = 'TRUNCATE '
    for table in tables:
        cursor.execute(clean_str + str(table))
    cursor.close()