import db_util
import cert_util
import x509_parse
import re
import csv

def parseAndUpdateDB(strPEM):
    #check pem format 
    if not re.search(r'-----BEGIN CERTIFICATE-----',strPEM) or not re.search(r'-----END CERTIFICATE-----',strPEM):
        return None

    my_dict = x509_parse.parse_pem(strPEM)
    db = db_util.connectDB(hostname,port,user,passwd,db)
    try:
        cert_id = db_util.insertCert(db,my_dict['Version'],my_dict['Serial No'],my_dict['Sig Alg'],my_dict['Not Before'],my_dict['Not After'])
        issuer = my_dict['Issuer']
        db_util.insertIssuer(db,issuer['C'],issuer['ST'],issuer['O'],issuer['OU'],issuer['CN'],issuer['L'])
        subject = my_dict['Subject']
        db_util.insertSubject(db,subject['C'],subject['ST'],subject['O'],subject['OU'],subject['CN'],subject['L'],my_dict['pKeyAlg']['pKeyType'])
        extension = my_dict['Extension']
        for key in extension.keys():
            value_str = (' ').join(extension[key]['value'])
            db_util.insertExtension(db,key,str(extension[key]['is_critical']),value_str,cert_id)
        db.commit()
    except Exception,e:
        print e
        db.rollback()
    db.close()
    

if __name__ == '__main__':
    
    #clean DB
    db = db_util.connectDB(hostname,port,user,passwd,db)
    tables = ['certificate','cert_subject','cert_issuer','ext_entry']
    db_util.cleanDB(db,tables)
    db.commit()
    db.close()

    with open('top-1m.csv','r') as f:
        reader = csv.reader(f)
        for line in reader:
            strPEM = cert_util.downloadCert(str(line[1]))
            if strPEM:
                #print strPEM
                parseAndUpdateDB(strPEM)
                
    '''
    #do parsing
    #get the number of records
    conn = db_util.connectDB(hostname,port,user,passwd,db)
    cursor = conn.cursor()
    count = 0

    try:
        count_str = "SELECT COUNT(connection_id) FROM SOIC_certs"
        cursor.execute(count_str)
        row = cursor.fetchone()
        count  = row[0] if row else 0
    except Exception,e:
        print ("SELECT COUNT FROM SOIC_certs ERROR:%s" %(`e`))
    print "count is %d" %(count) 

    #for each pem string parse it and store into new db
    piece = 20000
    start = 0
    end  = piece
    i = 1
    try:
        while end < count:
            query_str = "SELECT pem_str FROM SOIC_certs LIMIT %d,%d" %(start,end)
            cursor.execute(query_str)
            row = cursor.fetchone()
            while row:
                #print row[0]
                if parseAndUpdateDB(str(row[0])):
                    print "%f has been parsed" %(i/count)
                    i += 1 
                row = cursor.fetchone()
            start += piece
            end += piece
        query_str = "SELECT pem_str FROM SOIC_certs LIMIT %d,%d" %(start,count)
        cursor.execute(query_str)
        row = cursor.fetchone()
        while row:
            #print row[0]
            if parseAndUpdateDB(str(row[0])):
                print "%f has been parsed" %(i/count)
                i += 1 
            row = cursor.fetchone()    
    except Exception,e:
        print ("SELECT FROM SOIC_certs ERROR:%s" %(`e`))

    cursor.close()
    conn.close()
    '''
