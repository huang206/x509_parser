import socket
import ssl

def downloadCert(domain_name):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)

    ssl_sock = ssl.wrap_socket(s,cert_reqs=ssl.CERT_NONE)
    
    try:
        ssl_sock.connect((domain_name, 443))
    except Exception, e:
        print ('ssl_sock exception: %s.' %(`e`))
        return None
    
    Cert_DER = ssl_sock.getpeercert(binary_form=True)
    strPEM = ssl.DER_cert_to_PEM_cert(Cert_DER)
    return strPEM