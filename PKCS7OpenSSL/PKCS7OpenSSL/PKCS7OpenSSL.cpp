// PKCS7OpenSSL.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"

using namespace std;
using namespace ATL;

static unsigned int asn1_simple_hdr_len(const unsigned char* p, unsigned int len) {
	if (len <= 2 || p[0] > 0x31)
		return 0;
	return (p[1] & 0x80) ? (2 + (p[1] & 0x7f)) : 2;
}

/**
* Ref:  
1.https://cpp.hotexamples.com/examples/-/-/PKCS7_sign/cpp-pkcs7_sign-function-examples.html
2. https://blog.mtian.org/2015/06/windowspesign/ (keyword search: 一种更加快速安全的验证方法和一段验证代码)
*/

int main()
{
	string filePath = "D:\\downloadTest\\certTest5\\keyboard_dark_sha1_signature";
	std::ifstream input(filePath, std::ios::binary);
	// copies all data into buffer
	std::vector<char> buffer(std::istreambuf_iterator<char>(input), {});
	const unsigned char* pCertificate = reinterpret_cast<unsigned char*>(buffer.data());

	//Load crt file directly
	X509_LOOKUP* lookup = NULL;
	X509_STORE* store = NULL;
	store = X509_STORE_new();
	lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
	const char* certFile = "D:\\downloadTest\\certTest7\\ca.crt"; //Root Trusted CA certificate
	int res = X509_load_cert_file(lookup, certFile, X509_FILETYPE_PEM);


	//Load cert object from certificate store , put into a temp file then load the temp file.
	X509_LOOKUP * lookup2 = NULL;
	X509_STORE* store2 = NULL;
	store2 = X509_STORE_new();
	lookup2 = X509_STORE_add_lookup(store2, X509_LOOKUP_file());
	CertificateStoreOperation cso;
	PCCERT_CONTEXT cert;
	cso.GetTestCert(&cert);
	cso.ExportCertToFile(&cert, CertificateStoreOperation::OutputFileFormat::PEM);
	int res2 = X509_load_cert_file(lookup2, "1.pem", X509_FILETYPE_PEM);
   
	//Load cert object then construct X509 object -> Get AKI (Authority Key Identifier).
	string filePath2 = "D:\\downloadTest\\certTest7\\crazyfolk.pem";
	std::ifstream input2(filePath2, std::ios::binary);
	// copies all data into buffer
	std::vector<char> buffer2(std::istreambuf_iterator<char>(input2), {});
	const unsigned char* pCertificate2 = reinterpret_cast<unsigned char*>(buffer2.data());
	X509* x509Cert = NULL;
	BIO* cbio, * kbio;
	cbio = BIO_new_mem_buf(pCertificate2, buffer2.size());
	x509Cert = PEM_read_bio_X509(cbio, nullptr, nullptr, nullptr);
	const ASN1_OCTET_STRING* aki = X509_get0_authority_key_id(x509Cert);
	const GENERAL_NAMES* generalNames = X509_get0_authority_issuer(x509Cert);



	//Verification Process
	const char* CAfile = NULL, * CApath = NULL, * prog = NULL;
	PKCS7* pPkcs7 = d2i_PKCS7(NULL, &pCertificate, buffer.size());
	int seqhdrlen = asn1_simple_hdr_len(pPkcs7->d.sign->contents->d.other->value.sequence->data, pPkcs7->d.sign->contents->d.other->value.sequence->length);
	BIO* pContentBio = BIO_new_mem_buf(pPkcs7->d.sign->contents->d.other->value.sequence->data + seqhdrlen, pPkcs7->d.sign->contents->d.other->value.sequence->length - seqhdrlen);
	int nOk = PKCS7_verify(pPkcs7, pPkcs7->d.sign->cert, store2, pContentBio, NULL, PKCS7_NOCRL);
	remove("1.pem");

	//Construct X509 by PKCS7 pointer, then get aki.
	int text = 0;
	X509_STORE* store3 = NULL;
	store3 = X509_STORE_new();
	STACK_OF(X509)* certs = pPkcs7->d.sign->cert;
	for (int i = 0; certs && i < sk_X509_num(certs); i++) {
		X509* x = sk_X509_value(certs, i);
		//const ASN1_OCTET_STRING* myaki = X509_get0_subject_key_id(x);
		//const GENERAL_NAMES* myGeneralNames = X509_get0_authority_issuer(x);
		////Get cert by AKI from PKCS7 pointer
		//PCCERT_CONTEXT targetCert;
		//cso.GetCertByAKI(myaki, &targetCert);
		/*X509_NAME* subjectName = X509_get_subject_name(x);
		char cSubject[1024];
		X509_NAME_oneline(X509_get_subject_name(x), cSubject, sizeof(cSubject));*/
		
	/*	PCCERT_CONTEXT targetCert;
		cso.GetCertByIssuer(x, &targetCert);
		PCCERT_CONTEXT rootCert;
		cso.GetTopCertFromStore(L"Root", targetCert, &rootCert);*/

		PCCERT_CONTEXT *cert = new PCCERT_CONTEXT();
		cso.EnumerateCertFromStore(L"CA", x, cert);
	
		PCCERT_CONTEXT rootCert;
		cso.GetTopCertFromStore(L"Root", *cert, &rootCert);
		delete cert;
		/*d2i_X509(rootCert->pbCertEncoded,)*/
		X509* tempX = d2i_X509(NULL, (const unsigned char**)&(rootCert->pbCertEncoded), rootCert->cbCertEncoded);
		X509_STORE_add_cert(store3, tempX);
		int nOk = PKCS7_verify(pPkcs7, pPkcs7->d.sign->cert, store3, pContentBio, NULL, PKCS7_NOCRL);
	

	}



	std::cout << "Hello World!\n";
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
