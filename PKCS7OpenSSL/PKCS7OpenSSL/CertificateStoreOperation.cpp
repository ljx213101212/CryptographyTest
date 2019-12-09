#include "CertificateStoreOperation.h"


int char2int(char input)
{
	if (input >= '0' && input <= '9')
		return input - '0';
	if (input >= 'A' && input <= 'F')
		return input - 'A' + 10;
	if (input >= 'a' && input <= 'f')
		return input - 'a' + 10;
	throw std::invalid_argument("Invalid input string");
}

// This function assumes src to be a zero terminated sanitized string with
// an even number of [0-9a-f] characters, and target to be sufficiently large
void hex2bin(const char* src, char* target)
{
	while (*src && src[1])
	{
		*(target++) = char2int(*src) * 16 + char2int(src[1]);
		src += 2;
	}
}
void CertificateStoreOperation::GetTestCert(PCCERT_CONTEXT* cert) {


	HCERTSTORE hSystemStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM, // System store will be a 
								// virtual store
		0,                      // Encoding type not needed 
								// with this PROV
		NULL,                   // Accept the default HCRYPTPROV
		CERT_SYSTEM_STORE_CURRENT_USER,
		// Set the system store location in the
		// registry
		L"Root");               // Could have used other predefined 
								// system stores
								// including Trust, CA, or Root
	CRYPT_HASH_BLOB blob;
	const char* hexSubjectKeyIdentifier = "0a007b4107ce41a0b1b2772e84fddcc4913f6180";
	char hexSubjectKeyIdentifiderBin[20];
	hex2bin(hexSubjectKeyIdentifier, hexSubjectKeyIdentifiderBin);
	char hexSubjectKeyIdentifiderBinReverse[20];
	//std::reverse_copy(std::begin(hexSubjectKeyIdentifiderBin), std::end(hexSubjectKeyIdentifiderBin), std::begin(hexSubjectKeyIdentifiderBinReverse));
	blob.cbData = strlen(hexSubjectKeyIdentifier) / 2;
	blob.pbData = (BYTE*)hexSubjectKeyIdentifiderBin;
	*cert = CertFindCertificateInStore(hSystemStore,
		MY_ENCODING_TYPE,
		0,
		CERT_FIND_KEY_IDENTIFIER,
		&blob,
		NULL);

	CertCloseStore(
		hSystemStore,
		CERT_CLOSE_STORE_CHECK_FLAG);
}


void CertificateStoreOperation::ExportCertToFile(PCCERT_CONTEXT *cert, OutputFileFormat  fileFormat) {

	DWORD num = 1;
	/* open root certificate store */
	HCERTSTORE hCertStore = CertOpenSystemStore(NULL, L"ROOT");

	PCCERT_CONTEXT pCert = *cert;
	/* if you need save certificate in PEM */
	DWORD size = 0;
	CryptBinaryToString(pCert->pbCertEncoded, pCert->cbCertEncoded, CRYPT_STRING_BASE64HEADER, nullptr, &size);
	std::vector<wchar_t> pem(size);
	CryptBinaryToString(pCert->pbCertEncoded, pCert->cbCertEncoded, CRYPT_STRING_BASE64HEADER,
		pem.data(), &size);

	if (fileFormat == CertificateStoreOperation::OutputFileFormat::PEM) {
		std::wstring pem_cert = std::to_wstring(num) + L".pem";
		std::wofstream pem_cert_file(pem_cert, std::ios::binary | std::ios::out);
		pem_cert_file.write(pem.data(), pem.size() - 1);
	}

	/* or if you need save certificate in binary form (DER encoding)*/
	if (fileFormat == CertificateStoreOperation::OutputFileFormat::DER) {
		std::string der_cert = std::to_string(num) + ".cer";
		std::ofstream der_cert_file(der_cert, std::ios::binary | std::ios::out);
		der_cert_file.write(reinterpret_cast<char*>(pCert->pbCertEncoded), pCert->cbCertEncoded);
	}
}


void CertificateStoreOperation::GetCertByIssuer(const X509* x, PCCERT_CONTEXT* cert){
	std::vector<char> cIssuer(1024, '\0');
	X509_NAME* issuer = X509_get_issuer_name(x);
	const ASN1_STRING* data;
	data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(issuer, 0));
	HCERTSTORE hSystemStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM, // System store will be a 
								// virtual store
		0,                      // Encoding type not needed 
								// with this PROV
		NULL,                   // Accept the default HCRYPTPROV
		CERT_SYSTEM_STORE_CURRENT_USER,
		// Set the system store location in the
		// registry
		L"Root");               // Could have used other predefined 
								// system stores
								// including Trust, CA, or Root
	
	const unsigned char* pder[1024];
	size_t sizeIssuerLength = 0;
	//Get encoded issuer data.
	X509_NAME_get0_der(issuer, pder, &sizeIssuerLength);
	CERT_NAME_BLOB blob;
	blob.cbData = sizeIssuerLength;
	blob.pbData = (BYTE*)*pder;
	*cert = CertFindCertificateInStore(hSystemStore,
		MY_ENCODING_TYPE,
		0,
		CERT_FIND_ISSUER_NAME,
		&blob,
		NULL);

	CertCloseStore(
		hSystemStore,
		CERT_CLOSE_STORE_CHECK_FLAG);
}

/**
Useful method:
1. X509_NAME_entry_count
2. ASN1_STRING* issuerData = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(issuer, 4));
3. X509_NAME_oneline(X509_get_subject_name(x), cSubject.data(), sizeof(cSubject)); (don't know how to use oneline data yet)
4. CertStrToName(X509_ASN_ENCODING, (LPCWSTR)cIssuer.data(), CERT_OID_NAME_STR, NULL, IssuerData, &bIssuerLength, NULL); (might be useful later).
*/
void CertificateStoreOperation::GetCertBySubject(const X509* x, PCCERT_CONTEXT* cert) {

	std::vector<char> cSubject(1024,'\0');
	X509_NAME* name = X509_get_subject_name(x);
	const ASN1_STRING* data;
	data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name,0));

	HCERTSTORE hSystemStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM, // System store will be a 
								// virtual store
		0,                      // Encoding type not needed 
								// with this PROV
		NULL,                   // Accept the default HCRYPTPROV
		CERT_SYSTEM_STORE_CURRENT_USER,
		// Set the system store location in the
		// registry
		L"CA");               // Could have used other predefined 
								// system stores
								// including Trust, CA, or Root

	BYTE bIssuerData[1024];
	DWORD bIssuerLength = 0;
	//CertStrToName(X509_ASN_ENCODING, (LPCWSTR)cIssuer.data(), CERT_OID_NAME_STR, NULL,
	//	bIssuerData, &bIssuerLength, NULL);

	size_t sizeSubjectLength = 0;
	X509_NAME_get0_der(name, NULL, &sizeSubjectLength);
	std::vector<const unsigned char*> pder(sizeSubjectLength, {});

	//Key method.
	X509_NAME_get0_der(name, pder.data(), &sizeSubjectLength);
	CERT_NAME_BLOB blob;
	blob.cbData = sizeSubjectLength;
	blob.pbData = (BYTE*)*pder.data();
	/*blob.cbData = 0x1a;
	blob.pbData = (BYTE*)"CrazyFolks";*/

	//std::wstring wIssuer(cSubject.begin(), cSubject.end());
	//LPWSTR IssuerSTR = (LPWSTR)wIssuer.c_str();

	*cert = CertFindCertificateInStore(hSystemStore,
		MY_ENCODING_TYPE,
		0,
		CERT_FIND_SUBJECT_NAME,
		&blob,
		NULL);

	CertCloseStore(
		hSystemStore,
		CERT_CLOSE_STORE_CHECK_FLAG);
}

void CertificateStoreOperation::GetCertByAKI(const ASN1_OCTET_STRING* aki, PCCERT_CONTEXT* cert)
{
	HCERTSTORE hSystemStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM, // System store will be a 
								// virtual store
		0,                      // Encoding type not needed 
								// with this PROV
		NULL,                   // Accept the default HCRYPTPROV
		CERT_SYSTEM_STORE_CURRENT_USER,
		// Set the system store location in the
		// registry
		L"Root");               // Could have used other predefined 
								// system stores
								// including Trust, CA, or Root
	CRYPT_HASH_BLOB blob;
	
	//std::reverse_copy(std::begin(hexSubjectKeyIdentifiderBin), std::end(hexSubjectKeyIdentifiderBin), std::begin(hexSubjectKeyIdentifiderBinReverse));
	blob.cbData = aki->length;
	blob.pbData = (BYTE*)aki->data;
	*cert = CertFindCertificateInStore(hSystemStore,
		MY_ENCODING_TYPE,
		0,
		CERT_FIND_KEY_IDENTIFIER,
		&blob,
		NULL);

	CertCloseStore(
		hSystemStore,
		CERT_CLOSE_STORE_CHECK_FLAG);
}