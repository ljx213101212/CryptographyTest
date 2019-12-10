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


	HCERTSTORE hSystemStore = hSystemStoreROOT;
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
}


void CertificateStoreOperation::ExportCertToFile(PCCERT_CONTEXT *cert, OutputFileFormat  fileFormat) {

	DWORD num = 1;
	/* open root certificate store */
	HCERTSTORE hCertStore = hSystemStoreROOT;
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


void CertificateStoreOperation::GetCertByIssuer(const wchar_t* pvPara, const X509* x, PCCERT_CONTEXT* cert){
	std::vector<char> cIssuer(1024, '\0');
	X509_NAME* issuer = X509_get_issuer_name(x);
	const ASN1_STRING* data;
	data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(issuer, 0));
	HCERTSTORE hSystemStore = pvPara == hSystemStoreCA ? hSystemStoreCA : hSystemStoreROOT;
	
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

	HCERTSTORE hSystemStore = hSystemStoreCA;
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
}

void CertificateStoreOperation::GetCertByAKI(const wchar_t* pvPara, const ASN1_OCTET_STRING* aki, PCCERT_CONTEXT* cert)
{
	HCERTSTORE hSystemStore = pvPara == PV_PARA_STORE_CA ? hSystemStoreCA : hSystemStoreROOT;
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
}

void  CertificateStoreOperation::GetCertByAKIByBlob(const wchar_t* pvPara, CRYPT_DATA_BLOB* akiBlob, PCCERT_CONTEXT* cert) {

	HCERTSTORE hSystemStore = pvPara == PV_PARA_STORE_CA ? hSystemStoreCA : hSystemStoreROOT;
	CRYPT_HASH_BLOB blob = (CRYPT_DATA_BLOB)*akiBlob;
	*cert = CertFindCertificateInStore(hSystemStore,
		MY_ENCODING_TYPE,
		0,
		CERT_FIND_KEY_IDENTIFIER,
		&blob,
		NULL);
}

bool CertificateStoreOperation::isTopCert(PCCERT_CONTEXT inputCert) {

	
	CRYPT_DATA_BLOB akiBlob;
	CRYPT_DATA_BLOB skiBlob;
	GetAKIFromCert(inputCert, &akiBlob);
	GetSKIFromCert(inputCert, &skiBlob);
	bool ret = (0 == std::memcmp(akiBlob.pbData, skiBlob.pbData, akiBlob.cbData));
	return ret;
}

void CertificateStoreOperation::GetAKIFromCert(PCCERT_CONTEXT inputCert, CRYPT_DATA_BLOB* outputAKI) {

	PCERT_EXTENSION ext;
	DWORD dwsize = 0;
	CRYPT_DATA_BLOB* AuthorityKeyId = outputAKI;
	BOOL ret = FALSE;
	if ((ext = CertFindExtension(szOID_AUTHORITY_KEY_IDENTIFIER,
		inputCert->pCertInfo->cExtension, inputCert->pCertInfo->rgExtension)))
	{
		CERT_AUTHORITY_KEY_ID_INFO* info;
		ret = CryptDecodeObjectEx(MY_ENCODING_TYPE,
			X509_AUTHORITY_KEY_ID, ext->Value.pbData, ext->Value.cbData,
			CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG, NULL,
			&info, &dwsize);
		/*outputAKI = &info->KeyId;*/
		outputAKI->cbData = info->KeyId.cbData;
		outputAKI->pbData = info->KeyId.pbData;

	}
	else if (ext = CertFindExtension(szOID_AUTHORITY_KEY_IDENTIFIER2,
		inputCert->pCertInfo->cExtension, inputCert->pCertInfo->rgExtension))
	{
		CERT_AUTHORITY_KEY_ID2_INFO* info;
		ret = CryptDecodeObjectEx(MY_ENCODING_TYPE,
			X509_AUTHORITY_KEY_ID2, ext->Value.pbData, ext->Value.cbData,
			CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG, NULL,
			&info, &dwsize);
		outputAKI->cbData = info->KeyId.cbData;
		outputAKI->pbData = info->KeyId.pbData;
	}
}


void CertificateStoreOperation::GetSKIFromCert(PCCERT_CONTEXT inputCert, CRYPT_DATA_BLOB* outputSKI) {

	PCERT_EXTENSION ext;
	DWORD dwsize = 0;
	CRYPT_DATA_BLOB * subjectKeyId = outputSKI;
	BOOL ret = FALSE;
	if ((ext = CertFindExtension(szOID_SUBJECT_KEY_IDENTIFIER,
		inputCert->pCertInfo->cExtension, inputCert->pCertInfo->rgExtension)))
	{
		CERT_AUTHORITY_KEY_ID_INFO* info;
		ret = CryptDecodeObjectEx(MY_ENCODING_TYPE,
			szOID_SUBJECT_KEY_IDENTIFIER, ext->Value.pbData, ext->Value.cbData,
			CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG, NULL,
			&info, &dwsize);
		outputSKI->cbData = info->KeyId.cbData;
		outputSKI->pbData = info->KeyId.pbData;
	}
	else if (ext = CertFindExtension(szOID_AUTHORITY_KEY_IDENTIFIER2,
		inputCert->pCertInfo->cExtension, inputCert->pCertInfo->rgExtension))
	{
		CERT_AUTHORITY_KEY_ID2_INFO* info;
		ret = CryptDecodeObjectEx(MY_ENCODING_TYPE,
			szOID_SUBJECT_KEY_IDENTIFIER, ext->Value.pbData, ext->Value.cbData,
			CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG, NULL,
			&info, &dwsize);
		outputSKI->cbData = info->KeyId.cbData;
		outputSKI->pbData = info->KeyId.pbData;
	}
}

void CertificateStoreOperation::GetTopCertFromStore(const wchar_t* pvPara, PCCERT_CONTEXT inputCert, PCCERT_CONTEXT& outputCert) {
	
	HCERTSTORE hSystemStore = pvPara == PV_PARA_STORE_CA ? hSystemStoreCA : hSystemStoreROOT;
	PCCERT_CONTEXT outCert;
	PCERT_EXTENSION ext;
	DWORD dwsize = 0;
	BOOL ret = FALSE;
	CRYPT_DATA_BLOB AuthorityKeyId;
	if ((ext = CertFindExtension(szOID_AUTHORITY_KEY_IDENTIFIER,
		inputCert->pCertInfo->cExtension, inputCert->pCertInfo->rgExtension)))
	{
		CERT_AUTHORITY_KEY_ID_INFO* info;
		ret = CryptDecodeObjectEx(MY_ENCODING_TYPE,
			X509_AUTHORITY_KEY_ID, ext->Value.pbData, ext->Value.cbData,
			CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG, NULL,
			&info, &dwsize);
		AuthorityKeyId = info->KeyId;
	}
	else if (ext = CertFindExtension(szOID_AUTHORITY_KEY_IDENTIFIER2,
		inputCert->pCertInfo->cExtension, inputCert->pCertInfo->rgExtension))
	{
		CERT_AUTHORITY_KEY_ID2_INFO* info;
		ret = CryptDecodeObjectEx(MY_ENCODING_TYPE,
			X509_AUTHORITY_KEY_ID2, ext->Value.pbData, ext->Value.cbData,
			CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG, NULL,
			&info, &dwsize);
		AuthorityKeyId = info->KeyId;
	}
	GetCertByAKIByBlob(L"Root", &AuthorityKeyId, &outCert);
	if (outCert == nullptr) {
		return;
	}
	bool isTop = isTopCert(outCert);
	if (isTop) {
	/*	memcpy(outputCert, &outCert, outCert->cbCertEncoded);*/
		outputCert = outCert;
	}
	else {
		outputCert = nullptr;
	}
}

void CertificateStoreOperation::EnumerateCertFromStore(const wchar_t* pvPara, const X509* x, PCCERT_CONTEXT& outputCert) {

	HCERTSTORE hSystemStore = pvPara == PV_PARA_STORE_CA ? hSystemStoreCA : hSystemStoreROOT;
	PCCERT_CONTEXT sourceCert;
	GetCertByIssuer(pvPara,x, &sourceCert);
	PCCERT_CONTEXT pCertContext = NULL;
	size_t outputPtr = 0;
	while (pCertContext = CertEnumCertificatesInStore(
		hSystemStore,
		pCertContext))
	{	
		if (CertCompareCertificate(MY_ENCODING_TYPE, pCertContext->pCertInfo, sourceCert->pCertInfo)) {
			outputCert = pCertContext;
			return;
		}
	}

}

void CertificateStoreOperation::GetRootCAFromIntermediateStore(PCCERT_CONTEXT inputCert, PCCERT_CONTEXT& outputCert) {
	
	if (inputCert == NULL){
		return;
	}
	X509* x = d2i_X509(NULL, (const unsigned char**) &(inputCert->pbCertEncoded), inputCert->cbCertEncoded);
	X509_NAME* issuer = X509_get_issuer_name(x);
	//Get issuer length
	size_t issuerSize = 0;
	X509_NAME_get0_der(issuer, NULL, &issuerSize);
	std::vector<const unsigned char*> vDer(issuerSize, {});
	X509_NAME_get0_der(issuer, vDer.data(), &issuerSize);
	CERT_NAME_BLOB blob;
	blob.cbData = issuerSize;
	blob.pbData = (BYTE*)*vDer.data();

	//use issuer to search next cert's subject.
	PCCERT_CONTEXT nextCert = CertFindCertificateInStore(hSystemStoreCA,
		MY_ENCODING_TYPE,
		0,
		CERT_FIND_SUBJECT_NAME,
		&blob,
		NULL);

	//Means the next cert should be in Root Trusted CA folder in windows certificate store.
	if (nextCert == NULL) {
		outputCert = nextCert;
		return;
	}
	//Means the inputCert is identical to next cert, it's a self signed ROOT CA. Subject == Issuer
	else if (CertCompareCertificate(MY_ENCODING_TYPE, nextCert->pCertInfo, inputCert->pCertInfo)) {
		outputCert = nextCert;
		return;
	}
	else {
		//recursive.
		GetRootCAFromIntermediateStore(nextCert, outputCert);
	}
}

void CertificateStoreOperation::GetRootCAFromRootStore(PCCERT_CONTEXT inputCert, PCCERT_CONTEXT& outputCert)
{
	CRYPT_DATA_BLOB AuthorityKeyId;
	GetAKIFromCert(inputCert, &AuthorityKeyId);
	PCCERT_CONTEXT tempCert;
	GetCertByAKIByBlob(L"Root", &AuthorityKeyId, &tempCert);
	if (tempCert == NULL) {
		return;
	}
	if (isTopCert(tempCert)) {
		outputCert = tempCert;
	}
}
