#pragma once
#include "pch.h"

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define MY_STRING_TYPE (CERT_OID_NAME_STR)


class CertificateStoreOperation {
	
public:
	enum class OutputFileFormat {
		PEM,
		DER
	};

	void GetTestCert(PCCERT_CONTEXT* cert);
	void GetCertByAKI(const ASN1_OCTET_STRING* aki, PCCERT_CONTEXT* cert);
	void GetCertByAKIByBlob(const wchar_t* pvPara, CRYPT_DATA_BLOB* akiBlob, PCCERT_CONTEXT* cert);
	//void GetCertBySKI(const ASN1_OCTET_STRING* ski, PCCERT_CONTEXT* cert);
	void GetCertByIssuer(const X509* x, PCCERT_CONTEXT* cert);
	void GetCertBySubject(const X509* x, PCCERT_CONTEXT* cert);
	void ExportCertToFile(PCCERT_CONTEXT* cert, OutputFileFormat  fileFormat);

	void GetTopCertFromStore(const wchar_t * pvPara , PCCERT_CONTEXT inputCert, PCCERT_CONTEXT *outputCert);

	void GetAKIFromCert(PCCERT_CONTEXT inputCert, CRYPT_DATA_BLOB* outputAKI);
	void GetSKIFromCert(PCCERT_CONTEXT inputCert, CRYPT_DATA_BLOB* outputSKI);

	void EnumerateCertFromStore(const wchar_t* pvPara, const X509* x ,PCCERT_CONTEXT* outputCert);
	bool isTopCert(PCCERT_CONTEXT inputCert);
};

