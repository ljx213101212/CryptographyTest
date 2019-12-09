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
	//void GetCertBySKI(const ASN1_OCTET_STRING* ski, PCCERT_CONTEXT* cert);
	void GetCertByIssuer(const X509* x, PCCERT_CONTEXT* cert);
	void GetCertBySubject(const X509* x, PCCERT_CONTEXT* cert);
	void ExportCertToFile(PCCERT_CONTEXT* cert, OutputFileFormat  fileFormat);
};

