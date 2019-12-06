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
	void ExportCertToFile(PCCERT_CONTEXT* cert, OutputFileFormat  fileFormat);
};

