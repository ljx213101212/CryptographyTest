#pragma once
#include "pch.h"
#include <windows.h>
#include <wincrypt.h>


#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define MY_STRING_TYPE (CERT_OID_NAME_STR)
#define PV_PARA_STORE_CA L"CA"
#define PV_PARA_STORE_ROOT L"Root"


class CertificateStoreOperation {

public:

	CertificateStoreOperation() {
		hSystemStoreCA = CertOpenStore(
			CERT_STORE_PROV_SYSTEM,
			0,
			NULL,
			CERT_SYSTEM_STORE_CURRENT_USER,
			L"CA");
		hSystemStoreROOT = CertOpenStore(
			CERT_STORE_PROV_SYSTEM,
			0,
			NULL,
			CERT_SYSTEM_STORE_CURRENT_USER,
			L"Root");
	}
	~CertificateStoreOperation() {
		CertCloseStore(
			hSystemStoreCA,
			CERT_CLOSE_STORE_CHECK_FLAG);
		CertCloseStore(
			hSystemStoreROOT,
			CERT_CLOSE_STORE_CHECK_FLAG);
	}

	enum class OutputFileFormat {
		PEM,
		DER
	};
	/*
	obsolete group
	*/
	//Obsolete (Don't use , For learning and test only)
	void GetTestCert(PCCERT_CONTEXT* cert);
	//Obsolete (Don't use , For learning and test only)
	void GetCertByAKI(const wchar_t* pvPara, const ASN1_OCTET_STRING* aki, PCCERT_CONTEXT* cert);
	//void GetCertBySKI(const ASN1_OCTET_STRING* ski, PCCERT_CONTEXT* cert);
	//Obsolete (Don't use , For learning and test only)
	void GetCertBySubject(const X509* x, PCCERT_CONTEXT* cert);
	//Obsolete (Don't use , For learning and test only)
	void ExportCertToFile(PCCERT_CONTEXT* cert, OutputFileFormat  fileFormat);
	//Obsolete (Don't use , For learning and test only)
	void GetTopCertFromStore(const wchar_t* pvPara, PCCERT_CONTEXT inputCert, PCCERT_CONTEXT& outputCert);
	//Obsolete (Don't use , For learning and test only)
	void EnumerateCertFromStore(const wchar_t* pvPara, const X509* x, PCCERT_CONTEXT& outputCert);


	/*
	Formal APIs
	*/
	void GetCertByAKIByBlob(const wchar_t* pvPara, CRYPT_DATA_BLOB* akiBlob, PCCERT_CONTEXT* cert);
	void GetCertByIssuer(const wchar_t* pvPara, const X509* x, PCCERT_CONTEXT* cert);
	void GetAKIFromCert(PCCERT_CONTEXT inputCert, CRYPT_DATA_BLOB* outputAKI);
	void GetSKIFromCert(PCCERT_CONTEXT inputCert, CRYPT_DATA_BLOB* outputSKI);
	void GetRootCAFromIntermediateStore(PCCERT_CONTEXT inputCert, PCCERT_CONTEXT& outputCert);
	void GetRootCAFromRootStore(PCCERT_CONTEXT inputCert, PCCERT_CONTEXT& outputCert);
	bool isTopCert(PCCERT_CONTEXT inputCert);

private:
	HCERTSTORE  hSystemStoreCA;
	HCERTSTORE  hSystemStoreROOT;
};

