// CertificateStoreOperations.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <tchar.h>
using namespace std;
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define MY_STRING_TYPE (CERT_OID_NAME_STR)

#define BUFFER_SIZE 100
void MyHandleError(char* s);



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

void testPrintNames() {
	HCERTSTORE hCertStore;
	PCCERT_CONTEXT pCertContext;

	//---------------------------------------------------------------
	// Begin Processing by opening a certificate store.

	if (!(hCertStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		MY_ENCODING_TYPE,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		L"Root")))
	{
		MyHandleError((char*)("The MY system store did not open."));
	}

	//---------------------------------------------------------------
	//       Loop through the certificates in the store. 
	//       For each certificate,
	//             get and print the name of the 
	//                  certificate subject and issuer.
	//             convert the subject name from the certificate
	//                  to an ASN.1 encoded string and print the
	//                  octets from that string.
	//             convert the encoded string back into its form 
	//                  in the certificate.

	pCertContext = NULL;
	while (pCertContext = CertEnumCertificatesInStore(
		hCertStore,
		pCertContext))
	{
		LPTSTR pszString;
		LPTSTR pszName;
		DWORD cbSize;
		CERT_BLOB blobEncodedName;

		//-----------------------------------------------------------
		//        Get and display 
		//        the name of subject of the certificate.

		if (!(cbSize = CertGetNameString(
			pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			0,
			NULL,
			NULL,
			0)))
		{
			MyHandleError((char*)("CertGetName 1 failed."));
		}

		if (!(pszName = (LPTSTR)malloc(cbSize * sizeof(TCHAR))))
		{
			MyHandleError((char*)("Memory allocation failed."));
		}

		if (CertGetNameString(
			pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			0,
			NULL,
			pszName,
			cbSize))

		{
			_tprintf(TEXT("\nSubject -> %s.\n"), pszName);

			//-------------------------------------------------------
			//       Free the memory allocated for the string.
			free(pszName);
		}
		else
		{
			MyHandleError((char*)("CertGetName failed."));
		}

		//-----------------------------------------------------------
		//        Get and display 
		//        the name of Issuer of the certificate.

		if (!(cbSize = CertGetNameString(
			pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			CERT_NAME_ISSUER_FLAG,
			NULL,
			NULL,
			0)))
		{
			MyHandleError((char*)("CertGetName 1 failed."));
		}

		if (!(pszName = (LPTSTR)malloc(cbSize * sizeof(TCHAR))))
		{
			MyHandleError((char*)("Memory allocation failed."));
		}

		if (CertGetNameString(
			pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			CERT_NAME_ISSUER_FLAG,
			NULL,
			pszName,
			cbSize))
		{
			_tprintf((const wchar_t*)("Issuer  -> %s.\n"), pszName);

			//-------------------------------------------------------
			//       Free the memory allocated for the string.
			free(pszName);
		}
		else
		{
			MyHandleError((char*)("CertGetName failed."));
		}

		//-----------------------------------------------------------
		//       Convert the subject name to an ASN.1 encoded
		//       string and print the octets in that string.

		//       First : Get the number of bytes that must 
		//       be allocated for the string.

		cbSize = CertNameToStr(
			pCertContext->dwCertEncodingType,
			&(pCertContext->pCertInfo->Subject),
			MY_STRING_TYPE,
			NULL,
			0);

		//-----------------------------------------------------------
		//  The function CertNameToStr returns the number
		//  of bytes needed for a string to hold the
		//  converted name, including the null terminator. 
		//  If it returns one, the name is an empty string.

		if (1 == cbSize)
		{
			MyHandleError((char*)("Subject name is an empty string."));
		}

		//-----------------------------------------------------------
		//        Allocated the needed buffer. Note that this
		//        memory must be freed inside the loop or the 
		//        application will leak memory.

		if (!(pszString = (LPTSTR)malloc(cbSize * sizeof(TCHAR))))
		{
			MyHandleError((char*)("Memory allocation failed."));
		}

		//-----------------------------------------------------------
		//       Call the function again to get the string. 

		cbSize = CertNameToStr(
			pCertContext->dwCertEncodingType,
			&(pCertContext->pCertInfo->Subject),
			MY_STRING_TYPE,
			pszString,
			cbSize);

		//-----------------------------------------------------------
		//  The function CertNameToStr returns the number
		//  of bytes in the string, including the null terminator.
		//  If it returns 1, the name is an empty string.

		if (1 == cbSize)
		{
			MyHandleError((char*)("Subject name is an empty string."));
		}

		//-----------------------------------------------------------
		//    Get the length needed to convert the string back 
		//    back into the name as it was in the certificate.

		if (!(CertStrToName(
			MY_ENCODING_TYPE,
			pszString,
			MY_STRING_TYPE,
			NULL,
			NULL,        // NULL to get the number of bytes 
							// needed for the buffer.          
			&cbSize,     // Pointer to a DWORD to hold the 
							// number of bytes needed for the 
							// buffer
			NULL)))     // Optional address of a pointer to
							// old the location for an error in the 
							// input string.
		{
			MyHandleError(
				(char*)("Could not get the length of the BLOB."));
		}

		if (!(blobEncodedName.pbData = (LPBYTE)malloc(cbSize)))
		{
			MyHandleError(
				(char*)("Memory Allocation for the BLOB failed."));
		}
		blobEncodedName.cbData = cbSize;

		if (CertStrToName(
			MY_ENCODING_TYPE,
			pszString,
			MY_STRING_TYPE,
			NULL,
			blobEncodedName.pbData,
			&blobEncodedName.cbData,
			NULL))
		{
			_tprintf(TEXT("CertStrToName created the BLOB.\n"));
		}
		else
		{
			MyHandleError((char*)("Could not create the BLOB."));
		}

		//-----------------------------------------------------------
		//       Free the memory.

		free(blobEncodedName.pbData);
		free(pszString);

		//-----------------------------------------------------------
		//       Pause before information on the next certificate
		//       is displayed.

		

	} // End of while loop


	//---------------------------------------------------------------
	//   Close the MY store.

	if (CertCloseStore(
		hCertStore,
		CERT_CLOSE_STORE_CHECK_FLAG))
	{
		
	}
	else
	{
		
	}

}

void main(void)
{
	//--------------------------------------------------------------------
	// Copyright (C) Microsoft.  All rights reserved.
	// Declare and initialize variables.

	HCERTSTORE  hSystemStore;              // System store handle
	HCERTSTORE  hMemoryStore;              // Memory store handle
	HCERTSTORE  hDuplicateStore;           // Handle for a store to be 
										   // created
										   // as a duplicate of an open 
										   // store
	PCCERT_CONTEXT  pDesiredCert = NULL;   // Set to NULL for the first 
										   // call to
										   // CertFindCertificateInStore
	PCCERT_CONTEXT  pCertContext;
	HANDLE  hStoreFileHandle;             // Output file handle
	LPWSTR  pszFileName = LPWSTR(L"TestStor.sto");  // Output file name
	SECURITY_ATTRIBUTES sa;                // For DACL

	//-------------------------------------------------------------------
	// Open a new certificate store in memory.
	testPrintNames();
	if (hMemoryStore = CertOpenStore(
		CERT_STORE_PROV_MEMORY,    // Memory store
		0,                         // Encoding type
								   // not used with a memory store
		NULL,                      // Use the default provider
		0,                         // No flags
		NULL))                     // Not needed
	{
		printf("Opened a memory store. \n");
	}
	else
	{
		MyHandleError((char*)"Error opening a memory store.");
	}
	//-------------------------------------------------------------------
	// Open the My system store using CertOpenStore.

	if (hSystemStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM, // System store will be a 
								// virtual store
		0,                      // Encoding type not needed 
								// with this PROV
		NULL,                   // Accept the default HCRYPTPROV
		CERT_SYSTEM_STORE_CURRENT_USER,
		// Set the system store location in the
		// registry
		L"Root"))                 // Could have used other predefined 
								// system stores
								// including Trust, CA, or Root
	{
		printf("Opened the MY system store. \n");
	}
	else
	{
		MyHandleError((char*)"Could not open the MY system store.");
	}
	//-------------------------------------------------------------------
	// Create a duplicate of the My store.

	if (hDuplicateStore = CertDuplicateStore(hSystemStore))
	{
		printf("The MY store is duplicated.\n");
	}
	else
	{
		printf("Duplication of the MY store failed.\n.");
	}

	//-------------------------------------------------------------------
	// Close the duplicate store. 

	if (hDuplicateStore)
		CertCloseStore(
			hDuplicateStore,
			CERT_CLOSE_STORE_CHECK_FLAG);



	vector<BYTE> test = { 0x01,0x02 };
	BYTE* byteData = (BYTE*)"CrazyFolks";
	BYTE* certName = new BYTE[23 * sizeof(TCHAR)];
	//certName = test.data();
	LPWSTR outputName = NULL;
	DWORD readBytes = 23 * sizeof(TCHAR);
	LPCWSTR errorMessage = L"";


	//if (!(CertStrToName(
	//	MY_ENCODING_TYPE,
	//	pszString,
	//	MY_STRING_TYPE,
	//	NULL,
	//	NULL,        // NULL to get the number of bytes 
	//					// needed for the buffer.          
	//	&cbSize,     // Pointer to a DWORD to hold the 
	//					// number of bytes needed for the 
	//					// buffer
	//	NULL)))     // Optional address of a pointer to
	//					// old the location for an error in the 
	//					// input string.
	//{
	//	MyHandleError(
	//		TEXT("Could not get the length of the BLOB."));
	//}
	CRYPT_INTEGER_BLOB nameBlob = {
			nameBlob.cbData = 11,
			nameBlob.pbData = byteData
	};
	int num = CertNameToStr(
		MY_ENCODING_TYPE,
		&nameBlob,
		MY_STRING_TYPE,
		outputName,
		readBytes);

	BOOL isGetName = CertStrToName(MY_ENCODING_TYPE, TEXT("O=CrazyFolks"), MY_STRING_TYPE, NULL, certName, &readBytes, nullptr);
	delete []certName;
	const char* hexSerialNumber = "00c42997d8e5ad1ba8";
	char serialNumberBin[BUFFER_SIZE];
	hex2bin(hexSerialNumber, serialNumberBin);
	char serialNumberBinReverse[BUFFER_SIZE];
	std::reverse_copy(std::begin(serialNumberBin), std::end(serialNumberBin), std::begin(serialNumberBinReverse));
	BYTE* serialNumberByte = (BYTE*)serialNumberBinReverse;
	/*BYTE* serialNumber = hex2bin(0x00c42997d8e5ad1ba8;*/
	CERT_ISSUER_SERIAL_NUMBER certIDSerialNumber = {
			certIDSerialNumber.Issuer = {
				certIDSerialNumber.Issuer.cbData = 11,
				certIDSerialNumber.Issuer.pbData = byteData
			},
		// 00c42997d8e5ad1ba8
			certIDSerialNumber.SerialNumber = {
				certIDSerialNumber.SerialNumber.cbData = 9,
				certIDSerialNumber.SerialNumber.pbData = serialNumberByte
			}
	};
	CERT_ID certID = {
			certID.dwIdChoice = CERT_ID_ISSUER_SERIAL_NUMBER,
			certID.IssuerSerialNumber = certIDSerialNumber
	};
	//Try to get cert by CERT_FIND_CERT_ID
	if (pDesiredCert = CertFindCertificateInStore(
		hSystemStore,
		MY_ENCODING_TYPE,             // Use X509_ASN_ENCODING
		0,                            // No dwFlags needed 
		CERT_FIND_CERT_ID,        // Find a certificate with a
									  // subject that matches the 
									  // string in the next parameter
		&certID, // The Unicode string to be found
									  // in a certificate's subject
		NULL))                        // NULL for the first call to the
									  // function 
									  // In all subsequent
									  // calls, it is the last pointer
									  // returned by the function
	{
		printf("The desired certificate was found. \n");
	}
	else
	{
		//MyHandleError((char*)"Could not find the desired certificate.");
	}



	CRYPT_HASH_BLOB blob;
	const char* hexSubjectKeyIdentifier = "0a007b4107ce41a0b1b2772e84fddcc4913f6180";
	char hexSubjectKeyIdentifiderBin[20];
	hex2bin(hexSubjectKeyIdentifier, hexSubjectKeyIdentifiderBin);
	char hexSubjectKeyIdentifiderBinReverse[20];
	//std::reverse_copy(std::begin(hexSubjectKeyIdentifiderBin), std::end(hexSubjectKeyIdentifiderBin), std::begin(hexSubjectKeyIdentifiderBinReverse));
	blob.cbData = strlen(hexSubjectKeyIdentifier) / 2;
	blob.pbData = (BYTE*)hexSubjectKeyIdentifiderBin;
	pDesiredCert = CertFindCertificateInStore(hSystemStore,
		MY_ENCODING_TYPE,
		0,
		CERT_FIND_KEY_IDENTIFIER,
		&blob,
		NULL);

	//-------------------------------------------------------------------
	// Get a certificate that has the string "Insert_cert_subject_name1" 
	// in its subject. 

	if (pDesiredCert = CertFindCertificateInStore(
		hSystemStore,
		MY_ENCODING_TYPE,             // Use X509_ASN_ENCODING
		0,                            // No dwFlags needed 
		CERT_FIND_SUBJECT_STR,        // Find a certificate with a
									  // subject that matches the 
									  // string in the next parameter
		L"CrazyFolks", // The Unicode string to be found
									  // in a certificate's subject
		NULL))                        // NULL for the first call to the
									  // function 
									  // In all subsequent
									  // calls, it is the last pointer
									  // returned by the function
	{
		printf("The desired certificate was found. \n");
	}
	else
	{
		MyHandleError((char*)"Could not find the desired certificate.");
	}
	//-------------------------------------------------------------------
	// pDesiredCert is a pointer to a certificate with a subject that 
	// includes the string "Insert_cert_subject_name1", the string is 
	// passed as parameter #5 to the function.

	//------------------------------------------------------------------ 
	//  Create a new certificate from the encoded part of
	//  an available certificate.

	if (pCertContext = CertCreateCertificateContext(
		MY_ENCODING_TYPE,            // Encoding type
		pDesiredCert->pbCertEncoded,   // Encoded data from
									   // the certificate retrieved
		pDesiredCert->cbCertEncoded))  // Length of the encoded data
	{
		printf("A new certificate has been created.\n");
	}
	else
	{
		MyHandleError((char*)"A new certificate could not be created.");
	}

	//-------------------------------------------------------------------
	// Add the certificate from the My store to the new memory store.

	if (CertAddCertificateContextToStore(
		hMemoryStore,                // Store handle
		pDesiredCert,                // Pointer to a certificate
		CERT_STORE_ADD_USE_EXISTING,
		NULL))
	{
		printf("Certificate added to the memory store. \n");
	}
	else
	{
		MyHandleError((char*)"Could not add the certificate "
			"to the memory store.");
	}
	//-------------------------------------------------------------------
	// Find a different certificate in the My store, and add to it a link
	// to the memory store.

	//-------------------------------------------------------------------
	// Find the certificate context just added to the memory store.

	if (pDesiredCert)
		CertFreeCertificateContext(pDesiredCert);

	if (pDesiredCert = CertFindCertificateInStore(
		hSystemStore,
		MY_ENCODING_TYPE,            // Use X509_ASN_ENCODING
		0,                           // no dwFlags needed 
		CERT_FIND_SUBJECT_STR,       // Find a certificate with a
									 // subject that matches the 
									 // string in the next parameter
		L"Insert_cert_subject_name2",// The Unicode string to be found
									 // in a certificate's subject
		NULL))                       // NULL for the first call to the
									 // function 
									 // In all subsequent
									 // calls, it is the last pointer
									 // returned by the function
	{
		printf("The second certificate was found. \n");
	}
	else
	{
		MyHandleError((char*)"Could not find the second certificate.");
	}
	//-------------------------------------------------------------------
	// Add a link to the second certificate from the My store to 
	// the new memory store.

	if (CertAddCertificateLinkToStore(
		hMemoryStore,           // Store handle
		pDesiredCert,           // Pointer to a certificate
		CERT_STORE_ADD_USE_EXISTING,
		NULL))
	{
		printf("Certificate link added to the memory store. \n");
	}
	else
	{
		MyHandleError((char*)"Could not add the certificate link to the "
			"memory store.");
	}
	//--------------------------------------------------------------------
	// Find the first certificate in the memory store.

	if (pDesiredCert)
		CertFreeCertificateContext(pDesiredCert);

	if (pDesiredCert = CertFindCertificateInStore(
		hMemoryStore,
		MY_ENCODING_TYPE,            // Use X509_ASN_ENCODING
		0,                           // No dwFlags needed 
		CERT_FIND_SUBJECT_STR,       // Find a certificate with a
									 // subject that matches the string
									 // in the next parameter
		L"Insert_cert_subject_name1",// The Unicode string to be found
									 // in a certificate's subject
		NULL))                       // NULL for the first call to the
									 // function
									 // In all subsequent
									 // calls, it is the last pointer
									 // returned by the function
	{
		printf("The desired certificate was found in the "
			"memory store. \n");
	}
	else
	{
		printf("Certificate not in the memory store.\n");
	}
	//-------------------------------------------------------------------
	// Find the certificate link in the memory store.

	if (pDesiredCert)
		CertFreeCertificateContext(pDesiredCert);

	if (pDesiredCert = CertFindCertificateInStore(
		hMemoryStore,
		MY_ENCODING_TYPE,            // Use X509_ASN_ENCODING
		0,                           // No dwFlags needed 
		CERT_FIND_SUBJECT_STR,       // Find a certificate with a
									 // subject that matches the 
									 // string in the next parameter
		L"Insert_cert_subject_name1",// The Unicode string to be found
									 // in a certificate's subject
		NULL))                       // NULL for the first call to the
									 // function
									 // In all subsequent
									 // calls, it is the last pointer
									 // returned by the function
	{
		printf("The certificate link was found in the memory store. \n");
	}
	else
	{
		printf("The certificate link was not in the memory store.\n");
	}
	//-------------------------------------------------------------------
	// Create a file in which to save the new store and certificate.

	// Create a DACL for the file.
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = FALSE;

	// Call the function to set the DACL. The DACL
	// is set in the SECURITY_ATTRIBUTES 
	// lpSecurityDescriptor member.
	// if !CreateMyDACL(&sa), call MyHandleError("CreateMyDACL failed.");

	if (hStoreFileHandle = CreateFile(
		pszFileName,        // File path
		GENERIC_WRITE,      // Access mode
		0,                  // Share mode
		&sa,                // Security 
		CREATE_ALWAYS,      // How to create the file
		FILE_ATTRIBUTE_NORMAL,
		// File attributes
		NULL))              // Template
	{
		printf("Created a new file on disk. \n");
	}
	else
	{
		MyHandleError((char*)"Could not create a file on disk.");
	}
	//-------------------------------------------------------------------
	// hStoreFileHandle is the output file handle.
	// Save the memory store and its certificate to the output file.

	if (CertSaveStore(
		hMemoryStore,        // Store handle
		0,                   // Encoding type not needed here
		CERT_STORE_SAVE_AS_STORE,
		CERT_STORE_SAVE_TO_FILE,
		hStoreFileHandle,    // This is the handle of an open disk file
		0))                  // dwFlags
							 // No flags needed here
	{
		printf("Saved the memory store to disk. \n");
	}
	else
	{
		MyHandleError((char*)"Could not save the memory store to disk.");
	}
	//-------------------------------------------------------------------
	// Close the stores and the file. Reopen the file store, 
	// and check its contents.

	if (hMemoryStore)
		CertCloseStore(
			hMemoryStore,
			CERT_CLOSE_STORE_CHECK_FLAG);

	if (hSystemStore)
		CertCloseStore(
			hSystemStore,
			CERT_CLOSE_STORE_CHECK_FLAG);

	if (hStoreFileHandle)
		CloseHandle(hStoreFileHandle);

	printf("All of the stores and files are closed. \n");

	//-------------------------------------------------------------------
	//  Reopen the file store.

	if (hMemoryStore = CertOpenStore(
		CERT_STORE_PROV_FILENAME,    // Store provider type
		MY_ENCODING_TYPE,            // If needed, use the usual
									 // encoding types
		NULL,                        // Use the default HCRYPTPROV
		0,                           // Accept the default for all
									 // dwFlags
		L"TestStor.sto"))           // The name of an existing file
									 // as a Unicode string
	{
		printf("The file store has been reopened. \n");
	}
	else
	{
		printf("The file store could not be reopened. \n");
	}
	//-------------------------------------------------------------------
	// Find the certificate link in the reopened file store.

	if (pDesiredCert)
		CertFreeCertificateContext(pDesiredCert);

	if (pDesiredCert = CertFindCertificateInStore(
		hMemoryStore,
		MY_ENCODING_TYPE,            // Use X509_ASN_ENCODING
		0,                           // No dwFlags needed 
		CERT_FIND_SUBJECT_STR,       // Find a certificate with a
									 // subject that matches the string
									 // in the next parameter
		L"Insert_cert_subject_name1",// The Unicode string to be found
									 // in a certificate's subject
		NULL))                       // NULL for the first call to the
									 // function
									 // In all subsequent
									 // calls, it is the last pointer
									 // returned by the function
	{
		printf("The certificate link was found in the file store. \n");
	}
	else
	{
		printf("The certificate link was not in the file store.\n");
	}
	//-------------------------------------------------------------------
	// Clean up memory and end.

	if (pDesiredCert)
		CertFreeCertificateContext(pDesiredCert);
	if (hMemoryStore)
		CertCloseStore(
			hMemoryStore,
			CERT_CLOSE_STORE_CHECK_FLAG);
	if (hSystemStore)
		CertCloseStore(
			hSystemStore,
			CERT_CLOSE_STORE_CHECK_FLAG);
	if (hStoreFileHandle)
		CloseHandle(hStoreFileHandle);
	printf("All of the stores and files are closed. \n");
	return;
} // end main

//-------------------------------------------------------------------
// This example uses the function MyHandleError, a simple error
// handling function, to print an error message and exit 
// the program. 
// For most applications, replace this function with one 
// that does more extensive error reporting.

void MyHandleError(char* s)
{
	fprintf(stderr, "An error occurred in running the program. \n");
	fprintf(stderr, "%s\n", s);
	fprintf(stderr, "Error number %x.\n", GetLastError());
	fprintf(stderr, "Program terminating. \n");
	exit(1);
} // end MyHandleError

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
