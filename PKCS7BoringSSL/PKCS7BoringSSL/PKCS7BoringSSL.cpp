// PKCS7BoringSSL.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <openssl/base.h>
#include <openssl/nid.h>
#include <openssl/obj.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/stack.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/bytestring.h>
#include <fstream>
#include <vector>
#include "C:/Work/boringssl/boringssl/crypto/bytestring/internal.h"
#include "C:/Work/boringssl/boringssl/crypto/pkcs7/pkcs7.c"

using namespace std;


int pkcs7_parse_digests(uint8_t** der_bytes, CBS* out, CBS* cbs) {
	CBS in, content_info, content_type, wrapped_signed_data, signed_data;
	CBS spcIndirectDataWrapper, spcIndirectDataContentType, wrappered_spc_indirect_data, inner_data, octet_data, octet_string;
	uint64_t version;

	// The input may be in BER format.
	*der_bytes = NULL;
	if (!CBS_asn1_ber_to_der(cbs, &in, der_bytes) ||
		// See https://tools.ietf.org/html/rfc2315#section-7
		!CBS_get_asn1(&in, &content_info, CBS_ASN1_SEQUENCE) ||
		!CBS_get_asn1(&content_info, &content_type, CBS_ASN1_OBJECT)) {
		goto err;
	}

	if (!CBS_mem_equal(&content_type, kPKCS7SignedData,
		sizeof(kPKCS7SignedData))) {
		OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_NOT_PKCS7_SIGNED_DATA);
		goto err;
	}

	// See https://tools.ietf.org/html/rfc2315#section-9.1
	//if (!CBS_get_asn1(&content_info, &wrapped_signed_data,
	//	CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
	//	!CBS_get_asn1(&wrapped_signed_data, &signed_data, CBS_ASN1_SEQUENCE) ||
	//	!CBS_get_asn1_uint64(&signed_data, &version) ||
	//	!CBS_get_asn1(&signed_data, NULL /* digests */, CBS_ASN1_SET) ||
	//	!CBS_get_asn1(&signed_data, &spcIndirectDataWrapper /* content */, CBS_ASN1_SEQUENCE)||
	//	!CBS_get_asn1(&spcIndirectDataWrapper, &spcIndirectDataContentType /* content */, CBS_ASN1_OBJECT)||
	//	!CBS_get_asn1(&spcIndirectDataWrapper, &wrappered_spc_indirect_data,
	//		CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0)||
	//	!CBS_get_asn1(&wrappered_spc_indirect_data, &inner_data, CBS_ASN1_SEQUENCE) ||
	//	!CBS_get_asn1(&inner_data, &octet_data, CBS_ASN1_SEQUENCE)) {
	//	goto err;
	//}
	CBS_get_asn1(&content_info, &wrapped_signed_data,
		CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0);
	CBS_get_asn1(&wrapped_signed_data, &signed_data, CBS_ASN1_SEQUENCE);
	CBS_get_asn1_uint64(&signed_data, &version);
	CBS_get_asn1(&signed_data, NULL /* digests */, CBS_ASN1_SET);
	CBS_get_asn1(&signed_data, &spcIndirectDataWrapper /* content */, CBS_ASN1_SEQUENCE);
	CBS_get_asn1(&spcIndirectDataWrapper, &spcIndirectDataContentType /* content */, CBS_ASN1_OBJECT);
	CBS_get_asn1(&spcIndirectDataWrapper, &wrappered_spc_indirect_data,
				CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0);
	CBS_get_asn1(&wrappered_spc_indirect_data, &inner_data, CBS_ASN1_SEQUENCE);
	CBS_get_asn1(&inner_data, NULL, CBS_ASN1_SEQUENCE);
	CBS_get_asn1(&inner_data, &octet_data, CBS_ASN1_SEQUENCE);
	CBS_get_asn1(&octet_data, NULL, CBS_ASN1_SEQUENCE);
	CBS_get_asn1(&octet_data, &octet_string, CBS_ASN1_OCTETSTRING);


	if (version < 1) {
		OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_BAD_PKCS7_VERSION);
		goto err;
	}

	CBS_init(out, CBS_data(&octet_string), CBS_len(&octet_string));
	return 1;

err:
	OPENSSL_free(*der_bytes);
	*der_bytes = NULL;
	return 0;
}

int PKCS7_get_raw_digests(vector<uint8_t>& out_digest, size_t &out_digest_size, CBS* cbs,
	CRYPTO_BUFFER_POOL* pool) {


	CBS digests;
	uint8_t* der_bytes = NULL;
	int ret = 0;
	// See https://tools.ietf.org/html/rfc2315#section-9.1
	/*if (!pkcs7_parse_header(&der_bytes, &signed_data, cbs) ||
		!CBS_get_optional_asn1(
			&signed_data, &certificates, &has_certificates,
			CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0)) {
		goto err;
	}*/
	if (!pkcs7_parse_digests(&der_bytes, &digests, cbs)) {
		goto err;
	}
	{
		out_digest_size = CBS_len(&digests);
		uint8_t* tmp = (uint8_t*)CBS_data(&digests);
		//out_digest(std::begin(tmp))
	/*	out_digest(tmp, tmp + out_digest_size);*/
		for (int i = 0; i < out_digest_size; i++) {
			out_digest.push_back(*(tmp + i));
		}
		
	/*	memcpy(out_digest, (uint8_t*)CBS_data(&digests), out_digest_size);*/
	}
	ret = 1;
	return ret;
err:
	OPENSSL_free(der_bytes);
	return ret;
}


int PKCS7_get_spcIndirectDataContext_value(STACK_OF(X509)* out_digests, CBS* cbs) {

	int ret = 0;
	const size_t initial_digests_len = sk_X509_num(out_digests);
	
	size_t digest_size = 0;
	//uint8_t digest_data
	vector<uint8_t> digest_data;
	PKCS7_get_raw_digests(digest_data, digest_size, cbs, NULL);
	ret = 1;
	return ret;

}

BIO* PKCS7_dataInit() {
	return nullptr;
}

void getSpcIndirectDataContext(EVP_MD_CTX* ctx) {
	return;
}

PKCS7* d2i_PKCS7_RAZ(PKCS7** out, const uint8_t** inp,
	size_t len) {
	CBS cbs;
	CBS_init(&cbs, *inp, len);
	STACK_OF(X509*) out_digest;
	out_digest = sk_X509_new_null();
	PKCS7_get_spcIndirectDataContext_value(out_digest, &cbs);
	return nullptr;
}

int main()
{
	std::string filePath = "D:\\downloadTest\\certTest5\\keyboard_dark_sha1_signature";
	std::ifstream input(filePath, std::ios::binary);
	// copies all data into buffer
	std::vector<char> buffer(std::istreambuf_iterator<char>(input), {});
	const unsigned char* pCertificate = reinterpret_cast<unsigned char*>(buffer.data());

	//PKCS7* pcks7 = d2i_PKCS7(NULL, &pCertificate, buffer.size());
	PKCS7* pcks7 = d2i_PKCS7_RAZ(NULL, &pCertificate, buffer.size());
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
