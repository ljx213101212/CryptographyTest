// PKCS7BoringSSL.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

#include "pch.h"
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
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include "../includes/crypto/internal.h"
#include "../includes/bytestring/internal.h"
#include "../includes/pkcs7/pkcs7.c"


using namespace std;

//ASN1_ITEM_TEMPLATE(PKCS7_ATTR_VERIFY) =
//ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_IMPTAG | ASN1_TFLG_UNIVERSAL,
//	V_ASN1_SET, PKCS7_ATTRIBUTES, X509_ATTRIBUTE)
//ASN1_ITEM_TEMPLATE_END(PKCS7_ATTR_VERIFY)

//static ASN1_ITEM_EXP * item_type[] = {
//		ASN1_ITEM_ref(PKCS7_ATTR_VERIFY)
//};

//ref: https://wiki.openssl.org/index.php/EVP_Message_Digests
void digest_message(const unsigned char* message, size_t message_len, unsigned char** digest, unsigned int* digest_len)
{
	EVP_MD_CTX* mdctx;

	if ((mdctx = EVP_MD_CTX_create()) == NULL)
		return;

	if (1 != EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL))
		return;

	if (1 != EVP_DigestUpdate(mdctx, message, message_len))
		return;

	if ((*digest = (unsigned char*)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
		return;

	if (1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
		return;

	EVP_MD_CTX_destroy(mdctx);
}



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

int pkcs7_parse_public_key_info(uint8_t** der_bytes, CBS* out, CBS* cbs) {
	CBS in, content_info, content_type, wrapped_signed_data, signed_data, certificates;
	CBS spcIndirectDataWrapper, spcIndirectDataContentType, wrappered_spc_indirect_data, inner_data, octet_data, octet_string;
	uint64_t version;
	int has_certificates;
	if (!pkcs7_parse_header(der_bytes, &signed_data, cbs) ||
		!CBS_get_optional_asn1(
			&signed_data, &certificates, &has_certificates,
			CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0)) {
		goto err;
	}
	CBS public_key_info;
	CBS toplevel;
	CBS_get_asn1(&certificates, &toplevel, CBS_ASN1_SEQUENCE);
	CBS_get_asn1(&toplevel, &public_key_info, CBS_ASN1_SEQUENCE);
	CBS_get_optional_asn1(
		&public_key_info, NULL, NULL,
		CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 0);
	CBS_get_asn1(&public_key_info, NULL, CBS_ASN1_INTEGER);
	CBS_get_asn1(&public_key_info, NULL, CBS_ASN1_SEQUENCE);
	CBS_get_asn1(&public_key_info, NULL, CBS_ASN1_SEQUENCE);
	CBS_get_asn1(&public_key_info, NULL, CBS_ASN1_SEQUENCE);
	CBS_get_asn1(&public_key_info, NULL, CBS_ASN1_SEQUENCE);
	//out = &tbs_cert;
	CBS_init(out, CBS_data(&public_key_info), CBS_len(&public_key_info));
	return 1;
err:
	OPENSSL_free(*der_bytes);
	*der_bytes = NULL;
	return 0;
}

int PKCS7_get_raw_public_key_info(vector<uint8_t>& out_public_key_info, size_t& out_public_key_info_size, CBS* cbs,
	CRYPTO_BUFFER_POOL* pool) {
	CBS public_key_info;
	uint8_t* der_bytes = NULL;
	int ret = 0;
	if (!pkcs7_parse_public_key_info(&der_bytes, &public_key_info, cbs)) {
		return ret;
	}
	out_public_key_info_size = CBS_len(&public_key_info);
	uint8_t* tmp = (uint8_t*)CBS_data(&public_key_info);

	out_public_key_info.resize(out_public_key_info_size);
	out_public_key_info.assign(tmp, (tmp + out_public_key_info_size));
	ret = 1;
	return ret;
}

int pkcs7_parse_tbs_certificate(uint8_t** der_bytes, CBS* out, CBS* cbs) {
	int ret = 0;
	CBS in, top_level, signed_data, certificates;
	*der_bytes = NULL;
	int has_certificates;
	if (!pkcs7_parse_header(der_bytes, &signed_data, cbs) ||
		!CBS_get_optional_asn1(
			&signed_data, &certificates, &has_certificates,
			CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0)) {
		goto err;
	}
	CBS_init(out, CBS_data(&certificates), CBS_len(&certificates));
	return 1;
err:
	OPENSSL_free(*der_bytes);
	*der_bytes = NULL;
	return 0;
}

int PKCS7_get_raw_tbs_certificate(vector<uint8_t>& out_tbs_certificate, size_t& out_tbs_certificate_size, CBS* cbs,
	CRYPTO_BUFFER_POOL* pool) {
	CBS tbs_certificate;
	uint8_t* der_bytes = NULL;
	int ret = 0;
	if (!pkcs7_parse_tbs_certificate(&der_bytes, &tbs_certificate, cbs)) {
		return ret;
	}
	out_tbs_certificate_size = CBS_len(&tbs_certificate);
	uint8_t* tmp = (uint8_t*)CBS_data(&tbs_certificate);

	out_tbs_certificate.resize(out_tbs_certificate_size);
	out_tbs_certificate.assign(tmp, (tmp + out_tbs_certificate_size));
	ret = 1;
	return ret;
}


int PKCS7_parse_signature(uint8_t** der_bytes, CBS* out, CBS* cbs) {

	int ret = 0;
	CBS in, signed_data, certificates, signed_data_seq, signed_data_seq_inner, octet_string;
	uint64_t version;
	int has_certificates;
	if (!pkcs7_parse_header(der_bytes, &signed_data, cbs) ||
		!CBS_get_optional_asn1(
			&signed_data, &certificates, &has_certificates,
			CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0)) {
		goto err;
	}
	CBS_get_asn1(&signed_data, &signed_data_seq, CBS_ASN1_SET);
	CBS_get_asn1(&signed_data_seq, &signed_data_seq_inner, CBS_ASN1_SEQUENCE);
	CBS_get_asn1(&signed_data_seq_inner, NULL, CBS_ASN1_INTEGER);
	CBS_get_asn1(&signed_data_seq_inner, NULL, CBS_ASN1_SEQUENCE);
	CBS_get_asn1(&signed_data_seq_inner, NULL, CBS_ASN1_SEQUENCE);
	CBS_get_optional_asn1(
		&signed_data_seq_inner, NULL, &has_certificates,
		CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0);
	CBS_get_asn1(&signed_data_seq_inner, NULL, CBS_ASN1_SEQUENCE);
	CBS_get_asn1(&signed_data_seq_inner, &octet_string, CBS_ASN1_OCTETSTRING);

	CBS_init(out, CBS_data(&octet_string), CBS_len(&octet_string));
	return 1;
err:
	OPENSSL_free(*der_bytes);
	*der_bytes = NULL;
	return 0;
}

int PKCS7_get_raw_signature(vector<uint8_t>& out_signature, size_t& out_signature_size, CBS* cbs,
	CRYPTO_BUFFER_POOL* pool) {
	CBS signature;
	uint8_t* der_bytes = NULL;
	int ret = 0;
	if (!PKCS7_parse_signature(&der_bytes, &signature, cbs)) {
		return ret;
	}
	out_signature_size = CBS_len(&signature);
	uint8_t* tmp = (uint8_t*)CBS_data(&signature);
	out_signature.resize(out_signature_size);
	out_signature.assign(tmp, (tmp + out_signature_size));
	ret = 1;
	return ret;
}

int PKCS7_parse_signer_info(uint8_t** der_bytes, CBS* out, CBS* cbs) {

	int ret = 0;
	CBS in, signed_data, certificates, signed_data_seq, signed_data_seq_inner, signer_info;
	uint64_t version;
	int has_certificates;
	if (!pkcs7_parse_header(der_bytes, &signed_data, cbs) ||
		!CBS_get_optional_asn1(
			&signed_data, &certificates, &has_certificates,
			CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0)) {
		goto err;
	}
	CBS_get_asn1(&signed_data, &signed_data_seq, CBS_ASN1_SET);
	CBS_get_asn1(&signed_data_seq, &signed_data_seq_inner, CBS_ASN1_SEQUENCE);
	CBS_get_asn1(&signed_data_seq_inner, NULL, CBS_ASN1_INTEGER);
	CBS_get_asn1(&signed_data_seq_inner, NULL, CBS_ASN1_SEQUENCE);
	CBS_get_asn1(&signed_data_seq_inner, NULL, CBS_ASN1_SEQUENCE);
	CBS_get_optional_asn1(
		&signed_data_seq_inner, &signer_info, &has_certificates,
		CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0);
	//CBS_get_asn1(&signed_data_seq_inner, NULL, CBS_ASN1_SEQUENCE);
	//CBS_get_asn1(&signed_data_seq_inner, &octet_string, CBS_ASN1_OCTETSTRING);

	CBS_init(out, CBS_data(&signer_info), CBS_len(&signer_info));
	return 1;
err:
	OPENSSL_free(*der_bytes);
	*der_bytes = NULL;
	return 0;
}



int PKCS7_get_raw_signer_info(vector<uint8_t>& out_signer_info, size_t& out_signer_info_size, CBS* cbs,
	CRYPTO_BUFFER_POOL* pool) {

	CBS signer_info;
	uint8_t* der_bytes = NULL;
	int ret = 0;
	if (!PKCS7_parse_signer_info(&der_bytes, &signer_info, cbs)) {
		return ret;
	}
	out_signer_info_size = CBS_len(&signer_info);
	uint8_t* tmp = (uint8_t*)CBS_data(&signer_info);
	out_signer_info.resize(out_signer_info_size);
	out_signer_info.assign(tmp, (tmp + out_signer_info_size));
	ret = 1;
	return ret;

}

int PKCS7_parse_content_info(uint8_t** der_bytes, CBS* out, CBS* cbs) {

	CBS in, content_info, content_type, wrapped_signed_data, signed_data;
	CBS spcIndirectDataWrapper, spcIndirectDataContentType, wrappered_spc_indirect_data, ret;
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
	CBS_get_asn1(&content_info, &wrapped_signed_data,
		CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0);
	CBS_get_asn1(&wrapped_signed_data, &signed_data, CBS_ASN1_SEQUENCE);
	CBS_get_asn1_uint64(&signed_data, &version);
	CBS_get_asn1(&signed_data, NULL /* digests */, CBS_ASN1_SET);
	CBS_get_asn1(&signed_data, &spcIndirectDataWrapper /* content */, CBS_ASN1_SEQUENCE);
	CBS_get_asn1(&spcIndirectDataWrapper, &spcIndirectDataContentType /* content */, CBS_ASN1_OBJECT);
	CBS_get_asn1(&spcIndirectDataWrapper, &wrappered_spc_indirect_data,
		CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0);
	CBS_get_asn1(&wrappered_spc_indirect_data, &ret /* content */, CBS_ASN1_SEQUENCE);

	if (version < 1) {
		OPENSSL_PUT_ERROR(PKCS7, PKCS7_R_BAD_PKCS7_VERSION);
		goto err;
	}

	CBS_init(out, CBS_data(&ret), CBS_len(&ret));
	return 1;

err:
	OPENSSL_free(*der_bytes);
	*der_bytes = NULL;
	return 0;

}


int PKCS7_get_raw_content_info(vector<uint8_t>& out_content_info, size_t& out_content_info_size, CBS* cbs,
	CRYPTO_BUFFER_POOL* pool) {

	CBS content_info;
	uint8_t* der_bytes = NULL;
	int ret = 0;
	if (!PKCS7_parse_content_info(&der_bytes, &content_info, cbs)) {
		return ret;
	}
	out_content_info_size = CBS_len(&content_info);
	uint8_t* tmp = (uint8_t*)CBS_data(&content_info);
	out_content_info.resize(out_content_info_size);
	out_content_info.assign(tmp, (tmp + out_content_info_size));
	ret = 1;
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

int PKCS7_get_public_key_info_value(CBS* cbs) {

	int ret = 0;
	size_t public_key_info_size = 0;
	vector<uint8_t> public_key_info;
	PKCS7_get_raw_public_key_info(public_key_info, public_key_info_size, cbs, NULL);
	std::ofstream outfile("public_key_info.bin", std::ofstream::binary);
	outfile.write((const char*)public_key_info.data(), public_key_info.size());
	outfile.close();
	ret = 1;
	return ret;
}

int PKCS7_get_tbs_certificate(CBS* cbs) {

	int ret = 0;
	size_t tbs_certificate_size = 0;
	vector<uint8_t> tbs_certificate;
	PKCS7_get_raw_tbs_certificate(tbs_certificate, tbs_certificate_size, cbs, NULL);
	std::ofstream outfile("tbs_certificate.bin", std::ofstream::binary);
	outfile.write((const char*)tbs_certificate.data(), tbs_certificate.size());
	outfile.close();
	ret = 1;
	return ret;
}

int PKCS7_get_signature(CBS* cbs) {
	int ret = 0;
	size_t signature_size = 0;
	vector<uint8_t> signature;
	PKCS7_get_raw_signature(signature, signature_size, cbs, NULL);

	//output file
	std::ofstream outfile("signature.bin", std::ofstream::binary);
	outfile.write((const char*)signature.data(), signature.size());
	outfile.close();
	ret = 1;
	return ret;
}

int PKCS7_get_signer_info(CBS* cbs) {
	int ret = 0;
	size_t signer_info_size = 0;
	vector<uint8_t> signerInfo;
	PKCS7_get_raw_signer_info(signerInfo, signer_info_size, cbs, NULL);
	vector<uint8_t> prefix = { 0x31, (uint8_t)signer_info_size };
	signerInfo.insert(signerInfo.begin(), prefix.begin(), prefix.end());
	//
	//output file
	std::ofstream outfile("signer_info.bin", std::ofstream::binary);
	outfile.write((const char*)signerInfo.data(), signerInfo.size());
	outfile.close();
	ret = 1;
	return ret;
}

int PKCS7_get_content_info(CBS* cbs) {
	int ret = 0;
	size_t content_info_size = 0;
	vector <uint8_t> content_info;
	PKCS7_get_raw_content_info(content_info, content_info_size, cbs, NULL);

	//get digest (message_digest)
	std::unique_ptr<unsigned char*>digest = make_unique<unsigned char*>();
	size_t digest_len;

	digest_message(content_info.data(), content_info_size, digest.get(), &digest_len);
	std::ofstream outfile("content_info.bin", std::ofstream::binary);
	outfile.write((const char*)content_info.data(), content_info.size());
	outfile.close();
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


	STACK_OF(X509*) out_digest;
	out_digest = sk_X509_new_null();
	//PKCS7_get_spcIndirectDataContext_value(out_digest, &cbs);
	CBS_init(&cbs, *inp, len);
	PKCS7_get_public_key_info_value(&cbs);
	CBS_init(&cbs, *inp, len);
	PKCS7_get_tbs_certificate(&cbs);
	CBS_init(&cbs, *inp, len);
	PKCS7_get_signature(&cbs);
	CBS_init(&cbs, *inp, len);
	PKCS7_get_signer_info(&cbs);
	CBS_init(&cbs, *inp, len);
	PKCS7_get_content_info(&cbs);
	return nullptr;
}

//static const ASN1_TEMPLATE PKCS7_seq_tt[] = {
//	{  (0), (0), offsetof(PKCS7, type),
//	   "type", NULL
//	},
//	 { ASN1_TFLG_ADB_OID, -1, 0, "PKCS7", 0 }
//};
//
//const ASN1_ITEM* PKCS7_it(void) {
//	static const ASN1_ITEM local_it = {
//		ASN1_ITYPE_SEQUENCE,
//		V_ASN1_SEQUENCE,
//		PKCS7_seq_tt,
//		sizeof(PKCS7_seq_tt) / sizeof(ASN1_TEMPLATE),
//		NULL,
//		sizeof(PKCS7),
//		"PKCS7"
//	};
//	return &local_it;
//};

//IMPLEMENT_ASN1_FUNCTIONS(PKCS7)
int main()
{
	std::string filePath = "D:\\downloadTest\\certTest5\\keyboard_dark_sha1_signature";
	std::ifstream input(filePath, std::ios::binary);
	// copies all data into buffer
	std::vector<char> buffer(std::istreambuf_iterator<char>(input), {});
	const unsigned char* pCertificate = reinterpret_cast<unsigned char*>(buffer.data());

	//PKCS7* pcks7 = d2i_PKCS7(NULL, &pCertificate, buffer.size());

	unsigned char* abuf = NULL;

	//ASN1_VALUE* myAns = ASN1_item_d2i(NULL, &pCertificate, buffer.size(), PKCS7_it());
	//X509_STORE* store = NULL;
	//store = X509_STORE_new();
	//STACK_OF(X509)* certs = pcks7->d.sign->cert;
	//for (int i = 0; certs && i < sk_X509_num(certs); i++) {
	//	X509* x = sk_X509_value(certs, i);

	//	int j = i + 1;
	//}
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
