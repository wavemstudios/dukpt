/*
 * dukpt.c
 *
 *  Created on: 28 Jul 2016
 *      Author: steve
 */
/**
 * FEIG ELECTRONIC Contactless Demo
 *
 * Copyright (C) 2016 FEIG ELECTRONIC GmbH
 *
 * This software is the confidential and proprietary information of
 * FEIG ELECTRONIC GmbH ("Confidential Information"). You shall not
 * disclose such Confidential Information and shall use it only in
 * accordance with the terms of the license agreement you entered
 * into with FEIG ELECTRONIC GmbH.
 */

/*
 * This demo program looks up the DUKPT initial key with id 0xCC01 and label
 * "DUKPT_IK" in application 0's Cryptographic Token and executes three
 * transaction key derivations and data encryption operations.
 *
 * Build as follows:
 *
 * arm-linux-gcc -Wall -Werror dukpt-demo.c -o dukpt-demo -lfepkcs11 -lcrypto
 * fesign --module opensc-pkcs11.so --pin 648219 --slotid 1 --keyid 00a0 \
 *	  --infile dukpt-demo
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <feig/fepkcs11.h>

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(*(x)))

#define IMPORTKEY

static char *bin2hex(char *out, const void *in, size_t len)
{
	const char *p = (const char *)in;
	size_t i;

	for (i = 0; i < len; i++) {
		char digit;

		digit = p[i] >> 4;
		digit = digit < 0xA ? digit + '0' : digit - 10 + 'A';
		out[2 * i] = digit;

		digit = p[i] & 0xF;
		digit = digit < 0xA ? digit + '0' : digit - 10 + 'A';
		out[2 * i + 1] = digit;
	}

	out[2 * len] = '\0';

	return out;
}

static void crypto_token_login(CK_SESSION_HANDLE_PTR phSession)
{
	CK_RV rv = CKR_OK;

	rv = C_Initialize(NULL_PTR);
	assert(rv == CKR_OK);

	rv = C_OpenSession(FEPKCS11_APP0_TOKEN_SLOT_ID,
		    CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, phSession);
	assert(rv == CKR_OK);

	rv = C_Login(*phSession, CKU_USER, NULL_PTR, 0);
	assert(rv == CKR_OK);
}

static void crypto_token_logout(CK_SESSION_HANDLE hSession)
{
	CK_RV rv = CKR_OK;

	rv = C_Logout(hSession);
	assert(rv == CKR_OK);

	rv = C_CloseSession(hSession);
	assert(rv == CKR_OK);

	rv = C_Finalize(NULL_PTR);
	assert(rv == CKR_OK);
}

static CK_OBJECT_HANDLE get_dukpt_ikey(CK_SESSION_HANDLE hSession, char *label,
								    uint16_t id)
{
	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS dukptClass = CKO_DUKPT_IKEY;
	CK_KEY_TYPE dukptKeyType = CKK_DES2;
	CK_ATTRIBUTE attrs_dukpt_key[] = {
		{ CKA_CLASS, &dukptClass, sizeof(dukptClass) },
		{ CKA_KEY_TYPE, &dukptKeyType, sizeof(dukptKeyType) },
		{ CKA_LABEL, label, strlen(label) },
		{ CKA_ID, &id, sizeof(id) }
	};
	CK_ULONG ulObjectCount = 0;
	CK_RV rv = CKR_OK;

	rv = C_FindObjectsInit(hSession, attrs_dukpt_key,
						   ARRAY_SIZE(attrs_dukpt_key));
	assert(rv == CKR_OK);

	rv = C_FindObjects(hSession, &hKey, 1, &ulObjectCount);
	assert(rv == CKR_OK);

	rv = C_FindObjectsFinal(hSession);
	assert(rv == CKR_OK);

	return hKey;
}

static unsigned char *get_key_serial_number(CK_SESSION_HANDLE hSession,
				  CK_OBJECT_HANDLE hIKey, unsigned char ksn[10])
{
	CK_ATTRIBUTE ksn_template[] = {
		{ CKA_DUKPT_KEY_SERIAL_NUMBER, ksn, 10 }
	};
	CK_RV rv = CKR_OK;

	rv = C_GetAttributeValue(hSession, hIKey, ksn_template,
						      ARRAY_SIZE(ksn_template));
	assert(rv == CKR_OK);

	return ksn;
}

static CK_OBJECT_HANDLE get_transaction_key(CK_SESSION_HANDLE hSession,
							 CK_OBJECT_HANDLE hIKey)
{
	CK_RV rv = CKR_OK;
	CK_OBJECT_HANDLE hTxnKey = CK_INVALID_HANDLE;
	CK_MECHANISM mechanism = {
		CKM_KEY_DERIVATION_DUKPT_TRANSACTION_KEY, NULL_PTR, 0
	};
	CK_BBOOL ckTrue = CK_TRUE;
	CK_BBOOL ckFalse = CK_FALSE;
	CK_ATTRIBUTE template[] = {
		{ CKA_TOKEN, &ckFalse, sizeof(ckFalse) },
		{ CKA_DERIVE, &ckTrue, sizeof(ckTrue) }
	};

	rv = C_DeriveKey(hSession, &mechanism, hIKey, template,
						ARRAY_SIZE(template), &hTxnKey);
	assert(rv == CKR_OK);

	return hTxnKey;
}

static CK_OBJECT_HANDLE get_data_key(CK_SESSION_HANDLE hSession,
						       CK_OBJECT_HANDLE hTxnKey)
{
	CK_RV rv = CKR_OK;
	CK_OBJECT_HANDLE hDataKey = CK_INVALID_HANDLE;
	CK_MECHANISM mechanism = {
		CKM_KEY_DERIVATION_DUKPT_DATA_ENCRYPTION_REQUEST, NULL_PTR, 0
	};
	CK_BBOOL ckTrue = CK_TRUE;
	CK_BBOOL ckFalse = CK_FALSE;
	CK_ATTRIBUTE template[] = {
		{ CKA_TOKEN, &ckFalse, sizeof(ckFalse) },
		{ CKA_ENCRYPT, &ckTrue, sizeof(ckTrue) }
	};

	rv = C_DeriveKey(hSession, &mechanism, hTxnKey, template,
					       ARRAY_SIZE(template), &hDataKey);
	assert(rv == CKR_OK);

	return hDataKey;
}

void dukpt_encrypt(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hIKey,
			    void *in, size_t in_len, void *out, size_t *out_len)
{
	CK_OBJECT_HANDLE hTxnKey = get_transaction_key(hSession, hIKey);
	CK_OBJECT_HANDLE hDataKey = get_data_key(hSession, hTxnKey);
	CK_BYTE iv[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	CK_MECHANISM mech_des3_cbc = { CKM_DES3_CBC, &iv, sizeof(iv) };
	CK_ULONG ulOutLen = (CK_ULONG)(*out_len);
	CK_RV rv = CKR_OK;
	size_t padded_len = (in_len + 7) & ~0x7u;
	unsigned char padded_in[padded_len];

	assert(*out_len >= padded_len);

	memset(padded_in, 0, sizeof(padded_in));
	memcpy(padded_in, in, in_len);

	rv = C_EncryptInit(hSession, &mech_des3_cbc, hDataKey);
	assert(rv == CKR_OK);

	rv = C_Encrypt(hSession, padded_in, padded_len, out, &ulOutLen);
	assert(rv == CKR_OK);

	*out_len = (size_t)ulOutLen;

	C_DestroyObject(hSession, hDataKey);
	C_DestroyObject(hSession, hTxnKey);
}

int main(void)
{
	CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hIKey = CK_INVALID_HANDLE;
	unsigned char ksn[10];
	char label[] = "DUKPT_IKEY", hex[256];
	uint16_t id = 0xCC01;
	char track2[] = ";4111111111111111=151220100000?";
	char track2ctls[] = "4111111111111111D15122010000000F";
	unsigned char icc[] = {
		0x5A, 0x08, 0x41, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		0x5F, 0x24, 0x03, 0x15, 0x12, 0x31,
		0x57, 0x0F, 0x41, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			    0xD1, 0x51, 0x22, 0x01, 0x00, 0x00, 0x0F
	};
	unsigned char buffer[128];
	size_t len = sizeof(buffer);

	crypto_token_login(&hSession);

#ifdef IMPORTKEY

#endif

	hIKey = get_dukpt_ikey(hSession, label, id);
	if (hIKey == CK_INVALID_HANDLE) {
		printf("No DUKPT Initial Key found (label '%s', id %02hX).\n",
								     label, id);
		goto done;
	}

	printf("Example 1: Contact Magstripe\n");
	printf("KSN       : %s\n", bin2hex(hex, get_key_serial_number(
					   hSession, hIKey, ksn), sizeof(ksn)));
	printf("Plaintext : %s\n", bin2hex(hex, track2, strlen(track2)));
	len = sizeof(buffer);
	dukpt_encrypt(hSession, hIKey, track2, strlen(track2), buffer, &len);
	printf("CipherText: %s\n\n", bin2hex(hex, buffer, len));

	printf("Example 2: Contactless Magstripe\n");
	printf("KSN       : %s\n", bin2hex(hex, get_key_serial_number(
					   hSession, hIKey, ksn), sizeof(ksn)));
	printf("Plaintext : %s\n", bin2hex(hex, track2ctls,
							   strlen(track2ctls)));
	len = sizeof(buffer);
	dukpt_encrypt(hSession, hIKey, track2ctls, strlen(track2ctls), buffer,
									  &len);
	printf("CipherText: %s\n\n", bin2hex(hex, buffer, len));

	printf("Example 3: ICC (Contact and Contactless)\n");
	printf("KSN       : %s\n", bin2hex(hex, get_key_serial_number(
					   hSession, hIKey, ksn), sizeof(ksn)));
	printf("Plaintext : %s\n", bin2hex(hex, icc, sizeof(icc)));
	len = sizeof(buffer);
	dukpt_encrypt(hSession, hIKey, icc, sizeof(icc), buffer, &len);
	printf("CipherText: %s\n", bin2hex(hex, buffer, len));

done:
	crypto_token_logout(hSession);

	return EXIT_SUCCESS;
}



