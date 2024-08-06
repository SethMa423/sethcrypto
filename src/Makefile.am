bin_PROGRAMS = digest ECC_checkkey ECC_genkey ECC_sign ECC_verify ECC_encrypt \
				ECC_decrypt random symfunc DH

digest_SOURCES = my_math.c base64.c random.c \
				sm2.c program/functiontest.c sm2_tool.c \
				aes.c sm4.c des.c sm1.c \
				symmetric.c tool.c hash.c hmac.c

ECC_checkkey_SOURCES = my_math.c base64.c random.c \
				sm2.c program/functiontest.c sm2_tool.c \
				aes.c sm4.c des.c sm1.c \
				symmetric.c tool.c hash.c hmac.c

ECC_genkey_SOURCES = my_math.c base64.c random.c \
				sm2.c program/functiontest.c sm2_tool.c \
				aes.c sm4.c des.c sm1.c \
				symmetric.c tool.c hash.c hmac.c

ECC_sign_SOURCES = my_math.c base64.c random.c \
				sm2.c program/functiontest.c sm2_tool.c \
				aes.c sm4.c des.c sm1.c \
				symmetric.c tool.c hash.c hmac.c

ECC_verify_SOURCES = my_math.c base64.c random.c \
				sm2.c program/functiontest.c sm2_tool.c \
				aes.c sm4.c des.c sm1.c \
				symmetric.c tool.c hash.c hmac.c

ECC_encrypt_SOURCES = my_math.c base64.c random.c \
				sm2.c program/functiontest.c sm2_tool.c \
				aes.c sm4.c des.c sm1.c \
				symmetric.c tool.c hash.c hmac.c

ECC_decrypt_SOURCES = my_math.c base64.c random.c \
				sm2.c program/functiontest.c sm2_tool.c \
				aes.c sm4.c des.c sm1.c \
				symmetric.c tool.c hash.c hmac.c

random_SOURCES = my_math.c base64.c random.c \
				sm2.c program/functiontest.c sm2_tool.c \
				aes.c sm4.c des.c sm1.c \
				symmetric.c tool.c hash.c hmac.c

symfunc_SOURCES = my_math.c base64.c random.c \
				sm2.c program/functiontest.c sm2_tool.c \
				aes.c sm4.c des.c sm1.c \
				symmetric.c tool.c hash.c hmac.c

DH_SOURCES = base64.c random.c program/functiontest.c \
			 tool.c hash.c diffie_hellman.c

digest_CPPFLAGS = -DDIGEST -I $(top_srcdir)/src/include

ECC_checkkey_CPPFLAGS = -DECCCHECKKEY -I $(top_srcdir)/src/include

ECC_genkey_CPPFLAGS = -DSM2GENKEY -I $(top_srcdir)/src/include

ECC_sign_CPPFLAGS = -DECCSIGN -I $(top_srcdir)/src/include

ECC_verify_CPPFLAGS = -DSM2VERIFY -I $(top_srcdir)/src/include

ECC_encrypt_CPPFLAGS = -DECCENCRYPT -I $(top_srcdir)/src/include

ECC_decrypt_CPPFLAGS = -DECCDECRYPT -I $(top_srcdir)/src/include

random_CPPFLAGS = -DRANDOM -I $(top_srcdir)/src/include

symfunc_CPPFLAGS = -DSYMFUNC -I $(top_srcdir)/src/include

DH_CPPFLAGS = -DDH -I $(top_srcdir)/src/include
DH_LDADD = -ltommath -lm