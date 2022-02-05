OSSL_DIR=openssl-OpenSSL_0_9_8h
OSSL_MAKEFLAGS?=-j4
OSSL_FLAGS?="-march=native"

#main: openssl-OpenSSL_0_9_8h/libcrypto.a
main: $(OSSL_DIR)/libcrypto.a main.cpp parse_args.cpp parse_args.hpp unaddr.cpp unaddr.hpp ntohl.h
	$(CXX) \
    main.cpp parse_args.cpp unaddr.cpp -o main \
    -std=c++17 -march=native \
    $(OSSL_DIR)/libcrypto.a \
    -I$(OSSL_DIR) \
    -I$(OSSL_DIR)/include \
    -O3

$(OSSL_DIR)/libcrypto.a: $(OSSL_DIR)/config Makefile
	patch --forward -p0 < patches/openssl-x86_64-bintuils-2.20.51.patch; [ $$? -lt 2 ]
	cd $(OSSL_DIR) && ./config no-threads no-shared no-rc2 no-rc4 no-rc5 no-idea no-des no-bf no-cast no-camellia no-seed no-dh $(OSSL_FLAGS) && cd ..
	$(MAKE) -C $(OSSL_DIR) $(OSSL_MAKEFLAGS) depend
	$(MAKE) -C $(OSSL_DIR) $(OSSL_MAKEFLAGS) build_crypto


$(OSSL_DIR)/config: openssl-OpenSSL_0_9_8h.zip
	unzip -u openssl-OpenSSL_0_9_8h.zip
	touch $(OSSL_DIR)/config

openssl-OpenSSL_0_9_8h.zip:
	wget -c https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_0_9_8h.zip -O openssl-OpenSSL_0_9_8h.zip
