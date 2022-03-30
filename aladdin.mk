aladdin: $(OSSL_DIR)/libcrypto.a aladdin.cpp aladdin.mk
	$(CXX) \
	aladdin.cpp -o aladdin \
	-std=c++17 -march=native \
	$(OSSL_DIR)/libcrypto.a \
	-I$(OSSL_DIR) \
	-I$(OSSL_DIR)/include \
	-O3
