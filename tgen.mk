tgen: $(OSSL_DIR)/libcrypto.a tgen.cpp tgen.mk
	$(CXX) \
	tgen.cpp -o tgen \
	-std=c++17 -march=native \
	$(OSSL_DIR)/libcrypto.a \
	-I$(OSSL_DIR) \
	-I$(OSSL_DIR)/include \
	-O3
