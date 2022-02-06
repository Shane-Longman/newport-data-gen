bn_rand: bn_rand.cpp
	$(CXX) bn_rand.cpp -o bn_rand \
	-std=c++17 -march=native \
	$(OSSL_DIR)/libcrypto.a \
	-I$(OSSL_DIR) \
	-I$(OSSL_DIR)/include \
	-O3
