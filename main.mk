main: $(OSSL_DIR)/libcrypto.a main.cpp parse_args.cpp parse_args.hpp unaddr.cpp unaddr.hpp ntohl.h main.mk
	$(CXX) \
	main.cpp parse_args.cpp unaddr.cpp -o main \
	-std=c++17 -march=native \
	$(OSSL_DIR)/libcrypto.a \
	-I$(OSSL_DIR) \
	-I$(OSSL_DIR)/include \
	-O3

include openssl.mk
