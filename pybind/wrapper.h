#pragma once
#include<pybind11/pybind11.h>
#include"framework/server.h"
#include"tls/crypt.h"
#include"tls/tls.h"
#include"database/mysqldata.h"

std::string pemtojson(std::string filename);
std::string dertojson(std::string filename);

struct PyAES
{
	CBC<AES<128>> aes;
	void enc_key(pybind11::int_);
	void dec_key(pybind11::int_);
	void enc_iv(pybind11::int_);
	void dec_iv(pybind11::int_);
	std::vector<unsigned char> decrypt(std::vector<unsigned char> m);
	std::vector<unsigned char> encrypt(std::vector<unsigned char> m);
};

struct PySHA1 : public SHA1
{
	auto hash(std::vector<unsigned char> v) {
		return SHA1::hash(v.cbegin(), v.cend());
	}
};
struct PySHA256 : public SHA256
{
	auto hash(std::vector<unsigned char> v) {
		return SHA256::hash(v.cbegin(), v.cend());
	}
};
struct PySHA512 : public SHA512
{
	auto hash(std::vector<unsigned char> v) {
		return SHA512::hash(v.cbegin(), v.cend());
	}
};
struct PyHMAC : public HMAC<SHA256>
{
	void key(std::vector<unsigned char> v) {
		HMAC<SHA256>::key(v.cbegin(), v.cend());
	}
	auto hash(std::vector<unsigned char> v) {
		return HMAC<SHA256>::hash(v.cbegin(), v.cend());
	}
};

struct PyPRF : public PRF<SHA256>
{
	void secret(std::vector<unsigned char> v);
	void seed(std::vector<unsigned char> v);
};

struct PyDiffie : public DHE
{
	PyDiffie(int bit = 2048);
	PyDiffie(pybind11::int_ p, pybind11::int_ g, pybind11::int_ ya);
	pybind11::int_ set_yb(pybind11::int_ pub_key);
	pybind11::int_ get_p(), get_g(), get_K(), get_ya(), get_yb();
};

struct PyRSA : public RSA
{
	PyRSA(int bit = 1024);
	PyRSA(pybind11::int_ e, pybind11::int_ d, pybind11::int_ K);
	pybind11::int_ encode(pybind11::int_ m), decode(pybind11::int_ m);
};

struct PyClient : Client
{
	PyClient(std::string ip, int port);
	void send(std::vector<unsigned char> v);
	std::vector<unsigned char> recv();
};
struct PyTLSClient : PyClient 
{
	PyTLSClient(std::string ip, int port);
	int get_full_length(const std::string &s);
};
class PyHTTPSCLient : Client
{
public:
	PyHTTPSCLient(std::string ip, int port);
	std::string pyrecv();
	void pysend(std::string s);
protected:
	TLS<false> t;
	int get_full_length(const std::string &s);
};
struct PyTLS : TLS<false>
{
	template<std::string (TLS<false>::*FP)(std::string&&)>
	std::vector<unsigned char> to_vector_func(std::vector<unsigned char> s) {
		std::vector<unsigned char> v; std::string t;
		for(unsigned char c : s) t += c;
		for(unsigned char c : (this->*FP)(move(t))) v.push_back(c);
		return v;
	}
	std::vector<unsigned char> encode(std::vector<unsigned char> s);
	std::string alert(std::vector<unsigned char> s);
};

struct PySQL : SqlQuery
{
	std::string select(std::string table, std::string where);
	bool insert(std::vector<std::string> v);
	bool connect(std::string ip, std::string user, std::string pass, std::string db);
	std::vector<std::tuple<std::string, int, std::string>> column();
};
