#pragma once
#include<pybind11/pybind11.h>
#include"tls/crypt.h"

std::string pemtojson(std::string filename);
std::string dertojson(std::string filename);

struct PyAES : public AES
{
	PyAES(int bit = 128);
	void key(pybind11::int_);
	void iv(pybind11::int_);
	std::vector<unsigned char> encrypt(std::vector<unsigned char> m);
	std::vector<unsigned char> decrypt(std::vector<unsigned char> m);
};

struct PySHA1 : public SHA1
{
	auto hash(std::vector<unsigned char> v) {
		return SHA1::hash(v.cbegin(), v.cend());
	}
};
struct PySHA256 : public SHA2
{
	auto hash(std::vector<unsigned char> v) {
		return SHA2::hash(v.cbegin(), v.cend());
	}
};
struct PySHA512 : public SHA5
{
	auto hash(std::vector<unsigned char> v) {
		return SHA5::hash(v.cbegin(), v.cend());
	}
};
struct PyHMAC : public HMAC<SHA2>
{
	void key(std::vector<unsigned char> v) {
		HMAC<SHA2>::key(v.cbegin(), v.cend());
	}
	auto hash(std::vector<unsigned char> v) {
		return HMAC<SHA2>::hash(v.cbegin(), v.cend());
	}
};

struct PyPRF : public PRF<SHA2>
{
	void secret(std::vector<unsigned char> v);
	void seed(std::vector<unsigned char> v);
};

struct PyDiffie : public DiffieHellman
{
	PyDiffie(int bit = 1024);
	PyDiffie(pybind11::int_ p, pybind11::int_ g, pybind11::int_ ya);
	pybind11::int_ set_yb(pybind11::int_ pub_key);
	pybind11::int_ get_p();
	pybind11::int_ get_g();
	pybind11::int_ get_K();
	pybind11::int_ get_ya();
	pybind11::int_ get_yb();
};

struct PyRSA : public RSA
{
	PyRSA(int bit = 1024);
	PyRSA(pybind11::int_ e, pybind11::int_ d, pybind11::int_ K);
	pybind11::int_ encode(pybind11::int_ m), decode(pybind11::int_ m);
};
