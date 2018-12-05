#include<fstream>
#include<sstream>
#include<string>
#include<json/json.h>
#include<pybind11/pybind11.h>
#include"wrapper.h"
using namespace std;
namespace py = pybind11;
using namespace pybind11::literals;

string dertojson(string filename)
{
	ifstream f(filename);
	stringstream ss;
	ss << der2json(f);
	return ss.str();
}

string pemtojson(string filename)
{
	ifstream f(filename);
	stringstream ss;
	ss << pem2json(f);
	return ss.str();
}

PyAES::PyAES(int key) : AES(key)
{ }

void PyAES::key(py::int_ k) 
{
	AES::key(mpz_class{py::str(k)});
}

void PyAES::iv(py::int_ k)
{
	AES::iv(mpz_class{py::str(k)});
}

vector<unsigned char> PyAES::encrypt(vector<unsigned char> v)
{
	return AES::encrypt(v.cbegin(), v.cend());
}

vector<unsigned char> PyAES::decrypt(vector<unsigned char> v)
{
	return AES::decrypt(v.cbegin(), v.cend());
}

void PyPRF::secret(vector<unsigned char> v)
{
	PRF<SHA2>::secret(v.cbegin(), v.cend());
}
void PyPRF::seed(vector<unsigned char> v)
{
	PRF<SHA2>::seed(v.cbegin(), v.cend());
}

PyDiffie::PyDiffie(int bit) : DiffieHellman{bit}
{ }

PyDiffie::PyDiffie(py::int_ p, py::int_ g, py::int_ ya)
	: DiffieHellman{mpz_class{py::str(p)}, mpz_class{py::str(g)},
		mpz_class{py::str(ya)}}
{ }

py::int_ PyDiffie::set_yb(py::int_ pubkey)
{
	DiffieHellman::set_yb(mpz_class{py::str(pubkey)});
	return get_K();
}

py::int_ PyDiffie::get_p()
{
	return py::str(p.get_str());
}
py::int_ PyDiffie::get_g()
{
	return py::str(g.get_str());
}
py::int_ PyDiffie::get_K()
{
	return py::str(K.get_str());
}
py::int_ PyDiffie::get_ya()
{
	return py::str(ya.get_str());
}
py::int_ PyDiffie::get_yb()
{
	return py::str(yb.get_str());
}

PyRSA::PyRSA(int bit) : RSA{bit}
{ }
PyRSA::PyRSA(py::int_ e, py::int_ d, py::int_ K)
	: RSA{mpz_class{py::str(e)}, mpz_class{py::str(d)}, mpz_class{py::str(K)}}
{ }
py::int_ PyRSA::encode(py::int_ m)
{
	return py::str(RSA::encode(mpz_class{py::str(m)}).get_str());
}
py::int_ PyRSA::decode(py::int_ m)
{
	return py::str(RSA::decode(mpz_class{py::str(m)}).get_str());
}
