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
PyClient::PyClient(string ip, int port) : Client{ip, port}
{ }
void PyClient::send(vector<unsigned char> v)
{
	Client::send(string{v.begin(), v.end()}, 0);
}
vector<unsigned char> PyClient::recv()
{
	vector<unsigned char> v;
	for(unsigned char c : Client::recv(0)) v.push_back(c);
	return v;
}
PyTLSClient::PyTLSClient(string ip, int port) : PyClient(ip, port)
{ }

int PyTLSClient::get_full_length(const string &s) 
{
	return static_cast<unsigned char>(s[3]) * 0x100 + static_cast<unsigned char>(s[4]) + 5;
}

PyHTTPSCLient::PyHTTPSCLient(string ip, int port) : Client(ip, port)
{
	send(t.client_hello());
	t.server_hello(recv());
	t.server_certificate(recv());
	if(t.support_dhe()) t.server_key_exchange(recv());
	t.server_hello_done(recv());
	send(t.client_key_exchange());
	send(t.change_cipher_spec());
	send(t.finished());
	t.change_cipher_spec(recv());
	t.finished(recv());
}
int PyHTTPSCLient::get_full_length(const string &s) 
{
	return static_cast<unsigned char>(s[3]) * 0x100 + static_cast<unsigned char>(s[4]) + 5;
}
void PyHTTPSCLient::pysend(string s)
{
	send(t.encode(move(s)));
}
string PyHTTPSCLient::pyrecv()
{
	return t.decode(recv());
}
PyTLS::PyTLS() : TLS{nullptr}
{ }

std::vector<unsigned char> PyTLS::encode(std::vector<unsigned char> s)
{
	std::vector<unsigned char> v; std::string t;
	for(unsigned char c : s) t += c;
	for(unsigned char c : TLS<false>::encode(move(t))) v.push_back(c);
	return v;
}

string PySQL::select(string table, string where)
{
	SqlQuery::select(table, where);
	stringstream ss; ss << *this;
	return ss.str();
}

bool PySQL::insert(vector<string> v)
{
	SqlQuery::insert(v);
}
