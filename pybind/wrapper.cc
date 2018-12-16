#include<fstream>
#include<sstream>
#include<string>
#include<json/json.h>
#include<pybind11/pybind11.h>
#include"tls/crypt.h"
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

void PyAES::key(py::int_ k) 
{
	unsigned char key[16];
	mpz_class z{py::str(k)};
	mpz2bnd(z, key, key + 16);
	AES::key(key);
}

void PyAES::iv(py::int_ k)
{
	unsigned char iv[16];
	mpz_class z{py::str(k)};
	mpz2bnd(z, iv, iv + 16);
	AES::iv(iv);
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
string PyTLS::alert(vector<unsigned char> v)
{
	if(v.empty()) return "";
	std::string s, t;
	for(unsigned char c : v) t += c;
	switch(TLS<false>::alert(move(t))) {//s reuse
		case 0: s = "close_notify(0)"; break;
		case 10: s = "unexpected_message(10)"; break;
		case 20: s = "bad_record_mac(20)"; break;
		case 21: s = "decryption_failed_RESERVED(21)"; break;
		case 22: s = "record_overflow(22)"; break;
		case 30: s = "decompression_failure(30)"; break;
		case 40: s = "handshake_failure(40)"; break;
		case 41: s = "no_certificate_RESERVED(41)"; break;
		case 42: s = "bad_certificate(42)"; break;
		case 43: s = "unsupported_certificate(43)"; break;
		case 44: s = "certificate_revoked(44)"; break;
		case 45: s = "certificate_expired(45)"; break;
		case 46: s = "certificate_unknown(46)"; break;
		case 47: s = "illegal_parameter(47)"; break;
		case 48: s = "unknown_ca(48)"; break;
		case 49: s = "access_denied(49)"; break;
		case 50: s = "decode_error(50)"; break;
		case 51: s = "decrypt_error(51)"; break;
		case 60: s = "export_restriction_RESERVED(60)"; break;
		case 70: s = "protocol_version(70)"; break;
		case 71: s = "insufficient_security(71)"; break;
		case 80: s = "internal_error(80)"; break;
		case 90: s = "user_canceled(90)"; break;
		case 100: s = "no_renegotiation(100)"; break;
		case 110: s = "unsupported_extension(110)"; break;
	}
	return s;
}

string PySQL::select(string table, string where)
{
	SqlQuery::select(table, where);
	stringstream ss; ss << *this;
	return ss.str();
}

bool PySQL::insert(vector<string> v)
{//because python cannot find appropiate overloading 
	return SqlQuery::insert(v);
}

bool PySQL::connect(string ip, string user, string pass, string db)
{
	return SqlQuery::connect(ip, user, pass, db);
}

vector<tuple<string, int, string>> PySQL::column()
{//tuple is converted easily in python
	vector<tuple<string, int, string>> r;
	for(auto col : columns) r.push_back(make_tuple(col.name, col.size, col.type));
	return r;
}
