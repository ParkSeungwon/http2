#include<pybind11/pybind11.h>
#include<pybind11/stl.h>
#include<pybind11/iostream.h>
#include"wrapper.h"
using namespace std;
using namespace pybind11;
using namespace pybind11::literals;

PYBIND11_MODULE(tls_crypt, m) {
	m.def("base64_encode", &base64_encode);
	m.def("base64_decode", &base64_decode);
	m.def("pem2json", &pemtojson);
	m.def("der2json", &dertojson);
	class_<PyAES>(m, "AES")
		.def(init<unsigned short>(), "bit"_a = 128)
		.def("key", &PyAES::key)
		.def("iv", &PyAES::iv)
		.def("encrypt", &PyAES::encrypt)
		.def("decrypt", &PyAES::decrypt)
		;
	class_<PySHA256>(m, "SHA256")
		.def(init<>())
		.def("hash", &PySHA256::hash);
	class_<PySHA1>(m, "SHA1")
		.def(init<>())
		.def("hash", &PySHA1::hash);
	class_<PySHA512>(m, "SHA512")
		.def(init<>())
		.def("hash", &PySHA512::hash);
	class_<PyHMAC>(m, "HMAC")
		.def(init<>())
		.def("key", &PyHMAC::key)
		.def("hash", &PyHMAC::hash)
		;
	class_<PyPRF>(m, "PRF")
		.def(init<>())
		.def("label", &PyPRF::label)
		.def("seed", &PyPRF::seed)
		.def("secret", &PyPRF::secret)
		.def("get_n_byte", &PyPRF::get_n_byte)
		;
	class_<PyDiffie>(m, "DiffieHellman")
		.def(init<int>(), "bit"_a = 1024)
		.def(init<int_, int_, int_>())
		.def("set_yb", &PyDiffie::set_yb)
		.def_property_readonly("K", &PyDiffie::get_K)
		.def_property_readonly("p", &PyDiffie::get_p)
		.def_property_readonly("g", &PyDiffie::get_g)
		.def_property_readonly("ya", &PyDiffie::get_ya)
		.def_property_readonly("yb", &PyDiffie::get_yb)
		;
	class_<PyRSA>(m, "RSA") //		.def(init<int>(), "key_size"_a = 1024)
		.def(init<int>(), "bit"_a = 1024)
		.def(init<int_, int_, int_>())
		.def("encode", &PyRSA::encode)
		.def("decode", &PyRSA::decode)
		.def("sign", &PyRSA::decode)
		;
}
