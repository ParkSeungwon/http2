#include<catch.hpp>
#include<fstream>
#include<iostream>
#include<iomanip>
#include<gmpxx.h>
#include"crypt.h"
using namespace std;

//TEST_CASE("embed picture with base64 encode") {
//	unsigned char c; vector<unsigned char> v;
//	while(cin >> noskipws >> c) v.push_back(c);
//	cout << "<img src='data:image/jpeg;base64,";
//	cout << base64_encode(v);
//	cout << "'>";
//}

//TEST_CASE("www.dndd.com.???") {
//	const char* file[] = {"www.dndd.com.key", "www.dndd.com.pub", 
//						  "www.dndd.com.cert", "www.dndd.com.mod"};
//	mpz_class z[4];
//	for(int i=0; i<3; i++) {
//		unsigned char c; string s;
//		ifstream f(file[i]);
//		while(f >> noskipws >> c) s += c;
//		auto a = base64_decode(s);
//		z[i] = bnd2mpz(a.begin(), a.end());
//	}
//	ifstream f(file[3]);
//	vector<unsigned char> v;
//	for(string s; f >> setw(2) >> hex >> s;) v.push_back(stoi(s, nullptr,16));
//	z[3] = bnd2mpz(v.begin(), v.end());
//	for(auto a : z) cout << hex << a << endl;
//	cout << powm(z[2], z[1], z[3]) << endl;
//}

TEST_CASE("RSA class test") {
	cout << nextprime(5) << endl;
	RSA rsa{32};
	mpz_class a;
	cout << (a = rsa.encode(2000)) << ' ';
	cout << rsa.decode(a) << endl;

	unsigned char s[] = "Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure.";
	auto t = base64_encode({s, s+269});
	cout << t << endl;
	string e = "\
MIIEqjCCA5KgAwIBAgIJALe2kDNmG2sjMA0GCSqGSIb3DQEBCwUAMIGUMQswCQYD\
VQQGEwJVUzEQMA4GA1UECAwHTW9udGFuYTEQMA4GA1UEBwwHQm96ZW1hbjERMA8G\
A1UECgwIU2F3dG9vdGgxEzARBgNVBAsMCkNvbnN1bHRpbmcxGDAWBgNVBAMMD3d3\
dy53b2xmc3NsLmNvbTEfMB0GCSqGSIb3DQEJARYQaW5mb0B3b2xmc3NsLmNvbTAe\
Fw0xNjA4MTEyMDA3MzdaFw0xOTA1MDgyMDA3MzdaMIGUMQswCQYDVQQGEwJVUzEQ\
MA4GA1UECAwHTW9udGFuYTEQMA4GA1UEBwwHQm96ZW1hbjERMA8GA1UECgwIU2F3\
dG9vdGgxEzARBgNVBAsMCkNvbnN1bHRpbmcxGDAWBgNVBAMMD3d3dy53b2xmc3Ns\
LmNvbTEfMB0GCSqGSIb3DQEJARYQaW5mb0B3b2xmc3NsLmNvbTCCASIwDQYJKoZI\
hvcNAQEBBQADggEPADCCAQoCggEBAL8Myi0Ush6EQlvNOB9K8k11EPG2NZ/fyn0D\
mNOs3gNm7irx2LB9bgdUCxCYIU2AyxIg58xP3kV9yXJ3MurKkLtpUhADL6jzlcXx\
i2JWG+9nb6QQQZWtCpvjpcCw0nB2UDBbqOgILHztp6J6jTgpHKzH7fJ8lbCVgn1J\
XDjNdyXvvYB1U5Q8PcpjW58VtdMdEy8Z0TzbdjrMuH3J5cLX2kBv2CHccxtCLVOc\
/hr8fat6Nj+Y3oR8BWfOahQ4h6nxjLVoy2h/cSAr9aBj9VYvoybSt2+xWhfXOJkI\
/pNYb/7DE0kIFgunTWcAUjFnI06Y7VFFHbkE2Qvs2CizS73tNnkCAwEAAaOB/DCB\
+TAdBgNVHQ4EFgQUJ45nEXTDJh0/7TNjs6TYHTDl6NUwgckGA1UdIwSBwTCBvoAU\
J45nEXTDJh0/7TNjs6TYHTDl6NWhgZqkgZcwgZQxCzAJBgNVBAYTAlVTMRAwDgYD\
VQQIDAdNb250YW5hMRAwDgYDVQQHDAdCb3plbWFuMREwDwYDVQQKDAhTYXd0b290\
aDETMBEGA1UECwwKQ29uc3VsdGluZzEYMBYGA1UEAwwPd3d3LndvbGZzc2wuY29t\
MR8wHQYJKoZIhvcNAQkBFhBpbmZvQHdvbGZzc2wuY29tggkAt7aQM2YbayMwDAYD\
VR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEADpNIREpylmBxJYKpLMpgW/KI\
Ps8RdFoRStzZ2PZYLAXTVtnpjzfvjj47/yI2AMrY4pY/p9HtH956sNePNr1BVR7U\
uYY7hyVpNWBI1uRalM6i+nA4NsSFtEsj/nGeL9sGx7WcIfA+fOuR+FwJ/YRDpLNO\
BAwiMXFqSMiru+jO+mcVGjqCmEMztQ4fHon4N94b5rWg9KKLtxyQuphtlCEIgF3z\
v2atyXIoempI7s9jaTGMxY5m2kt4ZegDOkv4zEJU01JcLQSuJofhfkDLRUEWS26j\
Lkp2vSl/HFM3Bq3pW2rWt06UonzorE6mUD4rMp5oQhvkWWdh6seaUZwcVaN3dg==";
	for(auto& a : base64_decode(e)) cout << hex << +a << ' '; cout << endl;
}
