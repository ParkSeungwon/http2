#include<catch.hpp>
#include<iostream>
#include<iomanip>
#include<cctype>
#include<fstream>
#include<sstream>
#include"tls/crypt.h"
using namespace std;

//from packt.pcap
const char server_random[] = "e8:87:ba:fc:0b:44:ff:47:fb:36:e6:85:b3:d7:d3:01:46:93:f0:99:28:25:ff:8b:ac:6b:b4:5c:0f:8d:10:3c";
const char client_random[] = "64:3e:fb:44:58:18:b5:50:62:36:f5:2e:c9:61:52:9b:7c:55:24:45:03:23:b6:0a:99:d5:3e:f7:89:ae:23:13";
const char cert[] = "30:82:06:bf:30:82:05:a7:a0:03:02:01:02:02:10:0d:e5:09:17:1e:ae:4f:d4:87:d8:90:d9:41:9c:9b:5f:30:0d:06:09:2a:86:48:86:f7:0d:01:01:0b:05:00:30:4d:31:0b:30:09:06:03:55:04:06:13:02:55:53:31:15:30:13:06:03:55:04:0a:13:0c:44:69:67:69:43:65:72:74:20:49:6e:63:31:27:30:25:06:03:55:04:03:13:1e:44:69:67:69:43:65:72:74:20:53:48:41:32:20:53:65:63:75:72:65:20:53:65:72:76:65:72:20:43:41:30:1e:17:0d:31:38:30:37:33:31:30:30:30:30:30:30:5a:17:0d:31:39:30:38:30:35:31:32:30:30:30:30:5a:30:81:97:31:0b:30:09:06:03:55:04:06:13:02:55:53:31:13:30:11:06:03:55:04:08:13:0a:43:61:6c:69:66:6f:72:6e:69:61:31:16:30:14:06:03:55:04:07:13:0d:4d:6f:75:6e:74:61:69:6e:20:56:69:65:77:31:1c:30:1a:06:03:55:04:0a:13:13:4d:6f:7a:69:6c:6c:61:20:43:6f:72:70:6f:72:61:74:69:6f:6e:31:17:30:15:06:03:55:04:0b:13:0e:43:6c:6f:75:64:20:53:65:72:76:69:63:65:73:31:24:30:22:06:03:55:04:03:13:1b:73:68:61:76:61:72:2e:73:65:72:76:69:63:65:73:2e:6d:6f:7a:69:6c:6c:61:2e:63:6f:6d:30:82:01:22:30:0d:06:09:2a:86:48:86:f7:0d:01:01:01:05:00:03:82:01:0f:00:30:82:01:0a:02:82:01:01:00:f4:2d:f9:2c:43:fa:01:53:39:9d:dc:05:8f:1a:57:30:bb:82:20:b9:99:40:7d:f0:32:81:5c:b7:86:47:e4:0a:50:c0:f8:d1:9a:bc:c7:bf:b8:68:87:67:26:42:d4:05:05:15:77:a1:d4:e9:96:0f:0e:d1:18:fb:ae:4f:be:46:6e:cf:75:99:a4:3c:99:ad:7e:96:17:10:ca:28:96:8f:ae:6c:2e:7f:40:ca:c9:a6:fa:19:b9:7e:af:01:02:d2:2a:ea:5c:2e:ea:36:9a:0d:15:82:e2:9a:af:25:0f:a9:9e:1d:16:f9:3d:e4:1d:bf:ce:90:78:16:44:81:a4:56:df:49:c7:4f:45:a3:eb:ae:77:6e:9f:3e:5e:11:b5:58:05:ac:39:50:12:2b:ca:5a:6d:f4:ed:29:d9:3b:81:b2:64:45:26:b9:18:27:49:17:ed:d3:09:ab:e9:fc:76:79:12:6e:a6:3a:82:13:95:d1:f7:9e:32:ac:5b:65:67:a0:27:e5:84:32:67:6f:4c:7d:32:1b:50:16:4e:b4:16:d6:dc:6a:89:5e:90:6d:fa:f1:01:d9:d8:06:e1:7d:be:f9:8a:d2:f6:f0:0e:ca:2a:f2:85:fc:fe:ce:e2:21:92:ad:67:b6:09:e7:29:64:fa:3c:f3:d2:f5:7b:d7:40:01:7f:02:03:01:00:01:a3:82:03:4e:30:82:03:4a:30:1f:06:03:55:1d:23:04:18:30:16:80:14:0f:80:61:1c:82:31:61:d5:2f:28:e7:8d:46:38:b4:2c:e1:c6:d9:e2:30:1d:06:03:55:1d:0e:04:16:04:14:d0:52:53:87:3a:66:80:77:7e:5c:af:f4:32:f2:e1:53:b8:26:95:6f:30:81:88:06:03:55:1d:11:04:81:80:30:7e:82:1b:73:68:61:76:61:72:2e:73:65:72:76:69:63:65:73:2e:6d:6f:7a:69:6c:6c:61:2e:63:6f:6d:82:28:74:72:61:63:6b:69:6e:67:2d:70:72:6f:74:65:63:74:69:6f:6e:2e:73:65:72:76:69:63:65:73:2e:6d:6f:7a:69:6c:6c:61:2e:63:6f:6d:82:1d:74:72:61:63:6b:69:6e:67:2e:73:65:72:76:69:63:65:73:2e:6d:6f:7a:69:6c:6c:61:2e:63:6f:6d:82:16:73:68:61:76:61:72:2e:70:72:6f:64:2e:6d:6f:7a:61:77:73:2e:6e:65:74:30:0e:06:03:55:1d:0f:01:01:ff:04:04:03:02:05:a0:30:1d:06:03:55:1d:25:04:16:30:14:06:08:2b:06:01:05:05:07:03:01:06:08:2b:06:01:05:05:07:03:02:30:6b:06:03:55:1d:1f:04:64:30:62:30:2f:a0:2d:a0:2b:86:29:68:74:74:70:3a:2f:2f:63:72:6c:33:2e:64:69:67:69:63:65:72:74:2e:63:6f:6d:2f:73:73:63:61:2d:73:68:61:32:2d:67:36:2e:63:72:6c:30:2f:a0:2d:a0:2b:86:29:68:74:74:70:3a:2f:2f:63:72:6c:34:2e:64:69:67:69:63:65:72:74:2e:63:6f:6d:2f:73:73:63:61:2d:73:68:61:32:2d:67:36:2e:63:72:6c:30:4c:06:03:55:1d:20:04:45:30:43:30:37:06:09:60:86:48:01:86:fd:6c:01:01:30:2a:30:28:06:08:2b:06:01:05:05:07:02:01:16:1c:68:74:74:70:73:3a:2f:2f:77:77:77:2e:64:69:67:69:63:65:72:74:2e:63:6f:6d:2f:43:50:53:30:08:06:06:67:81:0c:01:02:02:30:7c:06:08:2b:06:01:05:05:07:01:01:04:70:30:6e:30:24:06:08:2b:06:01:05:05:07:30:01:86:18:68:74:74:70:3a:2f:2f:6f:63:73:70:2e:64:69:67:69:63:65:72:74:2e:63:6f:6d:30:46:06:08:2b:06:01:05:05:07:30:02:86:3a:68:74:74:70:3a:2f:2f:63:61:63:65:72:74:73:2e:64:69:67:69:63:65:72:74:2e:63:6f:6d:2f:44:69:67:69:43:65:72:74:53:48:41:32:53:65:63:75:72:65:53:65:72:76:65:72:43:41:2e:63:72:74:30:0c:06:03:55:1d:13:01:01:ff:04:02:30:00:30:82:01:05:06:0a:2b:06:01:04:01:d6:79:02:04:02:04:81:f6:04:81:f3:00:f1:00:76:00:bb:d9:df:bc:1f:8a:71:b5:93:94:23:97:aa:92:7b:47:38:57:95:0a:ab:52:e8:1a:90:96:64:36:8e:1e:d1:85:00:00:01:64:f1:2c:0c:e6:00:00:04:03:00:47:30:45:02:20:09:a0:12:a8:58:05:43:83:e1:6e:75:30:db:9e:5f:a7:64:8e:77:c2:24:d7:5e:c2:7b:8d:52:05:3f:05:95:c8:02:21:00:cb:9e:cd:3b:8b:c2:71:33:23:38:7e:88:b8:0d:c1:15:4b:9a:3a:28:0c:88:9a:bc:02:77:76:f4:09:da:e6:cb:00:77:00:87:75:bf:e7:59:7c:f8:8c:43:99:5f:bd:f3:6e:ff:56:8d:47:56:36:ff:4a:b5:60:c1:b4:ea:ff:5e:a0:83:0f:00:00:01:64:f1:2c:0d:b0:00:00:04:03:00:48:30:46:02:21:00:f6:25:43:d2:58:e6:7d:eb:73:4f:90:ca:8f:b5:48:3c:73:a2:10:df:e7:11:f9:c1:18:3f:9e:18:23:30:49:69:02:21:00:81:fd:d1:d8:ed:72:0a:e6:69:f9:b3:f7:d8:88:34:fe:56:28:85:05:a0:42:99:4e:0d:ef:e1:30:2e:68:14:ef:30:0d:06:09:2a:86:48:86:f7:0d:01:01:0b:05:00:03:82:01:01:00:4c:ee:1e:60:12:c3:0f:d4:2f:ac:c9:57:88:33:93:18:9d:61:8d:b4:da:0a:6d:ba:a0:b9:ad:a0:8a:29:b4:2c:9e:8a:8a:a3:e2:f8:bb:d9:5f:4f:b8:2d:af:7f:4b:01:5d:33:e8:bf:bd:1b:7a:7a:0c:65:82:39:7e:de:c7:1c:53:ac:68:6f:4e:43:ad:ca:4c:da:51:be:16:6a:c9:f4:ea:2f:34:c9:a9:45:1d:07:b4:f7:c6:b2:c9:5f:94:52:0f:6c:32:9e:30:55:99:80:ff:12:63:19:74:71:c7:19:02:a1:dd:e4:a2:2f:68:dc:57:ba:e8:06:0c:ac:ca:79:40:32:b5:7a:70:54:ba:d7:f0:cf:bb:2c:77:df:65:e4:f3:cf:da:3e:84:ba:2f:21:5b:5e:ec:20:59:2c:1d:c2:b6:76:db:45:ad:73:00:a8:80:49:5f:70:23:61:c0:c4:c7:d9:92:f0:a4:4f:81:a2:39:b4:b7:b2:cf:69:7d:3c:f5:a1:0b:a7:4a:b2:0c:c2:b6:da:23:06:10:c2:3d:9b:d3:a7:b3:38:fe:6e:33:72:3b:2a:19:84:b1:01:2e:d0:7c:1f:59:e5:8b:79:8c:a4:89:e2:c8:ba:b5:b6:73:f4:6f:7b:45:a0:aa:ef:d9:7c:51:be:ee:35:fd:1a:11:19";
const char p[] = "d6:c0:94:ad:57:f5:37:4f:68:d5:8c:7b:09:68:72:d9:45:ce:e1:f8:26:64:e0:59:44:21:e1:d5:e3:c8:e9:8b:c3:f0:a6:af:8f:92:f1:9e:3f:ef:93:37:b9:9b:9c:93:a0:55:d5:5a:96:e4:25:73:40:05:a6:8e:d4:70:40:fd:f0:0a:55:93:6e:ba:4b:93:f6:4c:ba:1a:00:4e:45:13:61:1c:9b:21:74:38:a7:03:a2:06:0c:20:38:d0:cf:aa:ff:bb:a4:8f:b9:da:c4:b2:45:0d:c5:8c:b0:32:0a:03:17:e2:a3:1b:44:a0:27:87:c6:57:fb:0c:0c:be:c1:1d";
const char g[] = "27:e1:ab:13:1b:6c:22:d2:59:d1:99:e9:df:8a:cb:b1:fe:2f:d4:46:1a:fb:7c:b3:21:d6:94:6b:02:c6:6a:9a:45:c0:62:d5:ff:d0:1e:47:07:5c:f7:b0:82:84:5e:87:e4:95:29:a6:6a:84:05:35:4d:11:48:18:49:33:07:83:41:c9:fa:62:7f:de:3c:2a:9a:19:5e:2c:ae:33:14:5c:47:bd:86:bb:cd:49:b0:12:f2:35:bb:c5:84:86:ce:1d:75:52:21:75:fc:7c:9e:fd:3a:ea:ac:06:85:5b:00:3e:65:a2:20:8d:16:e7:d8:9d:93:59:df:d5:e7:00:2d:e1";
const char ya[] = "96:56:27:c3:5a:ce:ee:f5:9e:cb:47:46:7b:fb:23:21:70:2a:1a:2d:dc:97:5a:f9:74:5d:dc:77:a5:dc:22:d2:6e:e5:74:4d:b2:3d:0f:b9:50:fd:e8:37:65:c0:98:8a:26:b5:db:44:58:be:4c:5e:51:12:6d:c1:60:3b:79:c1:5c:4f:53:6a:7d:97:05:1b:7d:2b:b2:7e:a8:64:5d:0d:dd:49:60:69:bf:7b:a1:cc:cd:f1:ed:49:25:30:29:0d:50:68:5b:ad:89:f8:e0:ee:f3:04:b5:65:d8:e0:33:98:27:eb:94:73:b3:bf:61:6f:31:23:85:fd:3d:8e:02:80";
const char sign[] = "2a:35:3d:99:f2:f0:d8:0b:02:67:6d:d4:17:61:39:9a:ab:dd:0a:4f:67:98:20:32:60:68:30:0e:7b:79:34:09:38:b2:70:40:a5:d2:de:ea:3f:f1:7a:d1:00:36:0f:f5:78:22:ed:b5:27:08:e5:52:cd:ad:39:e8:56:48:6e:7b:f1:ff:ed:40:a2:92:6d:61:00:a4:87:c8:b8:9f:84:fe:ca:b9:6e:a5:40:26:5a:48:b4:20:1a:cf:d1:72:87:db:99:a4:68:c0:95:9f:7c:ef:45:82:7f:26:9e:7f:bc:eb:aa:dd:8f:c3:f0:d5:18:bf:16:ae:e8:9d:62:75:2a:43:b3:b4:1f:eb:80:74:e4:91:5d:86:a4:76:0f:53:c8:80:eb:71:97:0a:79:15:e1:42:1b:5e:c5:c0:b2:13:ff:54:12:2e:1b:92:94:a3:67:c9:3a:14:48:78:b8:96:17:9e:21:68:e2:fc:2a:5a:b7:b7:58:ff:3f:92:30:4f:2f:d7:34:5e:6b:31:6d:0e:5b:98:8a:eb:31:dc:fc:bd:be:54:e2:f3:e1:7c:74:00:a0:95:84:69:d9:89:97:10:9a:bd:06:4e:81:a2:f8:b9:35:e7:41:2d:6d:37:4c:b1:59:f6:70:e0:58:2b:aa:07:33:5a:c0:73:0c:91:4d:66:df:b5";
const char yb[] = "c0:f5:83:22:3e:42:a6:5f:6b:67:82:cc:66:33:99:ff:31:09:16:df:15:e4:01:db:97:1a:f7:1a:c2:99:58:f8:ce:db:84:d3:23:6e:f6:a9:6b:67:79:e1:56:1b:68:37:b7:7f:51:97:a4:6e:97:b5:0b:06:1f:6e:c2:35:0a:20:a9:34:5f:de:ad:38:bc:be:e7:49:f4:cb:f7:60:b0:21:ef:20:86:8d:15:17:bf:b6:f1:73:59:d3:5a:81:f9:f1:ad:df:0d:31:5f:87:1c:49:20:f8:28:f3:4f:f7:28:b3:dd:e1:50:67:d6:76:bc:83:bd:66:9c:11:15:be:f9:3e";
const char data[] = "14:e4:b9:3c:80:83:56:62:de:c3:19:bd:0b:be:5e:2b:b7:91:67:4a:92:6f:cc:b8:fd:42:98:fb:84:d9:3b:ac:c4:cb:ab:1a:52:e3:2c:9b:f7:5f:b9:d9:66:d5:84:d2:22:77:0c:10:08:0c:99:2f:cc:e5:79:56:cb:0c:c9:e3:ad:9c:08:72:35:21:f9:98:79:12:3a:a0:2c:bf:9c:fa:59:2f:44:c3:af:3a:cc:23:75:f1:77:06:a4:b6:e7:ed:a0:3d:9c:74:f4:a4:42:0c:e4:14:d0:78:db:6d:0e:e3:47:87:b8:e9:02:32:56:21:ec:42:7f:6b:fa:5d:b4:90:51:41:1e:23:ac:26:1c:49:05:3b:a5:b6:91:5b:82:ea:28:5d:e5:3b:7a:33:dc:39:fc:bf:fd:13:08:68:4d:3b:82:f5:9a:03:9f:16:ae:49:85:fb:fd:0b:50:4f:74:2a:ec:1e:9e:b6:33:1e:5c:b3:90:be:c2:ec:82:91:dd:ea:fa:f2:b1:35:a9:dc:10:55:1a:5c:8d:d9:94:60:82:e9:09:be:c9:b2:04:ca:14:25:92:68:8d:b6:30:77:c1:07:a8:1b:c1:cf:0f:c5:a3:72:75:ef:fd:ff:25:f0:73:08:99:11:ac:3b:c6:b0:4e:b4:1f:1f:44:70:2a:6c:57:6e";
int hex(unsigned char c) {
	if(isdigit(c)) return c - '0';
	else return 10 + c - 'a';
}

vector<unsigned char> tr(const char *p) {
	vector<unsigned char> r;
	while(1) {
		int k = hex(*p++) * 0x10;
		k += hex(*p++);
		r.push_back(k);
		if(*p == ':') p++;
		else break;
	}
	return r;
}

mpz_class cc2z(const char *p) {
	string s = "0x";
	for(; *p; p++) if(*p != ':') s += *p;
	return mpz_class{s};
}		

stringstream get_padding(mpz_class z) {
	stringstream ss; char c; string s;
	ss << hex << z;
	ss >> c >> c;
	while(c == 'f') ss >> c;
	ss >> c;
	ss >> s;
	stringstream ss2, ss3;
	ss2 << s;
	while(ss2 >> setw(2) >> s) ss3 << noskipws << (unsigned char)stoi(s, nullptr, 16);
	return ss3;
}

array<mpz_class, 3> get_pubkeys(istream& is);
TEST_CASE("get_pubkey") {
	ifstream f("cert.pem");
	auto [K,e,sign] = get_pubkeys(f);
	cout << "pubkey : "  << hex << K << endl << e << endl << sign << endl;
	auto z = powm(sign, e, K);
	auto ss = get_padding(z);
//	cout << z << endl << der2json(ss);
}

array<mpz_class, 2> process_bitstring(string s);
TEST_CASE("DHA-RSA server key exchange signature verify") {
	stringstream ss;
//	const char sign[] = "86:b1:16:16:2e:f6:e1:aa:cd:f3:56:d7:42:7f:3a:48:f4:2f:d0:70:5c:23:a3:6c:5e:9a:05:19:3d:9b:c5:4e:0c:3e:bd:ea:af:29:40:d7:73:88:8f:46:80:71:40:55:6d:c5:27:de:45:6c:47:1d:7a:be:23:75:25:53:02:44:57:3c:ea:c9:ee:1c:26:10:27:c9:f5:fa:b5:33:d5:76:00:45:3c:89:2e:55:51:fc:47:52:88:41:ff:f2:10:dc:eb:64:59:ce:93:71:cc:2c:20:5b:c1:53:5b:c0:0a:bf:7f:dc:6a:10:e3:17:58:9b:3e:be:20:de:a5:77:c3:c6:18:16:7d:80:d9:71:f1:6e:ca:5e:ac:f0:00:34:52:c2:a3:95:c9:b7:6d:06:82:8c:4c:bc:92:a2:6d:99:a2:b3:d3:f5:a9:39:c9:35:74:12:ca:ae:9d:db:c0:a2:23:5d:6a:bc:12:65:c6:9c:5a:2e:27:19:32:29:58:ec:0e:1c:f1:8d:21:3e:c7:ac:59:fb:fd:dc:6a:1a:2a:b3:65:d1:56:45:c1:fa:3a:cf:5c:79:71:75:3a:8b:ba:9b:83:09:4d:cd:7d:e0:b7:07:34:00:51:af:61:4a:68:55:55:59:0a:23:4f:d4:2c:79:70:47:dc:84:f9:f4:bd:c2:46:1e";
	for(unsigned char c : tr(cert)) ss << noskipws << c;
	Json::Value jv = der2json(ss);
	const auto &[K, e] = process_bitstring(jv[0][0][6][1].asString());
	auto m = cc2z(sign);
	auto signature_decode = powm(m, e, K);

	vector<unsigned char> v;
	for(unsigned char c : tr(client_random)) v.push_back(c);
	for(unsigned char c : tr(server_random)) v.push_back(c);
	v.push_back(0); v.push_back(128);
	for(unsigned char c : tr(p)) v.push_back(c);
	v.push_back(0); v.push_back(128);
	for(unsigned char c : tr(g)) v.push_back(c);
	v.push_back(0); v.push_back(128);
	for(unsigned char c : tr(ya)) v.push_back(c);
	
	SHA5 sha;
	auto ar = sha.hash(v.begin(), v.end());
	auto h = bnd2mpz(ar.begin(), ar.end());

	string s = "0x1";
	for(int i=0; i<SHA5::output_size; i++) s += "00";
	REQUIRE(signature_decode % mpz_class{s} == h);

	auto ss2 = get_padding(signature_decode);
//	cout << signature_decode << endl << der2json(ss2) << endl;
//First of all, I compute signature^e mod n (e and n coming from the server Certificate). The result looks OK as its looks properly encoded (01FFFF...FF00...<hash>).
}

TEST_CASE("rsa with upper") {
	RSA rsa{256};//K should be bigger than m, K is 256 byte, and m is 256
	auto m = cc2z(sign);//it is possible that m > K
	auto z = rsa.encode(m);
	auto d = rsa.decode(z);
	REQUIRE(m == d);
}

//TEST_CASE("wolf dhe rsa") {
//	DiffieHellman A{2048};
//	A.ya = mpz_class{"0x2e78ce9ac03a2cb48a7b4188417fde50dbcdba7f6ed139845126f70a8f67a0e348427718504d9746a32bb72ff89d2c32eddcf26b85a08a5704a7acf094b1c4409952c3c65a496cbe2b13cc832d69c8a9cd5901e2745d81a9b728fc23d0295e2bd928f1375ad0a5abff01a98fd71104514021446c1e2d6083a028df67311c42a18e88d828cc83ff4ed337c0e640f338169a508629f909a0cacf386da9db93c81154481166f0073d1567bb8fa767eee572614f6d8925239315dde8ab469247b7ce243c494adadae895ec7427b169063edd02410b5b21b9ea5b251621fb90f27c103b3073b94f03b0b48937b65f0f1a35883ae42dffd9715f063aa4c2e1f3a9e82f"};
//	DiffieHellman B{A.p, A.g, A.ya};
//	A.set_yb(B.yb);
//}
//
