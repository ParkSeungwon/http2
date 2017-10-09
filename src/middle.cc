#include<iostream>
#include<regex>
#include"middle.h"
using namespace std;

std::map<int, Client> Middle::idNconn_;
Middle::Middle(int port) : port_{port} {}

string Middle::operator()(string s)
{
	regex e{R"(Cookie:.*middleID=(\d+))"};
	smatch m;
	if(regex_search(s, m, e)) {//if already connected
		int id = stoi(m[1].str());
		idNconn_[id].send(s);
		return idNconn_[id].recv();
	} else {//first connected
		idNconn_[++id_] = Client{"127.0.0.1", port_};
		idNconn_[id_].send(s);
		string r = idNconn_[id_].recv();
		cout << "sending" << endl << s << endl << "receiving" << endl << r;
		r.replace(16, 1, "\nSet-Cookie: middleID=" + to_string(id_) + "\r\n");
		return r;
	}
}

