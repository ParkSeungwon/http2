#include"asyncqueue.h"
#include<iostream>
#include<string>
#include<map>
#include<unistd.h>
#include<regex>
#include<cassert>
#include"server.h"
using namespace std;

string f(string s) {
	cout << s << endl;
}
struct Packet
{
	int fd, id;//client_fd, cookie id
	std::string content;
};

class M : public Server
{
public:
	M(int outport = 3000, int inport = 2001)
	: outport_{outport}, inport_{inport}
//	  influx_{bind(&M::recv, this), bind(&M::sow, this, placeholders::_1)},
//	  outflux_{bind(&M::loop, this), bind(&M::send, this, placeholders::_1)}
	{}

//	virtual ~M() {
//		for(auto& a : idNconn_) delete a.second;
//	}
//	Packet loop() {//blank function
//		while(1) this_thread::sleep_for(1s);
//	}
//
//protected:
////	AsyncQueue<Packet> influx_, outflux_;
//	std::map<int, Client*> idNconn_;
//
//private:
//	Packet recv() {
//		int cl_size = sizeof(client_addr);
//		client_fd = accept(server_fd, (sockaddr*)&client_addr, (socklen_t*)&cl_size);
//		assert(client_fd != -1);// cout << "accept() error" << endl;
//		string s = Tcpip::recv();
//		cout << "receiving " << s << endl;
//		regex e{R"(Cookie:.*middleID=(\d+))"};
//		int id = 0;
//		smatch m;
//		if(regex_search(s, m, e)) id = stoi(m[1].str());//if already connected
//		return {client_fd, id, s};
//	}
//	void send(Packet p) {
//		write(p.fd, p.content.data(), p.content.size()+1);
//		close(p.fd);
//	}
//	void sow(Packet p) {
//		bool newly_connected = false;
//		if(!p.id) {
//			idNconn_[p.id = ++id_] = new Client{"localhost", inport_};
//			newly_connected = true;
//		}
//		if(idNconn_[p.id]) idNconn_[p.id]->send(p.content);
//		string s = idNconn_[p.id]->recv();
//		if(newly_connected) 
//			p.content.replace(16, 1, "\nSet-Cookie: middleID=" + to_string(id_) + "\r\n");
//		outflux_.push_back(p);
//	}

	const int inport_, outport_;
	int id_ = 0;
};


int main(int ac, char** av)
{
	int port = ac < 2 ? 2002 : atoi(av[1]);
	M sv{port};
	sv.start(f);
}
