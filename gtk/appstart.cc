#include<gtkmm.h>
#include<sstream>
#include<iostream>
#include"asyncqueue.h"
#include"appstart.h"
#include"matrix.h"
using namespace std;

void AppServer::app_start(function<string(string, Gtk::Window*)> f) 
{
	int cl_size = sizeof(client_addr);
	while(true) {
		client_fd = accept(server_fd, (sockaddr*)&client_addr, (socklen_t*)&cl_size);
		if(client_fd == -1) cout << "accept() error" << endl;
		else {//connection established
			cout << "accepting" << endl;
			if(!fork()) {//child process begin here, current fd & addr is copied
				auto app = Gtk::Application::create();
				Gtk::Window root;
				Gtk::ScrolledWindow sc;
				Gtk::Grid grid;
				root.add(sc);
				sc.add(grid);
				for(string s = recv(); s != "event"; s = recv()) {//window definition 
					auto mat = win_def(s);
					auto v = analyse_matrix(mat);
					for(auto& a : v) {
						switch(a.type) {
						case 'W':
						case 'L':
						case 'B':
						case 'T':break;
						}
					}
				}
				AsyncQueue<string> aq{//recv->process->aq->send,event->aq.push()->send
					bind(&AppServer::process, this, bind(&Tcpip::recv, this)), 
					bind(&Tcpip::send, this, placeholders::_1)
				};
				Gtk::Button bt{"ok"};
				grid.attach(bt, 0,0,50,50);
				bt.signal_clicked().connect(bind(&AsyncQueue<string>::push_back, &aq, "clicked"));
				root.show_all_children();
				app->run(root);
			}
		}
	}
}

string AppServer::process(string s)
{
	return s;
}

Matrix<char> AppServer::win_def(string s)
{///window ascii art -> 2 dimension matrix
	stringstream ss;
	ss << s;
	string t;
	int line = 0, maxlen = 0;
	while(getline(ss, t)) {
		int len = t.size();
		maxlen = len > maxlen ? len : maxlen;
		line++;
	}
	Matrix<char> mat{maxlen, line};
	int x = 1, y = 0;
	for(int i=0; i<s.size(); i++) {
		if(s[i] == '\n') y++, x=1; 
		else mat[x++][y] = s[i];
	}
	return mat;
}


vector<Component> AppServer::analyse_matrix(Matrix<char>& m)
{///matrix -> fill component name, position, width, height 
	int w = m.get_width();
	int h = m.get_height();
	vector<Component> components;
	for(int y = 1; y <= h; y++) for(int x = 1; x <= w; x++) {
		if(m[x][y] >= '1' && m[x][y] <= '9') 
			if(m[x-1][y] >= 'A' && m[x-1][y] <= 'Z' && m[x+1][y] == '-') {
				int i, j;
				for(i=2; m[x+i][y] == '-'; i++);
				for(j=1; m[x-1][y+j] == '-'; j++);
				components.push_back({m[x-1][y], m[x][y], x-1, y, i+1, j});
			}
	}
	return components;
}


