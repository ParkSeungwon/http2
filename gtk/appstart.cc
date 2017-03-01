#include<gtkmm.h>
#include<iostream>
#include"asyncqueue.h"
#include"appstart.h"
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
				AsyncQueue<string> aq{
					bind(&AppServer::process, this, bind(&Tcpip::recv, this)), 
					bind(&Tcpip::send, this, placeholders::_1)
				};
				auto app = Gtk::Application::create();
				string s;
	//			while((s = recv()) != "event") {//window definition receive
					
	//			}//recv->process->q, event->q(aq.push())
				Gtk::Window root;
				Gtk::Grid grid;
				root.add(grid);
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
