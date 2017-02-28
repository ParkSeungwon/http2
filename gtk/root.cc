#include"root.h"
#include"../src/asyncqueue.h"
#include"server.h"
#include<iostream>
using namespace std;

RootWindow::RootWindow(Glib::RefPtr<Gtk::Application>& app) 
	: th(&RootWindow::start, this, std::ref(app))
{
	set_visible(false);
}

string RootWindow::operator()(string s)
{
	if(s == "event") {
		cout << s << endl;
		//	while(root.sub_windows[0].event_queue.empty());
		//	s = root.sub_windows[0].event_queue.front();
		//	root.sub_windows[0].event_queue.pop_front();
		return s + "from server queue";
	} else {
		sub_windows[s] = new Gtk::Window;
		cout << s << endl;
		sub_windows[s]->set_title(s);
		sub_windows[s]->show();
		return s + "from server";
	}
}
	
RootWindow::~RootWindow()
{
	th.join();
	for(auto& a : sub_windows) if(a.second) delete a.second;
}

int RootWindow::start(Glib::RefPtr<Gtk::Application>& app)
{
	return app->run(*this);
}

