#include<gtkmm.h>
#include<mutex>
#include<condition_variable>
#include<string>
#include<iostream>
#include<thread>
#include"tcpip.h"
using namespace std;

mutex mtx;
condition_variable cv;

class Win : public Gtk::Window
{
public:
	Win() : la{"Test"}, button{"OK"} {
		add(layout);
		layout.put(la, 50, 50);
		layout.put(button, 50, 80);
		this->signal_delete_event().connect(sigc::mem_fun(this, &Win::on_exit));
		button.signal_enter().connect(bind(&Win::on_click, this, "entered"));
		button.signal_clicked().connect(bind(&Win::on_click, this, "clicked"));
		show_all_children();
	}
	Gtk::Label la;
	string event;

protected:
	Gtk::Layout layout;
	Gtk::Button button;
	virtual bool on_exit(GdkEventAny* e) {
		event = "end";
		hide();
		cv.notify_all();
		return true;
	}
	virtual void on_click(string s) {
		event = s;
		cv.notify_all();
	}
};

class Functor
{
public:
	//Functor(Win& win) { }
	string operator()(string s) {
		//event poll, initiative goes to server now
		Win* w = new Win;
		w->la.set_text(s);
		unique_lock<mutex> lck{mtx};//conditional variable can be used here
		while(w.event.empty()) cv.wait(lck);
		s = w->event;
		w->event.clear();
		if(s == "") w->hide();
		return s;
	}
	Win* w;
	virtual ~Functor() {
		cout << "destroyed" << endl;
		delete w;
	}
};

int main(int ac, char** av)
{
	auto app = Gtk::Application::create(ac, av);
	Win win;
	Functor f(win);
	Server sv;
	thread th(&Server::start, &sv, f);
	app->run(win);
	th.join();
}
