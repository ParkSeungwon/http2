#include<gtkmm.h>
#include<iostream>
#include"server.h"
#include"asyncqueue.h"
#include"root.h"
using namespace std;

class Win : public Gtk::Window
{
public:
	Win() : bt{"test"} {
		add(bt);
		set_default_size(100,100);
		bt.signal_clicked().connect(bind(&Win::on_click, this));
		show_all_children();
	}
	deque<string> event_queue;
	Gtk::Button bt;
protected:
	void on_click() {
		//cout << "click indise" << endl;
		event_queue.push_back("clicked");
	}
};

class Functor
{
public:
	Gtk::Window* wp;
	string operator()(string s) {
		if(s == "event") {
			return s + "from event";
		} else {
			auto app = Gtk::Application::create();
			Win win;
			app->run(win);
			//wp = new Gtk::Window;
			//wp->show();
			return s;
		}
	}
};

int main(int ac, char** av)
{
	Server sv;
	Functor f;
	sv.start(f);
}
