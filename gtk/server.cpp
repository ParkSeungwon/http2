#include<gtkmm.h>
#include<iostream>
#include"appstart.h"
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
	string operator()(string s, Gtk::Window* wp) {
		if(s == "event") {
			cout << s << endl;
			wp->hide();
		//	while(root.sub_windows[0].event_queue.empty());
		//	s = root.sub_windows[0].event_queue.front();
		//	root.sub_windows[0].event_queue.pop_front();
			return s + "from server queue";
		} else {
			auto* p = new Gtk::Grid();
			wp->add(*p);
			wp->set_title(s);
			wp->resize(500,500);
			auto* b = new Gtk::Button("ok");
			p->attach(*b, 0, 0, 50, 50);
			wp->show();
			return s;
		}
	}

protected:
	Gtk::Window* wp;
} f;

int main(int ac, char** av)
{
	AppServer sv;
	sv.app_start(f);
}
