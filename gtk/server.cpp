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
	Functor(RootWindow& r) : root{r} {
	}
	RootWindow& root;
	string operator()(string s) {
		if(s == "event") {
			cout << s << endl;
		//	while(root.sub_windows[0].event_queue.empty());
		//	s = root.sub_windows[0].event_queue.front();
		//	root.sub_windows[0].event_queue.pop_front();
			return s + "from server queue";
		} else {
			root.sub_windows[s] = new Win;
			cout << s << endl;
			dynamic_cast<Win*>(root.sub_windows[s])->bt.set_label(s);
			root.sub_windows[s]->show();
			return s + "from server";
		}
	}

protected:
};

int main(int ac, char** av)
{
	auto app = Gtk::Application::create(ac, av);
	RootWindow win{app};
	Server sv;
	sv.start(Functor(win));
}
