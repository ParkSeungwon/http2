#include<gtkmm.h>
#include<string>
#include<thread>
#include"tcpip.h"
using namespace std;

class Win : public Gtk::Window
{
public:
	Win() : la{"Test"} {
		add(la);
		show_all_children();
	}
	Gtk::Label la;
};

class Functor
{
public:
	Functor(Win& win) : w(win) { }
	string operator()(string s) {
		w.la.set_text(s);
		w.show_all_children();
		return s;
	}
	Win& w;
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
