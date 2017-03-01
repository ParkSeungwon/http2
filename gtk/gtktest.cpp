#include<gtkmm.h>
#include<iostream>
#include<functional>
using namespace std;

void f() { 
	cout << " clicked" << endl; 
	Gtk::Window* w = new Gtk::Window;
	w->show();
}

int main()
{
	auto app = Gtk::Application::create();
	Gtk::Window w;
	Gtk::Button b("0k");
	w.add(b);
	b.signal_clicked().connect(bind(f));
	w.show_all_children();
	app->run(w);
}
	
