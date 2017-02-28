#include"root.h"
using namespace std;

RootWindow::RootWindow(Glib::RefPtr<Gtk::Application>& app) 
	: th(&RootWindow::start, this, std::ref(app))
{
	set_visible(false);
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
