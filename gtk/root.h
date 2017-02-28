#include<gtkmm.h>
#include<thread>
#include<vector>

class RootWindow : public Gtk::Window
{
public:
	RootWindow(Glib::RefPtr<Gtk::Application>& app);
	~RootWindow();
	std::map<std::string, Gtk::Window*> sub_windows;
	std::string operator()(std::string);
	
protected:

private:
	int start(Glib::RefPtr<Gtk::Application>& app);
	std::thread th;///<to make this window background to run server concurrently

};
