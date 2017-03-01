#include<gtkmm.h>
#include"server.h"

class AppServer : public Server
{
public:
	void app_start(std::function<std::string(std::string, Gtk::Window*)> f);

protected:
	std::string process(std::string s);
};

